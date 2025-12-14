import datetime
import sqlite3
import json
import hashlib
import socket
import geoip2.database
import os
from ipaddress import ip_address

LOG_FILE = "/data/honeypot.log"
DB_FILE = "/data/honeypot.db"
GEOIP_DB = "/data/GeoLite2-City.mmdb"  # Optional: for geolocation

def get_ip_info(ip_str):
    """Extract IP information and geolocation"""
    ip = ip_str.split(',')[0].strip() if ',' in ip_str else ip_str.strip()
    
    info = {
        "ip": ip,
        "is_private": False,
        "country": "Unknown",
        "city": "Unknown",
        "asn": "Unknown",
        "reverse_dns": "Unknown"
    }
    
    try:
        # Check if private IP
        addr = ip_address(ip)
        info["is_private"] = addr.is_private
        
        # Reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            info["reverse_dns"] = hostname
        except:
            pass
        
        # Geolocation (optional - requires GeoLite2 database)
        if os.path.exists(GEOIP_DB):
            try:
                with geoip2.database.Reader(GEOIP_DB) as reader:
                    response = reader.city(ip)
                    info["country"] = response.country.name or "Unknown"
                    info["city"] = response.city.name or "Unknown"
            except:
                pass
                
    except:
        pass
    
    return info

def calculate_request_hash(req):
    """Calculate hash of request for duplicate detection"""
    data = f"{req.method}{req.path}{req.query_string}{json.dumps(dict(req.form))}"
    return hashlib.md5(data.encode()).hexdigest()

def log_event(req, attack, severity, explanation):
    timestamp = datetime.datetime.utcnow().isoformat()
    ip = req.headers.get("X-Forwarded-For", req.remote_addr)
    
    # Get IP information
    ip_info = get_ip_info(ip)
    
    method = req.method
    path = req.path
    query = req.query_string.decode(errors="ignore")
    user_agent = req.headers.get("User-Agent", "Unknown")
    headers = dict(req.headers)
    
    # Process body data
    body = dict(req.form)
    
    # Handle JSON body
    if req.is_json:
        try:
            json_data = req.get_json()
            if json_data:
                body.update({"json_data": json_data})
        except:
            pass
    
    # Create request fingerprint
    request_hash = calculate_request_hash(req)
    
    # Truncate long values for storage
    body_text = json.dumps(body, default=str)[:1000]
    query_truncated = query[:500]
    user_agent_truncated = user_agent[:500]
    
    attack_type = attack or "None"
    reason = "; ".join(explanation) if explanation else "No explanation"
    severity = severity or "info"
    
    # Enhanced log line with more details
    log_line = (
        f"{timestamp} | "
        f"IP={ip_info['ip']} | "
        f"Country={ip_info['country']} | "
        f"Private={ip_info['is_private']} | "
        f"Method={method} | "
        f"Path={path} | "
        f"Attack={attack_type} | "
        f"Severity={severity} | "
        f"Reason={reason} | "
        f"Query={query_truncated} | "
        f"Body={body_text[:200]}... | "
        f"UA={user_agent_truncated} | "
        f"Hash={request_hash}\n"
    )
    
    # Write to file with rotation check
    try:
        # Check if log file is too large (>100MB)
        if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 100 * 1024 * 1024:
            # Rotate log
            old_log = f"{LOG_FILE}.{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.rename(LOG_FILE, old_log)
        
        with open(LOG_FILE, "a", encoding='utf-8') as f:
            f.write(log_line)
    except Exception as e:
        print(f"Error writing to log file: {e}")
    
    # Write to SQLite with enhanced schema
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # Create enhanced table if not exists
        c.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                country TEXT,
                city TEXT,
                is_private INTEGER,
                reverse_dns TEXT,
                method TEXT,
                path TEXT,
                attack TEXT,
                severity TEXT,
                reason TEXT,
                query TEXT,
                body TEXT,
                user_agent TEXT,
                request_hash TEXT,
                headers TEXT,
                UNIQUE(request_hash, timestamp) ON CONFLICT IGNORE
            )
        """)
        
        # Create index for faster queries
        c.execute("CREATE INDEX IF NOT EXISTS idx_ip ON events(ip)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_severity ON events(severity)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_attack ON events(attack)")
        
        # Insert the event
        c.execute(
            """INSERT INTO events 
               (timestamp, ip, country, city, is_private, reverse_dns, 
                method, path, attack, severity, reason, query, 
                body, user_agent, request_hash, headers) 
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                timestamp,
                ip_info['ip'],
                ip_info['country'],
                ip_info['city'],
                1 if ip_info['is_private'] else 0,
                ip_info['reverse_dns'],
                method,
                path,
                attack_type,
                severity,
                reason,
                query_truncated,
                body_text,
                user_agent_truncated,
                request_hash,
                json.dumps(headers, default=str)[:2000]
            )
        )
        
        # Create statistics table
        c.execute("""
            CREATE TABLE IF NOT EXISTS statistics (
                date TEXT PRIMARY KEY,
                total_requests INTEGER,
                attacks INTEGER,
                critical_severity INTEGER,
                high_severity INTEGER,
                medium_severity INTEGER,
                low_severity INTEGER
            )
        """)
        
        # Update daily statistics
        date = timestamp[:10]  # YYYY-MM-DD
        c.execute("""
            INSERT OR IGNORE INTO statistics (date, total_requests, attacks, 
                    critical_severity, high_severity, medium_severity, low_severity)
            VALUES (?, 0, 0, 0, 0, 0, 0)
        """, (date,))
        
        # Update counters
        c.execute("""
            UPDATE statistics 
            SET total_requests = total_requests + 1
            WHERE date = ?
        """, (date,))
        
        if attack_type != "None":
            c.execute("""
                UPDATE statistics 
                SET attacks = attacks + 1
                WHERE date = ?
            """, (date,))
            
            # Update severity counters
            if severity == "critical":
                c.execute("UPDATE statistics SET critical_severity = critical_severity + 1 WHERE date = ?", (date,))
            elif severity == "high":
                c.execute("UPDATE statistics SET high_severity = high_severity + 1 WHERE date = ?", (date,))
            elif severity == "medium":
                c.execute("UPDATE statistics SET medium_severity = medium_severity + 1 WHERE date = ?", (date,))
            elif severity == "low":
                c.execute("UPDATE statistics SET low_severity = low_severity + 1 WHERE date = ?", (date,))
        
        conn.commit()
        conn.close()
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    
    # Also log to console for debugging
    print(f"[{severity.upper()}] {timestamp} {method} {path} from {ip} - {attack_type or 'No attack'}: {reason}")