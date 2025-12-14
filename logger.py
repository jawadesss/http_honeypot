import datetime
import sqlite3
import json

LOG_FILE = "/data/honeypot.log"
DB_FILE = "/data/honeypot.db"

def log_event(req, attack, severity, explanation):
    timestamp = datetime.datetime.utcnow().isoformat()
    ip = req.headers.get("X-Forwarded-For", req.remote_addr)
    method = req.method
    path = req.path
    query = req.query_string.decode(errors="ignore")
    user_agent = req.headers.get("User-Agent", "Unknown")
    body = dict(req.form)
    body_text = json.dumps(body)[:500]  # truncate if huge

    attack_type = attack or "None"
    reason = "; ".join(explanation) if explanation else "No explanation"
    severity = severity or "info"

    log_line = (
        f"{timestamp} | IP={ip} | {method} {path} "
        f"| Attack={attack_type} | Severity={severity} "
        f"| Reason={reason} | Query={query} | Body={body_text} | UA={user_agent}\n"
    )

    # Write to file
    with open(LOG_FILE, "a") as f:
        f.write(log_line)

    # Write to SQLite
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            time TEXT,
            ip TEXT,
            method TEXT,
            path TEXT,
            attack TEXT,
            severity TEXT,
            reason TEXT,
            query TEXT,
            body TEXT,
            user_agent TEXT
        )
    """)
    c.execute(
        "INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?)",
        (timestamp, ip, method, path, attack_type, severity, reason, query, body_text, user_agent)
    )
    conn.commit()
    conn.close()
