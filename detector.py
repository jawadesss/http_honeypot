import re
import math
import ipaddress
from urllib.parse import unquote

LOGIN_PATHS = ["/login"]
ADMIN_PATHS = ["/admin", "/phpmyadmin", "/wp-login.php", "/administrator", "/admin.php", "/admin/login", "/admin/admin", "/admin/index.php", "/manager", "/webadmin", "/cpanel", "/whm"]
SENSITIVE_PATHS = ["/.env", "/config", "/backup", "/.git", "/.svn", "/.htaccess", "/.htpasswd", "/wp-config.php", "/config.php", "/settings.php", "/database.yml", "/docker-compose.yml", "/dockerfile", "/passwd", "/shadow", "/.bash_history", "/.ssh", "/.aws", "/credentials"]

# Expanded SQL patterns
SQL_KEYWORDS = [
    r"\bunion\s+(all\s+)?select\b",
    r"select\s+.+\s+from\s+.+",
    r"insert\s+into\s+.+\s+values\s*\(.+\)",
    r"update\s+.+\s+set\s+.+\s+where\s*",
    r"delete\s+from\s+.+\s+where\s*",
    r"drop\s+(table|database)\s+",
    r"truncate\s+table\s+",
    r"create\s+(table|database)\s+",
    r"alter\s+table\s+",
    r"exec\s*\(.+\)",
    r"xp_cmdshell\s*",
    r"information_schema\b",
    r"pg_sleep\s*\(",
    r"waitfor\s+delay\s+",
    r"benchmark\s*\(",
    r"sleep\s*\(",
    r"\b1\s*=\s*1\b",
    r"\bor\s+'?'\s*=\s*'?'",
    r"\band\s+'?'\s*=\s*'?'",
]

# Enhanced XSS patterns
XSS_PATTERNS = [
    r"<script\b[^>]*>.*?</script>",
    r"javascript\s*:",
    r"on\w+\s*=",
    r"<\s*iframe\b",
    r"<\s*img\b[^>]*\bsrc\s*=\s*javascript:",
    r"<\s*a\b[^>]*\bhref\s*=\s*javascript:",
    r"<\s*form\b[^>]*>",
    r"<\s*input\b[^>]*\btype\s*=\s*(hidden|text)",
    r"alert\s*\(",
    r"document\.\w+",
    r"window\.location",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
]

# Enhanced command injection patterns
CMD_PATTERNS = [
    r"[;&|]\s*(sh|bash|cmd|powershell|python|perl|php|ruby|nc|netcat|wget|curl|ftp)\b",
    r"`[^`]+`",
    r"\$\([^)]+\)",
    r"\$\{[^}]+\}",
    r"(sudo|su)\s+",
    r"chmod\s+[0-9]+\s+",
    r"rm\s+-rf",
    r"cat\s+/etc/passwd",
    r"ls\s+-la",
    r"id\s*;?",
    r"whoami\s*;?",
    r"pwd\s*;?",
]

# Directory traversal patterns
TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%252e%252e%252f",
    r"\.\.%00",
    r"\.\./\.\./",
]

# LFI/RFI patterns
LFI_PATTERNS = [
    r"\.\./\.\./",
    r"/etc/passwd",
    r"/etc/shadow",
    r"/proc/self/environ",
    r"\.\.\\",
    r"php://filter",
    r"phar://",
    r"zip://",
    r"data://",
    r"expect://",
    r"file://",
    r"http://",
    r"https://",
    r"ftp://",
    r"=\s*http",
]

# Scan patterns
SCANNER_UA = [
    r"(nmap|nikto|acunetix|nessus|openvas|sqlmap|wpscan|joomscan|dirb|dirbuster|gobuster|wfuzz|burpsuite|zap|owasp|paros|arachni)",
    r"(scan|scanner|security|pentest|vulnerability)",
    r"(bot|spider|crawler)\b",
]

# Suspicious headers
MALICIOUS_HEADERS = [
    "x-forwarded-host",
    "x-original-url",
    "x-rewrite-url",
    "proxy-",
    "cf-",
    "true-client-ip",
]

def entropy(s):
    """Calculate Shannon entropy of a string"""
    if not s:
        return 0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    e = 0
    for c in freq:
        p = freq[c] / len(s)
        e -= p * math.log2(p)
    return e

def is_private_ip(ip_str):
    """Check if IP is private/internal"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except:
        return False

def detect_scanning(req):
    """Detect scanning activities"""
    path = req.path
    user_agent = req.headers.get('User-Agent', '').lower()
    headers = {k.lower(): v for k, v in req.headers.items()}
    
    # User agent detection
    for pattern in SCANNER_UA:
        if re.search(pattern, user_agent, re.I):
            return True, "Known scanner tool detected by User-Agent"
    
    # Suspicious headers
    for header in MALICIOUS_HEADERS:
        if header in headers:
            return True, f"Suspicious header detected: {header}"
    
    # Common scan patterns in path
    scan_patterns = [
        r"\.(bak|old|temp|tmp|swp|swo)$",
        r"\.(git|svn)/",
        r"\.(env|ini|cfg|conf|config)$",
        r"/(cgi-bin|bin|dev|proc|sys)/",
        r"\.(asp|aspx|jsp|php|pl|py|rb|sh|cgi)$",
        r"\.(xml|json|yml|yaml)$",
    ]
    
    for pattern in scan_patterns:
        if re.search(pattern, path, re.I):
            return True, f"Scan pattern detected in path: {pattern}"
    
    # Unusual number of dots or special chars in path
    if path.count('.') > 3 or path.count('/') > 10:
        return True, "Unusual path structure (too many dots or slashes)"
    
    return False, None

def detect_attack(req):
    method = req.method
    path = req.path
    ip = req.headers.get("X-Forwarded-For", req.remote_addr)
    
    # Decode URL-encoded payloads
    try:
        query = unquote(req.query_string.decode(errors="ignore")).lower()
    except:
        query = req.query_string.decode(errors="ignore").lower()
    
    body_dict = dict(req.form)
    
    # Handle JSON body if present
    if req.is_json:
        try:
            json_data = req.get_json()
            if json_data:
                body_dict.update(json_data)
        except:
            pass
    
    body = " ".join([str(v) for v in body_dict.values()]).lower()
    payload = f"{query} {body}"
    
    explanation = []

    # 0️⃣ First check for scanning activities
    is_scan, scan_reason = detect_scanning(req)
    if is_scan:
        explanation.append(scan_reason)
        return "Scanning/Reconnaissance", "medium", explanation

    # 1️⃣ Recon / scanning - sensitive paths
    if path in ADMIN_PATHS:
        explanation.append(f"Sensitive admin endpoint accessed: {path}")
        return "Reconnaissance", "high", explanation
    
    if path in SENSITIVE_PATHS:
        explanation.append(f"Sensitive system file accessed: {path}")
        return "Reconnaissance", "critical", explanation

    # 1.1 Directory traversal attempts
    for pattern in TRAVERSAL_PATTERNS:
        if re.search(pattern, payload, re.I):
            explanation.append(f"Directory traversal attempt detected: {pattern}")
            return "Directory Traversal", "critical", explanation

    # 1.2 LFI/RFI attempts
    for pattern in LFI_PATTERNS:
        if re.search(pattern, payload, re.I):
            explanation.append(f"LFI/RFI attempt detected: {pattern}")
            return "LFI/RFI", "critical", explanation

    # 2️⃣ Legit login (avoid false positives)
    if path in LOGIN_PATHS and method == "POST":
        allowed_fields = {"email", "username", "password", "csrf_token", "captcha"}
        if set(body_dict.keys()).issubset(allowed_fields):
            pwd = str(body_dict.get("password", ""))
            if len(pwd) < 128 and entropy(pwd) < 4.5:
                explanation.append("Normal login attempt")
                return None, "info", explanation

    # 3️⃣ Bruteforce / fuzzing detection with more criteria
    if method == "POST":
        # Payload size detection
        if len(payload) > 1500:
            explanation.append(f"Very large POST payload ({len(payload)} chars)")
            return "Fuzzing/Bruteforce", "high", explanation
        elif len(payload) > 800:
            explanation.append(f"Large POST payload ({len(payload)} chars)")
            return "Fuzzing/Bruteforce", "medium", explanation
        
        # Entropy detection
        payload_entropy = entropy(payload)
        if payload_entropy > 6.0:
            explanation.append(f"Very high entropy payload ({payload_entropy:.2f})")
            return "Fuzzing/Bruteforce", "high", explanation
        elif payload_entropy > 5.2:
            explanation.append(f"High entropy payload ({payload_entropy:.2f})")
            return "Fuzzing/Bruteforce", "medium", explanation
        
        # Unusual number of parameters
        if len(body_dict) > 20:
            explanation.append(f"Unusually high number of parameters ({len(body_dict)})")
            return "Fuzzing/Bruteforce", "medium", explanation

    # 4️⃣ HTTP Method anomalies
    if method not in ["GET", "POST", "HEAD"]:
        explanation.append(f"Unusual HTTP method: {method}")
        return "Method Anomaly", "low", explanation

    # 5️⃣ SQL Injection with improved detection
    sql_hits = sum(1 for p in SQL_KEYWORDS if re.search(p, payload, re.I))
    if sql_hits >= 2:
        explanation.append(f"Multiple SQL patterns detected ({sql_hits})")
        return "SQL Injection", "critical", explanation
    elif sql_hits == 1:
        explanation.append("Single SQL pattern detected")
        return "SQL Injection", "high", explanation

    # 6️⃣ XSS with improved detection
    xss_hits = sum(1 for p in XSS_PATTERNS if re.search(p, payload, re.I))
    if xss_hits >= 2:
        explanation.append(f"Multiple XSS patterns detected ({xss_hits})")
        return "XSS", "critical", explanation
    elif xss_hits == 1:
        explanation.append("XSS pattern detected")
        return "XSS", "high", explanation

    # 7️⃣ Command Injection with improved detection
    cmd_hits = sum(1 for p in CMD_PATTERNS if re.search(p, payload, re.I))
    if cmd_hits >= 2:
        explanation.append(f"Multiple command injection patterns detected ({cmd_hits})")
        return "Command Injection", "critical", explanation
    elif cmd_hits == 1:
        explanation.append("Command injection pattern detected")
        return "Command Injection", "high", explanation

    # 8️⃣ Private IP access attempt
    if is_private_ip(ip.split(',')[0].strip()):
        explanation.append(f"Access from private IP: {ip}")
        return "Internal Network Scan", "medium", explanation

    # 9️⃣ Unusual path patterns
    suspicious_path_patterns = [
        r"\.\.",  # Directory traversal
        r"%00",   # Null byte
        r"\.php\?",  # PHP with query
        r"=",      # Lots of parameters
    ]
    
    for pattern in suspicious_path_patterns:
        if re.search(pattern, path + query):
            explanation.append(f"Suspicious pattern in request: {pattern}")
            return "Suspicious Request", "low", explanation

    explanation.append("Benign request")
    return None, "info", explanation