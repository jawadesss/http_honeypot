import re
import math

LOGIN_PATHS = ["/login"]
ADMIN_PATHS = ["/admin", "/phpmyadmin", "/wp-login.php"]
SENSITIVE_PATHS = ["/.env", "/config", "/backup"]

SQL_KEYWORDS = [
    r"\bunion\b",
    r"\bselect\b.+\bfrom\b",
    r"\binformation_schema\b",
    r"\border\s+by\b",
    r"\bsleep\s*\(",
    r"\bbenchmark\s*\(",
]

XSS_PATTERNS = [
    r"<script",
    r"</script",
    r"onerror\s*=",
    r"onload\s*=",
    r"javascript:",
]

CMD_PATTERNS = [
    r";\s*\w+",
    r"\|\|\s*\w+",
    r"&&\s*\w+",
    r"`.+`",
    r"\$\(.+\)",
]

def entropy(s):
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

def detect_attack(req):
    method = req.method
    path = req.path

    query = req.query_string.decode(errors="ignore").lower()
    body_dict = dict(req.form)
    body = " ".join(body_dict.values()).lower()
    payload = f"{query} {body}"

    explanation = []

    # 1️⃣ Recon / scanning
    if path in ADMIN_PATHS or path in SENSITIVE_PATHS:
        explanation.append("Sensitive endpoint accessed")
        return "Reconnaissance", "low", explanation

    # 2️⃣ Legit login (avoid false positives)
    if path in LOGIN_PATHS and method == "POST":
        allowed_fields = {"email", "username", "password"}
        if set(body_dict.keys()).issubset(allowed_fields):
            pwd = body_dict.get("password", "")
            if len(pwd) < 128 and entropy(pwd) < 4.5:
                explanation.append("Normal login attempt")
                return None, "info", explanation

    # 3️⃣ Bruteforce / fuzzing
    if method == "POST":
        if len(payload) > 800:
            explanation.append("Oversized POST payload")
            return "Fuzzing / Bruteforce", "medium", explanation
        if entropy(payload) > 5.2:
            explanation.append("High entropy payload")
            return "Fuzzing / Bruteforce", "medium", explanation

    # 4️⃣ SQL Injection
    sql_hits = sum(1 for p in SQL_KEYWORDS if re.search(p, payload, re.I))
    if sql_hits > 0:
        explanation.append(f"SQL grammar detected ({sql_hits} patterns)")
        return "SQL Injection", "high", explanation

    # 5️⃣ XSS
    for p in XSS_PATTERNS:
        if re.search(p, payload, re.I):
            explanation.append("Client-side script execution attempt")
            return "XSS", "high", explanation

    # 6️⃣ Command Injection
    for p in CMD_PATTERNS:
        if re.search(p, payload):
            explanation.append("Shell execution syntax detected")
            return "Command Injection", "high", explanation

    explanation.append("Benign request")
    return None, "info", explanation
