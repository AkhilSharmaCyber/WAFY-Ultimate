"""
Signature-based detection engine.
Returns: "malicious" | "obfuscated" | "valid"
"""
import re

# ────────────────────────────────────────────────
#  MALICIOUS PATTERNS
# ────────────────────────────────────────────────
MALICIOUS_PATTERNS = [
    # SQL Injection
    r"(?i)union\s+select",
    r"(?i)drop\s+table",
    r"(?i)or\s+1\s*=\s*1",
    r"(?i)select\s+.*\s+from",
    r"(?i)insert\s+into",
    r"(?i)delete\s+from",
    r"(?i)update\s+.*\s+set",
    r"(?i)exec\s*\(",
    r"(?i)xp_cmdshell",
    r"(?i)waitfor\s+delay",
    r"(?i)'; *drop",
    r"(?i)or\s+'a'\s*=\s*'a",
    r"(?i)and\s+sleep\s*\(",
    r"(?i)or\s+sleep\s*\(",
    r"(?i)benchmark\s*\(",
    r"(?i)select\s+@@version",
    r"(?i)select\s+@@datadir",
    r"(?i)select\s+load_file",
    r"(?i)select\s+user\s*\(\s*\)",
    r"(?i)select\s+database\s*\(\s*\)",
    r"' or '1'\s*=\s*'1",
    r"\" or \"1\"\s*=\s*\"1",
    r"(?i)having\s+1\s*=\s*1",
    r"(?i)group by.*having",
    r"(?i)order by \d+",
    r"(?i)extractvalue\s*\(",
    r"(?i)updatexml\s*\(",
    r"convert\s*\(\s*int",
    r"(?i)' union all select",
    r"(?i)admin'--",
    r"--\s*$",
    # XSS
    r"(?i)<script[\s>]",
    r"(?i)</script>",
    r"(?i)javascript\s*:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)onmouseover\s*=",
    r"(?i)onclick\s*=",
    r"(?i)onfocus\s*=",
    r"(?i)onblur\s*=",
    r"(?i)onkeydown\s*=",
    r"(?i)onkeyup\s*=",
    r"(?i)alert\s*\(",
    r"(?i)confirm\s*\(",
    r"(?i)prompt\s*\(",
    r"(?i)document\.cookie",
    r"(?i)window\.location",
    r"(?i)eval\s*\(",
    r"(?i)settimeout\s*\(",
    r"(?i)setinterval\s*\(",
    r"(?i)innerhtml\s*=",
    r"(?i)srcdoc\s*=",
    r"(?i)String\.fromCharCode",
    r"(?i)constructor\.constructor",
    r"(?i)<iframe",
    r"(?i)<svg[\s>]",
    r"(?i)<img[^>]+onerror",
    r"(?i)<body[^>]+onload",
    r"data:text/html",
    r"(?i)<embed",
    r"(?i)<object",
    r"&#x[0-9a-f]+;",
    # Path Traversal
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
    r"boot\.ini",
    r"(?i)windows[/\\]system32",
    r"win\.ini",
    r"%2e%2e%2f",
    r"%252e%252e%252f",
    # Command Injection
    r";\s*(ls|cat|whoami|pwd|id|uname|curl|wget|bash|sh|python|perl|nc)\b",
    r"\|\s*(ls|cat|whoami|pwd|id|uname|curl|wget|bash|sh|python|perl|nc)\b",
    r"&&\s*(ls|cat|whoami|pwd|id|uname|curl|wget|bash|sh)",
    r"\$\(.*\)",
    r"`[^`]+`",
    r"(?i)/bin/(bash|sh|zsh|ksh)",
    # SSRF
    r"(?i)file://",
    r"(?i)gopher://",
    r"(?i)dict://",
    r"http://127\.0\.0\.1",
    r"http://localhost",
    r"http://0\.0\.0\.0",
    r"169\.254\.169\.254",
    r"metadata\.google\.internal",
    r"(?i)kubernetes\.default\.svc",
    r"http://10\.",
    r"http://192\.168\.",
    r"http://172\.(1[6-9]|2\d|3[01])\.",
    r"0x7f000001",
    r"file:/etc/passwd",
]

# ────────────────────────────────────────────────
#  OBFUSCATION PATTERNS (need ML second opinion)
# ────────────────────────────────────────────────
OBFUSCATION_PATTERNS = [
    r"(%[0-9A-Fa-f]{2}){3,}",       # heavy URL encoding
    r"(\\x[0-9A-Fa-f]{2}){2,}",     # hex escape sequences
    r"(\\u[0-9A-Fa-f]{4}){2,}",     # unicode escapes
    r"(?i)\bchar\s*\(",              # SQL CHAR()
    r"(?i)\bconcat\s*\(",            # SQL CONCAT
    r"(?i)\bsubstr(ing)?\s*\(",      # SQL SUBSTR
    r"(?i)base64_decode\s*\(",
    r"(?i)fromCharCode",
    r"(?i)decodeURIComponent\s*\(",
    r"(?i)\bROT13\b",
    r"(?i)\bmd5\s*\(",
    r"(?i)\bsha1\s*\(",
    r"(?i)\bcase\s+when\b",          # SQL CASE obfuscation
    r"(?:/\*.*?\*/)",                # inline SQL comments
    r"--[^\n]*",                     # SQL line comments
]

# ────────────────────────────────────────────────
#  ATTACK TYPE DETECTION
# ────────────────────────────────────────────────
ATTACK_TYPE_MAP = {
    "SQL Injection": [
        r"(?i)union\s+select",
        r"(?i)or\s+1\s*=\s*1",
        r"(?i)select\s+.*\s+from",
        r"(?i)drop\s+table",
        r"(?i)waitfor\s+delay",
        r"(?i)exec\s*\(",
    ],
    "XSS": [
        r"(?i)<script",
        r"(?i)onerror\s*=",
        r"(?i)onload\s*=",
        r"(?i)alert\s*\(",
        r"(?i)javascript\s*:",
        r"(?i)eval\s*\(",
    ],
    "Path Traversal": [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"boot\.ini",
    ],
    "Command Injection": [
        r";\s*(ls|cat|whoami)",
        r"&&\s*(ls|cat|whoami)",
        r"\|\s*(ls|cat|whoami)",
        r"`[^`]+`",
        r"\$\(.*\)",
    ],
    "SSRF": [
        r"http://127\.0\.0\.1",
        r"http://localhost",
        r"169\.254\.169\.254",
        r"(?i)file://",
        r"(?i)gopher://",
        r"http://10\.",
        r"http://192\.168\.",
    ],
}


def check_signature(user_input: str) -> str:
    """
    Returns:
        "malicious"  — definite attack pattern matched
        "obfuscated" — suspicious encoding, needs ML
        "valid"      — clean
    """
    text = " ".join(user_input.split())

    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            return "malicious"

    for pattern in OBFUSCATION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            return "obfuscated"

    return "valid"


def detect_attack_type(user_input: str) -> str:
    """Returns the most likely attack type string, or 'Unknown'."""
    for attack, patterns in ATTACK_TYPE_MAP.items():
        for pattern in patterns:
            if re.search(pattern, user_input, re.IGNORECASE | re.DOTALL):
                return attack
    return "Unknown"
