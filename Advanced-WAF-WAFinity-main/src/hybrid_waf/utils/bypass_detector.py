"""WAF Bypass Attempt Detector."""
import re

BYPASS_PATTERNS = [
    "<scr<script>ipt>",
    "jaVasCript:",
    "jAvAsCrIpT:",
    "%00",
    "%2e%2e%2f",
    "..%2f",
    "%252e%252e%252f",
    "<%00script>",
    "<scr\x00ipt>",
    "\x00<script>",
    "&#106;avascript",   # HTML entity bypass
    "&#x6A;avascript",
    "vbscript:",
]

BYPASS_REGEX = [
    r"<\w+/\*.*?\*/\w*\s+on\w+=",  # comment injection in tag
    r"(?i)<script[^>]*>",           # script with attributes
    r"(?i)expression\s*\(",         # CSS expression()
    r"(?i)-moz-binding",
]


def is_bypass_attempt(payload: str) -> bool:
    lower = payload.lower()
    for p in BYPASS_PATTERNS:
        if p.lower() in lower:
            return True
    for pattern in BYPASS_REGEX:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False
