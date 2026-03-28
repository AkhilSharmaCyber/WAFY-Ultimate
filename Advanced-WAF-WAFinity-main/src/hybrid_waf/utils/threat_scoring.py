"""Threat Scoring — returns 0-100 score and severity label."""

ATTACK_BONUS = {
    "SQL Injection": 20,
    "Command Injection": 25,
    "SSRF": 22,
    "Path Traversal": 18,
    "XSS": 15,
    "WAF_Bypass": 20,
    "Scanner": 12,
    "AI_Anomaly": 10,
    "Learned_Attack": 12,
    "Adaptive_Rule": 10,
}


def calculate_threat_score(attack_type: str, signature_result: str, features=None) -> int:
    score = 0
    if signature_result == "malicious":
        score += 70
    elif signature_result == "obfuscated":
        score += 40

    at = (attack_type or "Unknown").strip()
    score += ATTACK_BONUS.get(at, 8)

    if features is not None:
        try:
            score += min(int(sum(features)) * 2, 10)
        except (TypeError, ValueError):
            pass

    return max(0, min(100, int(score)))


def get_severity(score: int) -> str:
    s = int(score or 0)
    if s >= 90:
        return "CRITICAL"
    if s >= 60:
        return "HIGH"
    if s >= 40:
        return "MEDIUM"
    return "LOW"
