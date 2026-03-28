"""
Attack Statistics Tracker
Tracks total, malicious, blocked counts and per-attack-type breakdowns.
"""

stats = {
    "total_requests": 0,
    "malicious_requests": 0,
    "blocked_ips": 0,
    "attack_counts": {
        "XSS": 0,
        "SQL Injection": 0,
        "Command Injection": 0,
        "Path Traversal": 0,
        "SSRF": 0,
        "WAF_Bypass": 0,
        "Scanner": 0,
        "AI_Anomaly": 0,
        "Learned_Attack": 0,
        "Adaptive_Rule": 0,
        "Unknown": 0,
    },
}


def increment_total():
    stats["total_requests"] += 1


def increment_malicious(attack_type):
    stats["malicious_requests"] += 1
    at = (attack_type or "Unknown").strip() or "Unknown"
    if at not in stats["attack_counts"]:
        stats["attack_counts"][at] = 0
    stats["attack_counts"][at] += 1


def increment_blocked():
    stats["blocked_ips"] += 1


def get_stats():
    return dict(stats)


# legacy helper kept for compatibility
attack_types = {}

def track_attack_type(attack_type):
    if attack_type not in attack_types:
        attack_types[attack_type] = 0
    attack_types[attack_type] += 1
