"""Online learning — remembers attack payloads and detects similar future ones."""

attack_patterns: list = []
MAX_PATTERNS = 1000


def learn_attack(payload: str) -> None:
    if payload and payload not in attack_patterns:
        attack_patterns.append(payload)
        if len(attack_patterns) > MAX_PATTERNS:
            attack_patterns.pop(0)


def is_similar_attack(payload: str) -> bool:
    for pattern in attack_patterns:
        # substring match in either direction
        if len(pattern) >= 10 and (pattern in payload or payload in pattern):
            return True
    return False
