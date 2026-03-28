"""In-memory IP blocking with configurable threshold."""

blocked_ips: dict = {}
attack_counter: dict = {}
BLOCK_THRESHOLD = 5   # block after 5 attacks from same IP


def is_ip_blocked(ip: str) -> bool:
    return ip in blocked_ips


def register_attack(ip: str) -> bool:
    """Increment attack count; returns True if IP should now be blocked."""
    attack_counter[ip] = attack_counter.get(ip, 0) + 1
    if attack_counter[ip] >= BLOCK_THRESHOLD:
        blocked_ips[ip] = True
        return True
    return False


def unblock_ip(ip: str) -> None:
    blocked_ips.pop(ip, None)
    attack_counter.pop(ip, None)


def get_blocked_ips() -> list:
    return list(blocked_ips.keys())
