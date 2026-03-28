"""Per-IP behavior tracker — ratio of malicious to total requests."""

behavior_data: dict = {}


def update_behavior(ip: str, is_malicious: bool) -> None:
    if ip not in behavior_data:
        behavior_data[ip] = {"total": 0, "malicious": 0}
    behavior_data[ip]["total"] += 1
    if is_malicious:
        behavior_data[ip]["malicious"] += 1


def get_behavior_score(ip: str) -> float:
    """Returns ratio 0.0–1.0 of malicious requests for this IP."""
    d = behavior_data.get(ip)
    if not d or d["total"] == 0:
        return 0.0
    return d["malicious"] / d["total"]


def get_all_behavior() -> dict:
    return dict(behavior_data)
