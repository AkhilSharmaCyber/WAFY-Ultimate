"""Auto-defense decision engine."""


def decide_action(threat_score: int, behavior_score: float) -> str:
    """
    Returns "block" | "monitor" | "allow"
    """
    if threat_score >= 85 or behavior_score >= 0.8:
        return "block"
    if threat_score >= 50 or behavior_score >= 0.5:
        return "monitor"
    return "allow"
