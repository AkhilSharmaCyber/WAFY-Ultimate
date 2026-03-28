"""Feedback loop — stores detection results for future model retraining."""

feedback_memory: list = []
MAX_ENTRIES = 500


def store_feedback(payload: str, attack_type: str, result: str) -> None:
    feedback_memory.append({
        "payload": payload[:200],
        "attack_type": attack_type,
        "result": result,
    })
    if len(feedback_memory) > MAX_ENTRIES:
        feedback_memory.pop(0)


def get_feedback() -> list:
    return list(feedback_memory)
