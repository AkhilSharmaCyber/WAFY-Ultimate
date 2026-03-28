"""Feature extractor for the Isolation Forest anomaly detector (5 features)."""
import math
from collections import Counter


def _entropy(data: str) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def extract_features(payload: str, headers, request_count: int) -> list:
    """Returns 5 features for the anomaly model."""
    payload = str(payload)
    length = len(payload)
    entropy = _entropy(payload)
    try:
        header_count = len(headers)
    except Exception:
        header_count = 0
    special = sum(1 for c in payload if not c.isalnum())
    special_ratio = special / length if length else 0.0
    return [length, entropy, header_count, special_ratio, float(request_count)]
