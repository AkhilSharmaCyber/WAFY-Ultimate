"""Feature extractor for the ML classifier model (8 features)."""
import math


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    e = 0.0
    for f in freq.values():
        p = f / len(text)
        e -= p * math.log2(p)
    return e


def _numeric_text_ratio(text: str) -> float:
    if not text:
        return 0.0
    digits = sum(c.isdigit() for c in text)
    alpha = sum(c.isalpha() for c in text)
    return digits / alpha if alpha else float(digits)


def _special_char_count(text: str) -> int:
    specials = ["'", '"', "{", "}", "[", "]", "--", ";", "/", "\\", "=", "<", ">"]
    return sum(text.count(s) for s in specials)


def extract_features(uri: str, get_data: str, post_data: str) -> list:
    """Returns 8 features: [URI_Len, GET_Len, POST_Len, URI_Entropy,
    GET_Entropy, POST_Entropy, Numeric_Text_Ratio, Special_Char_Count]"""
    combined = uri + get_data + post_data
    return [
        len(uri),
        len(get_data),
        len(post_data),
        _entropy(uri),
        _entropy(get_data),
        _entropy(post_data),
        _numeric_text_ratio(combined),
        _special_char_count(combined),
    ]
