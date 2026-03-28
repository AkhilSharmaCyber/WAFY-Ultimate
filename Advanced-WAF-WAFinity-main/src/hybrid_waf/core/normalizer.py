"""
Payload Normalizer — double-decodes URL encoding, unescapes HTML entities,
strips null bytes and strips leading/trailing whitespace.
"""
import urllib.parse
import html
import re


def normalize_payload(payload: str) -> str:
    if not payload:
        return ""

    # Double URL-decode (handles %25xx → %xx → char)
    payload = urllib.parse.unquote(payload)
    payload = urllib.parse.unquote(payload)

    # HTML entity decode
    payload = html.unescape(payload)

    # Remove null bytes
    payload = payload.replace("\x00", "")

    # Collapse repeated whitespace
    payload = re.sub(r"\s+", " ", payload).strip()

    return payload
