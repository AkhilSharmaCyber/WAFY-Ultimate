"""Structured JSON logging for WAFinity."""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Optional

LOG_DIR = "logs"
ACCESS_LOG = os.path.join(LOG_DIR, "access.log")
ATTACK_LOG = os.path.join(LOG_DIR, "attack.log")
BLOCKED_IPS_LOG = os.path.join(LOG_DIR, "blocked_ips.log")
SYSTEM_LOG = os.path.join(LOG_DIR, "system.log")


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class _JsonFmt(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        d = getattr(record, "log_data", None)
        if isinstance(d, dict):
            return json.dumps(d, default=str)
        return json.dumps({"message": record.getMessage(), "timestamp": _ts()}, default=str)


def _logger(name: str, path: str) -> logging.Logger:
    os.makedirs(LOG_DIR, exist_ok=True)
    lg = logging.getLogger(f"wafinity.{name}")
    lg.setLevel(logging.INFO)
    lg.propagate = False
    if not lg.handlers:
        h = logging.FileHandler(path, encoding="utf-8")
        h.setFormatter(_JsonFmt())
        lg.addHandler(h)
    return lg


def _emit(lg: logging.Logger, data: dict, level: int = logging.INFO) -> None:
    r = logging.LogRecord(lg.name, level, "", 0, "", (), None)
    r.log_data = data
    lg.handle(r)


def log_access(client_ip, endpoint, method, payload="", action="allowed", user_agent="", **kw):
    _emit(_logger("access", ACCESS_LOG), {
        "timestamp": _ts(), "event": "request",
        "ip": client_ip, "method": method, "endpoint": endpoint,
        "payload": (payload or "")[:500], "action": action,
        "user_agent": user_agent, **kw
    })


def log_attack(client_ip, endpoint, method, payload, attack_type, threat_score,
               severity, action="flagged", user_agent="", detection_source="signature", **kw):
    _emit(_logger("attack", ATTACK_LOG), {
        "timestamp": _ts(), "event": "attack_detected",
        "ip": client_ip, "method": method, "endpoint": endpoint,
        "payload": (payload or "")[:1000],
        "attack_type": attack_type or "Unknown",
        "threat_score": threat_score, "severity": severity,
        "action": action, "user_agent": user_agent,
        "detection_source": detection_source, **kw
    })


def log_blocked_ip(client_ip, endpoint="", method="", user_agent="",
                   reason="threshold_exceeded", **kw):
    _emit(_logger("blocked", BLOCKED_IPS_LOG), {
        "timestamp": _ts(), "event": "ip_blocked",
        "ip": client_ip, "method": method, "endpoint": endpoint,
        "user_agent": user_agent, "reason": reason, **kw
    })


def log_system_error(message, exception: Optional[Exception] = None,
                     client_ip="", endpoint="", **kw):
    _emit(_logger("system", SYSTEM_LOG), {
        "timestamp": _ts(), "event": "system_error",
        "message": message, "exception": str(exception) if exception else "",
        "ip": client_ip, "endpoint": endpoint, **kw
    }, level=logging.ERROR)
