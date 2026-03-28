"""
WAFinity Core Proxy / Check Route
Handles incoming payload analysis and threat detection pipeline.
"""
from flask import Blueprint, request, jsonify, render_template
import time
import urllib.parse

# -------------------------------------------------- #
#  DEV_MODE = False  →  IP blocking / rate limiting  #
#  DEV_MODE = True   →  log-only (never hard-blocks) #
# -------------------------------------------------- #
DEV_MODE = True

# ---- globals ---- #
live_attacks = []
request_counts = {}

TIME_WINDOW = 60   # seconds
MAX_REQUESTS = 100  # per IP per TIME_WINDOW

proxy_bp = Blueprint('proxy', __name__)

# ---- local imports ---- #
from src.hybrid_waf.core.normalizer import normalize_payload
from src.hybrid_waf.utils.signature_checker import check_signature, detect_attack_type
from src.hybrid_waf.utils.threat_scoring import calculate_threat_score, get_severity
from src.hybrid_waf.utils.ip_blocker import is_ip_blocked, register_attack
from src.hybrid_waf.utils.attack_stats import (
    increment_total, increment_malicious, increment_blocked, track_attack_type, get_stats
)
from src.hybrid_waf.utils.ml_checker import check_ml_prediction
from src.hybrid_waf.utils.preprocessor import extract_features as ml_extract
from src.hybrid_waf.ai.feature_extractor import extract_features as ai_extract
from src.hybrid_waf.ai.anomaly_detector import predict
from src.hybrid_waf.ai.attack_clusterer import add_attack_sample, run_clustering
from src.hybrid_waf.ai.behavior_tracker import update_behavior, get_behavior_score
from src.hybrid_waf.ai.online_learning import learn_attack, is_similar_attack
from src.hybrid_waf.intel.threat_feed import is_bad_ip, is_known_tool
from src.hybrid_waf.utils.bypass_detector import is_bypass_attempt
from src.hybrid_waf.ai.adaptive_rules import generate_rule, match_auto_rule
from src.hybrid_waf.ai.attack_explainer import explain_attack
from src.hybrid_waf.ai.auto_defense import decide_action
from src.hybrid_waf.ai.feedback_loop import store_feedback
from src.hybrid_waf.utils.logging_manager import log_access, log_attack, log_blocked_ip, log_system_error


# ---- helpers ---- #

def is_rate_limited(ip):
    now = time.time()
    if ip not in request_counts:
        request_counts[ip] = []
    request_counts[ip] = [t for t in request_counts[ip] if now - t < TIME_WINDOW]
    request_counts[ip].append(now)
    return len(request_counts[ip]) > MAX_REQUESTS


def add_live_attack(payload, attack_type, severity, threat_score, ip):
    entry = {
        "payload": payload[:200],
        "attack_type": attack_type,
        "severity": severity,
        "threat_score": threat_score,
        "ip": ip,
        "time": time.strftime("%H:%M:%S")
    }
    live_attacks.append(entry)
    if len(live_attacks) > 50:
        live_attacks.pop(0)


def _malicious_response(attack_type, severity, threat_score, message, explanation):
    return {
        "status": "malicious",
        "attack_type": attack_type,
        "severity": severity,
        "threat_score": int(threat_score),
        "explanation": explanation,
        "message": message,
    }


# ---- main check route ---- #

@proxy_bp.route('/check_request', methods=['POST'])
def check_request():
    data = request.get_json(silent=True) or {}

    client_ip = request.remote_addr or "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "")
    user_input = data.get("user_request", "")
    user_input = urllib.parse.unquote(user_input)

    # Always count total requests
    increment_total()

    print(f"[WAFinity] Checking: {user_input[:120]!r}")

    normalized_input = normalize_payload(user_input).lower()

    # ---- RATE LIMIT ---- #
    if is_rate_limited(client_ip) and not DEV_MODE:
        log_access(client_ip, "/check_request", "POST", user_input, "rate_limited", user_agent)
        return jsonify({"status": "blocked", "message": "Rate limit exceeded"}), 429

    # ---- IP BLOCK ---- #
    if is_ip_blocked(client_ip) and not DEV_MODE:
        return jsonify({"status": "blocked", "message": "IP blocked"}), 403

    # ---- THREAT INTEL ---- #
    if is_bad_ip(client_ip) and not DEV_MODE:
        return jsonify({"status": "blocked", "message": "Malicious IP"}), 403

    if is_known_tool(normalized_input):
        attack_type = "Scanner"
        threat_score = calculate_threat_score(attack_type, "malicious")
        severity = get_severity(threat_score)
        add_live_attack(user_input, attack_type, severity, threat_score, client_ip)
        increment_malicious(attack_type)
        track_attack_type(attack_type)
        return jsonify(_malicious_response(
            attack_type, severity, threat_score,
            "Known attack tool detected",
            explain_attack(normalized_input, attack_type)
        ))

    # ---- BYPASS DETECTION ---- #
    if is_bypass_attempt(normalized_input):
        attack_type = "WAF_Bypass"
        threat_score = calculate_threat_score(attack_type, "malicious")
        severity = get_severity(threat_score)
        add_live_attack(user_input, attack_type, severity, threat_score, client_ip)
        increment_malicious(attack_type)
        track_attack_type(attack_type)
        return jsonify(_malicious_response(
            attack_type, severity, threat_score,
            "WAF bypass attempt detected",
            explain_attack(normalized_input, attack_type)
        ))

    # ---- ONLINE LEARNING / SIGNATURE ---- #
    if is_similar_attack(normalized_input):
        signature_result = "malicious"
        attack_type = "Learned_Attack"
    else:
        signature_result = check_signature(normalized_input)
        attack_type = None

    # ---- AUTO RULE MATCH ---- #
    if signature_result != "malicious" and match_auto_rule(normalized_input):
        signature_result = "malicious"
        attack_type = "Adaptive_Rule"

    # ---- AI ANOMALY ---- #
    try:
        ai_features = ai_extract(normalized_input, request.headers, 1)
        if predict(ai_features) == -1 and signature_result != "malicious":
            signature_result = "malicious"
            attack_type = "AI_Anomaly"
    except Exception as e:
        log_system_error("AI anomaly error", e, client_ip, "/check_request")

    # ---- VALID ---- #
    if signature_result == "valid":
        update_behavior(client_ip, False)
        log_access(client_ip, "/check_request", "POST", user_input, "allowed", user_agent)
        return jsonify({"status": "valid", "message": "Safe ✅"})

    # ---- MALICIOUS ---- #
    if signature_result == "malicious":
        if not attack_type:
            attack_type = detect_attack_type(normalized_input) or "Unknown"

        update_behavior(client_ip, True)
        increment_malicious(attack_type)
        track_attack_type(attack_type)

        generate_rule(normalized_input)
        learn_attack(normalized_input)

        try:
            features = ai_extract(normalized_input, request.headers, 1)
            add_attack_sample(features, user_input)
        except Exception:
            pass

        threat_score = calculate_threat_score(attack_type, "malicious")
        severity = get_severity(threat_score)

        behavior_score = get_behavior_score(client_ip)
        action = decide_action(threat_score, behavior_score)

        add_live_attack(user_input, attack_type, severity, threat_score, client_ip)

        log_attack(
            client_ip, "/check_request", "POST", user_input,
            attack_type, threat_score, severity, action, user_agent, "signature"
        )

        if action == "block" and not DEV_MODE:
            ip_blocked = register_attack(client_ip)
            if ip_blocked:
                increment_blocked()
                log_blocked_ip(client_ip)
            return jsonify({"status": "blocked", "message": "Auto-blocked by WAFinity"}), 403

        store_feedback(normalized_input, attack_type, "malicious")

        return jsonify(_malicious_response(
            attack_type, severity, threat_score,
            "Malicious payload detected 🚨",
            explain_attack(normalized_input, attack_type)
        ))

    # ---- OBFUSCATED → ML ---- #
    if signature_result == "obfuscated":
        try:
            features = ml_extract(user_input, "", "")
            prediction = check_ml_prediction(features)

            if prediction == 1:
                attack_type = detect_attack_type(normalized_input) or "Unknown"
                threat_score = calculate_threat_score(attack_type, "obfuscated")
                severity = get_severity(threat_score)

                add_live_attack(user_input, attack_type, severity, threat_score, client_ip)
                increment_malicious(attack_type)
                track_attack_type(attack_type)

                log_attack(
                    client_ip, "/check_request", "POST", user_input,
                    attack_type, threat_score, severity, "flagged", user_agent, "ml"
                )

                return jsonify(_malicious_response(
                    attack_type, severity, threat_score,
                    "Obfuscated attack detected via ML 🤖",
                    explain_attack(normalized_input, attack_type)
                ))

            return jsonify({"status": "obfuscated", "ml_verdict": "safe", "message": "Suspicious but ML cleared ⚠️"})

        except Exception as e:
            log_system_error("ML error", e, client_ip, "/check_request")

    log_access(client_ip, "/check_request", "POST", user_input, "allowed", user_agent)
    return jsonify({"status": "valid", "message": "Safe ✅"})


# ---- dashboard / API routes ---- #

@proxy_bp.route('/stats')
def dashboard():
    return render_template("dashboard.html")


@proxy_bp.route('/stats_data')
def stats_data():
    return jsonify(get_stats())


@proxy_bp.route('/attack_clusters')
def attack_clusters():
    return jsonify(run_clustering())


@proxy_bp.route('/live_attacks')
def get_live_attacks():
    return jsonify(live_attacks)


@proxy_bp.route('/recent_attacks')
def recent_attacks():
    """Last 10 attacks with full detail — used by extension popup."""
    return jsonify(list(reversed(live_attacks[-10:])))
