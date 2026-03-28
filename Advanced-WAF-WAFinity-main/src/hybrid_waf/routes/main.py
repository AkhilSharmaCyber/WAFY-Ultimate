from flask import Blueprint, jsonify, render_template

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    return render_template("index.html")


@main_bp.route('/home')
def home():
    return render_template("home.html")


@main_bp.route('/health')
def health():
    return jsonify({"status": "ok"})


@main_bp.route('/api/info')
def api_info():
    return jsonify({
        "service": "WAFinity WAF",
        "status": "running",
        "version": "2.0",
        "endpoints": {
            "check": "POST /check_request",
            "stats": "GET /stats_data",
            "live":  "GET /live_attacks",
            "recent": "GET /recent_attacks",
            "clusters": "GET /attack_clusters",
            "dashboard": "GET /stats",
        }
    })
