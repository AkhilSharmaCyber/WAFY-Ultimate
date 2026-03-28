"""
WAFinity - Advanced Hybrid Web Application Firewall
Main Flask application entry point.
"""
from flask import Flask
from flask_cors import CORS

from src.hybrid_waf.routes.main import main_bp
from src.hybrid_waf.routes.proxy import proxy_bp

app = Flask(__name__)

# Allow Chrome extension (localhost + 127.0.0.1) to call the API
CORS(app, resources={r"/*": {"origins": "*"}})

app.register_blueprint(main_bp)
app.register_blueprint(proxy_bp)

if __name__ == '__main__':
    print("\n" + "="*55)
    print("  WAFinity WAF Backend  -  http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(debug=True, port=5000, host="0.0.0.0")
