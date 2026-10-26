
from flask import Flask, jsonify
from flask_cors import CORS
import os
from ml_detector import detect_anomaly

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return jsonify({
        "app": "SentinelX",
        "status": "running",
        "message": "Intrusion Detection API"
    })

@app.route("/api/events", methods=["GET"])
def get_events():
    # Cloud demo: Windows Security Logs are not available here.
    return jsonify({
        "mode": "demo",
        "events": [],
        "message": (
            "Live Windows Security Logs are available only "
            "when running on the monitored Windows machine."
        )
    })

@app.route("/api/analyze", methods=["GET"])
def analyze_activity():
    try:
        result = detect_anomaly(
            failed_logins=12,
            login_hour=2,
            unique_ips=8
        )
        return jsonify(result)
    except Exception:
        app.logger.exception("Threat analysis failed")
        return jsonify({"error": "Threat analysis failed"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
