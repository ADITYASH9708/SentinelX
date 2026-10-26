

from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
import os
from ml_detector import detect_anomaly

app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return jsonify({
        "app": "SentinelX",
        "status": "running",
        "mode": "demo"
    })


@app.route("/api/events", methods=["GET"])
def get_events():
    now = datetime.now(timezone.utc)

    events = [
        {
            "id": 4625,
            "recordId": 1005,
            "time": (now - timedelta(minutes=2)).isoformat(),
            "machine": "SentinelX-Demo",
            "result": "FAILED",
            "message": "Demo event: Failed login attempt detected."
        },
        {
            "id": 4624,
            "recordId": 1004,
            "time": (now - timedelta(minutes=5)).isoformat(),
            "machine": "SentinelX-Demo",
            "result": "SUCCESS",
            "message": "Demo event: Successful login."
        },
        {
            "id": 4625,
            "recordId": 1003,
            "time": (now - timedelta(minutes=8)).isoformat(),
            "machine": "SentinelX-Demo",
            "result": "FAILED",
            "message": "Demo event: Invalid credentials supplied."
        },
        {
            "id": 4624,
            "recordId": 1002,
            "time": (now - timedelta(minutes=12)).isoformat(),
            "machine": "SentinelX-Demo",
            "result": "SUCCESS",
            "message": "Demo event: Login completed successfully."
        },
        {
            "id": 4625,
            "recordId": 1001,
            "time": (now - timedelta(minutes=15)).isoformat(),
            "machine": "SentinelX-Demo",
            "result": "FAILED",
            "message": "Demo event: Login attempt rejected."
        }
    ]

    return jsonify({
        "mode": "demo",
        "events": events,
        "message": "Demonstration events only; not live Windows logs."
    })


@app.route("/api/analyze", methods=["GET"])
def analyze_activity():
    try:
        result = detect_anomaly(
            failed_logins=12,
            login_hour=2,
            unique_ips=8
        )
        result["mode"] = "demo"
        return jsonify(result)
    except Exception:
        app.logger.exception("Threat analysis failed")
        return jsonify({"error": "Threat analysis failed"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
