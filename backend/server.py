from flask import Flask, jsonify
from flask_cors import CORS
import subprocess
import json
from ml_detector import detect_anomaly

app = Flask(__name__)
CORS(app)

@app.route("/api/events", methods=["GET"])
def get_events():
    command = (
        "Get-WinEvent -FilterHashtable "
        "@{LogName='Security'; Id=4624,4625} -MaxEvents 50 | "
        "Select-Object Id, RecordId, TimeCreated, MachineName, "
        "@{Name='Message';Expression={$_.Message}} | "
        "ConvertTo-Json -Compress"
    )

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=15
    )

    if result.returncode != 0:
        return jsonify({
            "error": "Unable to read Windows Security logs",
            "details": result.stderr.strip()
        }), 500

    if not result.stdout.strip():
        return jsonify({"events": []})

    data = json.loads(result.stdout)
    if isinstance(data, dict):
        data = [data]

    events = []

    for item in data:
        event_id = int(item["Id"])
        message = item.get("Message") or ""

        events.append({
            "id": event_id,
            "recordId": item.get("RecordId"),
            "time": item.get("TimeCreated"),
            "machine": item.get("MachineName"),
            "result": "SUCCESS" if event_id == 4624 else "FAILED",
            "message": message[:1500]
        })

    return jsonify({"events": events})

@app.route("/api/analyze", methods=["GET"])
def analyze_activity():
    try:
        result = detect_anomaly(
            failed_logins=12,
            login_hour=2,
            unique_ips=8
        )
        return jsonify(result)
    except Exception as error:
        return jsonify({"error": str(error)}), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
