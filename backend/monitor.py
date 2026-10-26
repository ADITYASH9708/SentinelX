
import subprocess
import json
import time
from datetime import datetime, timezone

def read_login_events():
    command = (
        "Get-WinEvent -FilterHashtable "
        "@{LogName='Security'; Id=4624,4625} -MaxEvents 20 | "
        "Select-Object Id, TimeCreated, MachineName, "
        "@{Name='RecordId';Expression={$_.RecordId}} | "
        "ConvertTo-Json -Compress"
    )

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Could not read Windows events:", result.stderr)
        return []

    if not result.stdout.strip():
        return []

    events = json.loads(result.stdout)
    return events if isinstance(events, list) else [events]


def monitor():
    seen = set()
    print("SentinelX real Windows log monitoring started.")
    print("Checking for new login events every 5 seconds.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            events = read_login_events()

            for event in reversed(events):
                record_id = event.get("RecordId")

                if record_id is None or record_id in seen:
                    continue

                seen.add(record_id)
                event_id = int(event["Id"])

                status = (
                    "SUCCESSFUL LOGIN"
                    if event_id == 4624
                    else "FAILED LOGIN"
                )

                print(
                    f"[{event['TimeCreated']}] "
                    f"{status} | Event ID: {event_id} | "
                    f"Machine: {event.get('MachineName', 'Unknown')}"
                )

            # Keep memory usage bounded during long sessions.
            if len(seen) > 5000:
                seen.clear()
                for event in events:
                    if event.get("RecordId") is not None:
                        seen.add(event["RecordId"])

            time.sleep(5)

    except KeyboardInterrupt:
        print("\nSentinelX monitoring stopped.")


if __name__ == "__main__":
    monitor()

