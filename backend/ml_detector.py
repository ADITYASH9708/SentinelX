
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

MODEL_PATH = Path(__file__).with_name("sentinelx_model.joblib")

FEATURES = ["failed_logins", "login_hour", "unique_ips"]


def create_training_data():
    normal = [
        [0, 9, 1], [1, 10, 1], [0, 11, 1],
        [1, 14, 1], [0, 15, 1], [2, 16, 1],
        [0, 13, 2], [1, 12, 1], [0, 10, 2],
        [1, 17, 1], [0, 8, 1], [2, 18, 1],
        [0, 14, 1], [1, 9, 1], [0, 16, 1],
        [2, 11, 1], [1, 15, 2], [0, 12, 1],
        [1, 13, 1], [0, 17, 1], [2, 10, 1],
        [0, 7, 1], [1, 16, 1], [0, 18, 2],
    ]

    unusual = [
        [12, 2, 8], [15, 3, 6], [10, 1, 9],
        [20, 2, 12], [18, 4, 10], [14, 0, 7],
    ]

    return pd.DataFrame(normal + unusual, columns=FEATURES)


def train_model():
    data = create_training_data()

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("detector", IsolationForest(
            n_estimators=200,
            contamination=0.20,
            random_state=42
        ))
    ])

    model.fit(data)
    joblib.dump(model, MODEL_PATH)

    print("SentinelX ML model trained.")
    print(f"Training examples: {len(data)}")
    print(f"Saved model: {MODEL_PATH}")

    return model


def detect_anomaly(failed_logins, login_hour, unique_ips):
    failed_logins = int(failed_logins)
    login_hour = int(login_hour)
    unique_ips = int(unique_ips)

    if failed_logins < 0:
        raise ValueError("failed_logins cannot be negative.")

    if not 0 <= login_hour <= 23:
        raise ValueError("login_hour must be between 0 and 23.")

    if unique_ips < 1:
        raise ValueError("unique_ips must be at least 1.")

    if not MODEL_PATH.exists():
        train_model()

    model = joblib.load(MODEL_PATH)

    sample = pd.DataFrame([{
        "failed_logins": failed_logins,
        "login_hour": login_hour,
        "unique_ips": unique_ips
    }], columns=FEATURES)

    prediction = int(model.predict(sample)[0])
    score = float(model.decision_function(sample)[0])

    # Explicit security rule supplements the ML model.
    # This is a heuristic, not proof of an attack.
    rule_triggered = (
        failed_logins >= 5 or
        (failed_logins >= 3 and unique_ips >= 3)
    )

    suspicious = prediction == -1 or rule_triggered

    return {
        "status": "SUSPICIOUS" if suspicious else "NORMAL",
        "anomaly_score": round(score, 4),
        "ml_prediction": (
            "ANOMALY" if prediction == -1 else "NORMAL"
        ),
        "rule_triggered": rule_triggered,
        "features": {
            "failed_logins": failed_logins,
            "login_hour": login_hour,
            "unique_ips": unique_ips
        },
        "model": "Isolation Forest + security heuristic",
        "note": (
            "Experimental model trained on synthetic examples. "
            "A suspicious result requires investigation."
        )
    }


if __name__ == "__main__":
    train_model()

    tests = [
        ("Ordinary login", 1, 10, 1),
        ("Repeated failures", 12, 2, 8),
        ("Moderate activity", 3, 14, 1),
    ]

    for name, failures, hour, ips in tests:
        print(f"\n{name}:")
        print(detect_anomaly(failures, hour, ips))

