import json
from datetime import datetime

def evaluate_and_score(metrics: dict, src_ip: str, user: str):
    signals = []
   
    # Threshold 1: Classic Brute Force (Fast attempts targeting one user)
    if metrics["failures"] >= 10 and metrics["failure_rate"] > 0.8:
        signals.append("high_failures_single_user")
       
    # Threshold 2: Account Takeover Indicator (Success right after brute forcing)
    if metrics["failures"] >= 5 and metrics["successes"] >= 1:
        signals.append("success_after_failures")
       
    # Threshold 3: Horizontal Password Spraying (Targeting multiple users from one IP)
    if metrics["unique_users"] >= 3 and metrics["failures"] >= 6:
        signals.append("password_spraying")

    if not signals:
        return None

    # Calculate Risk Score
    weights = {"high_failures_single_user": 3, "success_after_failures": 5, "password_spraying": 4}
    total_score = sum(weights.get(sig, 1) for sig in signals)
   
    severity = "low"
    if total_score >= 6: severity = "high"
    elif total_score >= 3: severity = "medium"

    alert = {
        "timestamp": datetime.now().isoformat(),
        "src_ip": src_ip,
        "user": user,
        "metrics": metrics,
        "signals": signals,
        "severity": severity,
        "confidence": min(0.99, 0.4 + (0.1 * total_score))
    }
    return alert
