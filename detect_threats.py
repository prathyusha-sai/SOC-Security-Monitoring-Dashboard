
import pandas as pd
from pathlib import Path

# Locate project files
project_folder = Path(__file__).parent
log_file = project_folder / "data" / "security_logs.csv"

# Read security logs
df = pd.read_csv(log_file)

# Convert timestamps to datetime
df["timestamp"] = pd.to_datetime(df["timestamp"])

# Sort events chronologically
df = df.sort_values("timestamp")

# Store detected security alerts
alerts = []

print("\n===== SOC THREAT DETECTION =====")

# ------------------------------------
# RULE 1: BRUTE-FORCE DETECTION
# ------------------------------------

failed = df[df["event_type"] == "Login Failed"]

for ip, group in failed.groupby("source_ip"):

    group = group.sort_values("timestamp")
    times = group["timestamp"].tolist()

    left = 0

    for right in range(len(times)):

        # Keep only events within 5 minutes
        while (
            times[right] - times[left]
            > pd.Timedelta(minutes=5)
        ):
            left += 1

        count = right - left + 1

        # Generate one alert per IP
        if count >= 5:
            alerts.append({
                "timestamp": times[right],
                "source_ip": ip,
                "username": "Multiple/Unknown",
                "alert_type": "Possible Brute Force",
                "severity": "High",
                "description": (
                    f"{count} failed logins within 5 minutes"
                )
            })

            break

# ------------------------------------
# RULE 2: REPEATED ACCOUNT FAILURES
# ------------------------------------

failed_by_user = (
    failed.groupby("username")
    .size()
)

for username, count in failed_by_user.items():

    if count >= 10:
        user_events = failed[
            failed["username"] == username
        ]

        alerts.append({
            "timestamp": user_events["timestamp"].max(),
            "source_ip": "Multiple/Unknown",
            "username": username,
            "alert_type": "Repeated Account Failures",
            "severity": "Medium",
            "description": (
                f"{count} failed logins for account"
            )
        })

# ------------------------------------
# RULE 3: ACCOUNT LOCKOUT
# ------------------------------------

lockouts = df[df["event_type"] == "Account Locked"]

for _, event in lockouts.iterrows():

    alerts.append({
        "timestamp": event["timestamp"],
        "source_ip": event["source_ip"],
        "username": event["username"],
        "alert_type": "Account Lockout",
        "severity": "Low",
        "description": "Account lockout event detected"
    })

# ------------------------------------
# SAVE ALERT REPORT
# ------------------------------------

report_folder = project_folder / "reports"
report_folder.mkdir(exist_ok=True)

report_file = report_folder / "security_alerts.csv"

columns = [
    "timestamp",
    "source_ip",
    "username",
    "alert_type",
    "severity",
    "description"
]

alerts_df = pd.DataFrame(alerts, columns=columns)

if not alerts_df.empty:
    alerts_df = alerts_df.sort_values("timestamp")

alerts_df.to_csv(report_file, index=False)

# Display results
print(f"\nTotal Alerts Generated: {len(alerts_df)}")

print("\n--- Alerts by Severity ---")

if alerts_df.empty:
    print("No security alerts detected.")
else:
    print(alerts_df["severity"].value_counts().to_string())

print("\n--- Security Alerts ---")

if alerts_df.empty:
    print("No alerts to display.")
else:
    print(
        alerts_df[
            ["source_ip", "username", "alert_type", "severity"]
        ].to_string(index=False)
    )

print(f"\nAlert report saved to: {report_file}")

print("\n===== DETECTION COMPLETE =====")
