
import pandas as pd
from pathlib import Path

# Locate the project and security log file
project_folder = Path(__file__).parent
file_path = project_folder / "data" / "security_logs.csv"

# Read the CSV file
df = pd.read_csv(file_path)

# Convert timestamps into datetime format
df["timestamp"] = pd.to_datetime(df["timestamp"])

print("\n===== SOC SECURITY LOG ANALYSIS =====")

# 1. Total security events
print("\nTotal Security Events:", len(df))

# 2. Count different event types
print("\n--- Security Event Summary ---")
event_counts = df["event_type"].value_counts()
print(event_counts.to_string())

# 3. Filter failed login attempts
failed_logins = df[df["event_type"] == "Login Failed"]

print("\n--- Failed Login Analysis ---")
print("Total Failed Logins:", len(failed_logins))

# 4. Count failed logins for each IP
failed_by_ip = (
    failed_logins.groupby("source_ip")
    .size()
    .sort_values(ascending=False)
)

print("\n--- Failed Login Attempts by IP ---")
print(failed_by_ip.to_string())

# 5. Find IPs with 5 or more failed logins
suspicious_ips = failed_by_ip[failed_by_ip >= 5]

print("\n--- IPs Requiring Investigation ---")

if suspicious_ips.empty:
    print("No suspicious IPs found using this threshold.")
else:
    print(suspicious_ips.to_string())

# 6. Count failed logins by username
failed_by_user = (
    failed_logins.groupby("username")
    .size()
    .sort_values(ascending=False)
)

print("\n--- Failed Login Attempts by Username ---")
print(failed_by_user.to_string())

# 7. Create a report folder
report_folder = project_folder / "reports"
report_folder.mkdir(exist_ok=True)

# 8. Save the results as a CSV
report_path = report_folder / "failed_login_summary.csv"

failed_by_ip.rename(
    "failed_attempts"
).to_csv(report_path, header=True)

print("\nReport saved to:", report_path)
print("\n===== ANALYSIS COMPLETE =====")
