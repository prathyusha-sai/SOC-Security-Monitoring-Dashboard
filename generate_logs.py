
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

# Create the data folder if needed
data_folder = Path(__file__).parent / "data"
data_folder.mkdir(exist_ok=True)

output_file = data_folder / "security_logs.csv"

users = ["admin", "john", "sarah", "analyst", "guest"]

ip_addresses = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.30",
    "192.168.1.40",
    "10.0.0.15"
]

event_types = [
    "Login Success",
    "Login Failed",
    "Access Denied",
    "Account Locked"
]

logs = []
start_time = datetime(2026, 10, 12, 8, 0, 0)

# Generate 190 simulated events
for i in range(190):
    timestamp = start_time + timedelta(minutes=i * 3)

    event = random.choices(
        event_types,
        weights=[55, 30, 10, 5],
        k=1
    )[0]

    logs.append({
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "username": random.choice(users),
        "source_ip": random.choice(ip_addresses),
        "event_type": event
    })

# Add 10 repeated failed logins from one IP
for i in range(10):
    logs.append({
        "timestamp": (
            start_time + timedelta(hours=5, seconds=i * 20)
        ).strftime("%Y-%m-%d %H:%M:%S"),
        "username": "admin",
        "source_ip": "192.168.1.99",
        "event_type": "Login Failed"
    })

# Sort all events by time
logs.sort(key=lambda log: log["timestamp"])

# Save the CSV file
with open(output_file, "w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(
        file,
        fieldnames=[
            "timestamp",
            "username",
            "source_ip",
            "event_type"
        ]
    )

    writer.writeheader()
    writer.writerows(logs)

print(f"Successfully generated {len(logs)} security events!")
print(f"File saved to: {output_file}")
