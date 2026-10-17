
import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

# Configure dashboard
st.set_page_config(
    page_title="SOC Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Locate project files
project_folder = Path(__file__).parent

logs_file = project_folder / "data" / "security_logs.csv"
alerts_file = project_folder / "reports" / "security_alerts.csv"

# Load data
logs = pd.read_csv(logs_file)
alerts = pd.read_csv(alerts_file)

logs["timestamp"] = pd.to_datetime(logs["timestamp"])
alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])

# Dashboard title
st.title("🛡️ SOC Security Monitoring Dashboard")
st.caption("Security Event Monitoring and Threat Detection")

# Calculate metrics
total_events = len(logs)

failed_logins = len(
    logs[logs["event_type"] == "Login Failed"]
)

successful_logins = len(
    logs[logs["event_type"] == "Login Success"]
)

total_alerts = len(alerts)

# Display KPI cards
col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", total_events)
col2.metric("Successful Logins", successful_logins)
col3.metric("Failed Logins", failed_logins)
col4.metric("Security Alerts", total_alerts)

st.divider()

# Event distribution chart
st.subheader("Security Event Distribution")

event_counts = (
    logs["event_type"]
    .value_counts()
    .reset_index()
)

event_counts.columns = ["Event Type", "Count"]

fig_events = px.bar(
    event_counts,
    x="Event Type",
    y="Count",
    color="Event Type",
    title="Security Events by Type"
)

st.plotly_chart(fig_events, width="stretch")

# Failed logins by IP
st.subheader("Failed Login Attempts by IP Address")

failed_data = logs[
    logs["event_type"] == "Login Failed"
]

ip_counts = (
    failed_data["source_ip"]
    .value_counts()
    .reset_index()
)

ip_counts.columns = ["IP Address", "Failed Attempts"]

fig_ips = px.bar(
    ip_counts,
    x="IP Address",
    y="Failed Attempts",
    color="Failed Attempts",
    title="Failed Logins by Source IP"
)

st.plotly_chart(fig_ips, width="stretch")


# -------------------------------------
# SECURITY EVENT TIMELINE
# -------------------------------------

st.subheader("📈 Security Event Timeline")

# Create hourly time intervals
timeline_data = logs.copy()

timeline_data["hour"] = (
    timeline_data["timestamp"].dt.floor("h")
)

# Count events per hour and event type
hourly_events = (
    timeline_data.groupby(
        ["hour", "event_type"]
    )
    .size()
    .reset_index(name="count")
)

# Create the timeline chart
fig_timeline = px.line(
    hourly_events,
    x="hour",
    y="count",
    color="event_type",
    markers=True,
    title="Security Events Over Time",
    labels={
        "hour": "Time",
        "count": "Number of Events",
        "event_type": "Event Type"
    }
)

st.plotly_chart(
    fig_timeline,
    width="stretch"
)

st.divider()


# -------------------------------------
# INTERACTIVE SECURITY LOG EXPLORER
# -------------------------------------

st.subheader("🔍 Security Log Explorer")

st.write(
    "Filter security events by username, "
    "IP address, and event type."
)

# Create three filter columns
col1, col2, col3 = st.columns(3)

with col1:
    selected_user = st.selectbox(
        "Select Username",
        ["All"] + sorted(logs["username"].unique().tolist())
    )

with col2:
    selected_ip = st.selectbox(
        "Select IP Address",
        ["All"] + sorted(logs["source_ip"].unique().tolist())
    )

with col3:
    selected_event = st.selectbox(
        "Select Event Type",
        ["All"] + sorted(logs["event_type"].unique().tolist())
    )

# Create a copy of the original logs
filtered_logs = logs.copy()

# Apply username filter
if selected_user != "All":
    filtered_logs = filtered_logs[
        filtered_logs["username"] == selected_user
    ]

# Apply IP address filter
if selected_ip != "All":
    filtered_logs = filtered_logs[
        filtered_logs["source_ip"] == selected_ip
    ]

# Apply event type filter
if selected_event != "All":
    filtered_logs = filtered_logs[
        filtered_logs["event_type"] == selected_event
    ]

# Display number of matching events
st.write(
    f"**Matching Security Events: {len(filtered_logs)}**"
)

# Display filtered security logs
st.dataframe(
    filtered_logs.sort_values(
        "timestamp",
        ascending=False
    ),
    width="stretch",
    hide_index=True
)

st.divider()


# Security alerts
st.subheader("🚨 Security Alerts")

severity_filter = st.selectbox(
    "Filter alerts by severity",
    ["All", "High", "Medium", "Low"]
)

if severity_filter == "All":
    filtered_alerts = alerts
else:
    filtered_alerts = alerts[
        alerts["severity"] == severity_filter
    ]

st.dataframe(
    filtered_alerts,
    width="stretch",
    hide_index=True
)


# -------------------------------------
# ALERT SEVERITY VISUALIZATION
# -------------------------------------

st.subheader("📊 Security Alert Severity Analysis")

# Count alerts by severity
severity_counts = (
    alerts["severity"]
    .value_counts()
    .reindex(["High", "Medium", "Low"], fill_value=0)
    .reset_index()
)

severity_counts.columns = ["Severity", "Count"]

# Create a donut chart
fig_severity = px.pie(
    severity_counts,
    names="Severity",
    values="Count",
    hole=0.5,
    title="Security Alerts by Severity",
    color="Severity",
    color_discrete_map={
        "High": "#FF4B4B",
        "Medium": "#FFA500",
        "Low": "#00B894"
    }
)

st.plotly_chart(
    fig_severity,
    width="stretch"
)

st.divider()


# -------------------------------------
# DOWNLOAD SECURITY REPORTS
# -------------------------------------

st.subheader("📥 Download Security Reports")

col1, col2 = st.columns(2)

with col1:
    st.download_button(
        label="Download Security Alerts",
        data=filtered_alerts.to_csv(index=False),
        file_name="security_alerts.csv",
        mime="text/csv"
    )

with col2:
    st.download_button(
        label="Download Filtered Security Logs",
        data=filtered_logs.to_csv(index=False),
        file_name="filtered_security_logs.csv",
        mime="text/csv"
    )

st.divider()


st.caption(
    "This dashboard uses simulated security events. "
)
