
import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

# -------------------------------------
# PAGE CONFIGURATION
# -------------------------------------

st.set_page_config(
    page_title="SOC Security Monitoring Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# -------------------------------------
# LOAD SECURITY DATA
# -------------------------------------

project_folder = Path(__file__).parent

logs_file = project_folder / "data" / "security_logs.csv"
alerts_file = project_folder / "reports" / "security_alerts.csv"

@st.cache_data
def load_data():
    logs_df = pd.read_csv(logs_file)
    alerts_df = pd.read_csv(alerts_file)

    logs_df["timestamp"] = pd.to_datetime(
        logs_df["timestamp"]
    )
    alerts_df["timestamp"] = pd.to_datetime(
        alerts_df["timestamp"]
    )

    return logs_df, alerts_df


try:
    logs, alerts = load_data()
except (FileNotFoundError, pd.errors.EmptyDataError) as error:
    st.error(f"Unable to load security data: {error}")
    st.stop()

# -------------------------------------
# DASHBOARD HEADER
# -------------------------------------

st.title("🛡️ SOC Security Monitoring Dashboard")

st.caption(
    "Security Operations | Threat Detection | "
    "Alert Investigation | MITRE ATT&CK"
)

st.caption(
    "🧪 Demo Mode | Simulated security data — not live monitoring"
)

# -------------------------------------
# SECURITY METRICS
# -------------------------------------

total_events = len(logs)

successful_logins = (
    logs["event_type"] == "Login Success"
).sum()

failed_logins = (
    logs["event_type"] == "Login Failed"
).sum()

total_alerts = len(alerts)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", total_events)
col2.metric("Successful Logins", successful_logins)
col3.metric("Failed Logins", failed_logins)
col4.metric("Security Alerts", total_alerts)

st.divider()

# -------------------------------------
# CREATE DASHBOARD TABS
# -------------------------------------

tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Overview",
    "🚨 Alert Investigation",
    "🔍 Log Explorer",
    "📥 Reports"
])

# =====================================
# TAB 1 - SECURITY OVERVIEW
# =====================================

with tab1:

    st.subheader("Security Monitoring Overview")

    chart_col1, chart_col2 = st.columns(2)

    # Event distribution
    with chart_col1:

        event_counts = (
            logs["event_type"]
            .value_counts()
            .reset_index()
        )

        event_counts.columns = [
            "Event Type",
            "Count"
        ]

        fig_events = px.bar(
            event_counts,
            x="Event Type",
            y="Count",
            color="Event Type",
            title="Security Event Distribution"
        )

        fig_events.update_layout(
            height=360,
            showlegend=False,
            margin=dict(l=10, r=10, t=55, b=10)
        )

        st.plotly_chart(
            fig_events,
            width="stretch"
        )

    # Alert severity distribution
    with chart_col2:

        severity_counts = (
            alerts["severity"]
            .value_counts()
            .reindex(
                ["High", "Medium", "Low"],
                fill_value=0
            )
            .reset_index()
        )

        severity_counts.columns = [
            "Severity",
            "Count"
        ]

        fig_severity = px.pie(
            severity_counts,
            names="Severity",
            values="Count",
            hole=0.55,
            title="Security Alert Severity",
            color="Severity",
            color_discrete_map={
                "High": "#FF4B4B",
                "Medium": "#FFA500",
                "Low": "#00B894"
            }
        )

        fig_severity.update_layout(
            height=360,
            margin=dict(l=10, r=10, t=55, b=10)
        )

        st.plotly_chart(
            fig_severity,
            width="stretch"
        )

    # Second row of charts
    chart_col3, chart_col4 = st.columns(2)

    # Failed logins by IP
    with chart_col3:

        failed_data = logs[
            logs["event_type"] == "Login Failed"
        ]

        ip_counts = (
            failed_data["source_ip"]
            .value_counts()
            .reset_index()
        )

        ip_counts.columns = [
            "IP Address",
            "Failed Attempts"
        ]

        fig_ips = px.bar(
            ip_counts,
            x="IP Address",
            y="Failed Attempts",
            color="Failed Attempts",
            title="Failed Logins by Source IP",
            color_continuous_scale="Blues"
        )

        fig_ips.update_layout(
            height=360,
            margin=dict(l=10, r=10, t=55, b=10),
            xaxis_tickangle=-30
        )

        st.plotly_chart(
            fig_ips,
            width="stretch"
        )

    # Security event timeline
    with chart_col4:

        timeline_data = logs.copy()

        timeline_data["hour"] = (
            timeline_data["timestamp"].dt.floor("h")
        )

        hourly_events = (
            timeline_data.groupby(
                ["hour", "event_type"]
            )
            .size()
            .reset_index(name="count")
        )

        fig_timeline = px.line(
            hourly_events,
            x="hour",
            y="count",
            color="event_type",
            markers=True,
            title="Security Events Over Time",
            labels={
                "hour": "Time",
                "count": "Events",
                "event_type": "Event Type"
            }
        )

        fig_timeline.update_layout(
            height=360,
            margin=dict(l=10, r=10, t=55, b=10),
            legend_title_text=""
        )

        st.plotly_chart(
            fig_timeline,
            width="stretch"
        )

    st.caption(
        "All charts are based on the simulated security log dataset."
    )


# =====================================
# TAB 2 - ALERT INVESTIGATION
# =====================================

with tab2:

    st.subheader("🚨 Security Alert Investigation")

    st.write(
        "Review security alerts and investigate "
        "related authentication activity."
    )

    severity_filter = st.selectbox(
        "Filter alerts by severity",
        ["All", "High", "Medium", "Low"],
        key="alert_severity"
    )

    if severity_filter == "All":
        filtered_alerts = alerts.copy()
    else:
        filtered_alerts = alerts[
            alerts["severity"] == severity_filter
        ].copy()

    st.write(
        f"**Matching Security Alerts: {len(filtered_alerts)}**"
    )

    st.dataframe(
        filtered_alerts,
        width="stretch",
        hide_index=True,
        height=240
    )

    st.divider()

    st.subheader("🔎 SOC Alert Investigation Panel")

    if filtered_alerts.empty:
        st.info("No alerts match the selected severity.")

    else:

        alert_options = filtered_alerts.index.tolist()

        selected_index = st.selectbox(
            "Select an alert to investigate",
            options=alert_options,
            format_func=lambda i: (
                f"{alerts.loc[i, 'severity']} | "
                f"{alerts.loc[i, 'alert_type']} | "
                f"{alerts.loc[i, 'timestamp']}"
            ),
            key="selected_alert"
        )

        selected_alert = alerts.loc[selected_index]

        # Investigation summary
        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Severity",
            selected_alert["severity"]
        )

        col2.metric(
            "Source IP",
            str(selected_alert["source_ip"])
        )

        col3.metric(
            "Username",
            str(selected_alert["username"])
        )

        st.write(
            "**Alert Type:**",
            selected_alert["alert_type"]
        )

        st.write(
            "**Description:**",
            selected_alert["description"]
        )

        st.write(
            "**Alert Timestamp:**",
            selected_alert["timestamp"]
        )

        # -------------------------------------
        # MITRE ATT&CK MAPPING
        # -------------------------------------

        st.markdown("### 🎯 MITRE ATT&CK Mapping")

        alert_type = selected_alert["alert_type"]

        if alert_type == "Possible Brute Force":

            st.write(
                "**MITRE Technique:** T1110 - Brute Force"
            )

            st.write(
                "**Tactic:** Credential Access"
            )

            st.info(
                "Repeated failed login attempts from "
                "the same source IP may indicate "
                "password-guessing activity."
            )

            st.markdown(
                "[View MITRE ATT&CK Technique T1110]"
                "(https://attack.mitre.org/techniques/T1110/)"
            )

        elif alert_type == "Repeated Account Failures":

            st.write(
                "**Potential MITRE Technique:** "
                "T1110 - Brute Force"
            )

            st.write(
                "**Tactic:** Credential Access"
            )

            st.info(
                "Repeated failures against one account "
                "may indicate brute-force activity. "
                "Additional investigation is required."
            )

            st.markdown(
                "[View MITRE ATT&CK Technique T1110]"
                "(https://attack.mitre.org/techniques/T1110/)"
            )

        else:

            st.write(
                "**MITRE Technique:** Not assigned"
            )

            st.info(
                "An account lockout alone does not "
                "confirm a specific attack technique."
            )

        # -------------------------------------
        # RELATED SECURITY EVENTS
        # -------------------------------------

        st.markdown("### 📋 Related Security Events")

        related_logs = logs.copy()

        alert_ip = selected_alert["source_ip"]
        alert_user = selected_alert["username"]

        # Placeholder IPs are not actual source addresses.
        valid_ip = (
            pd.notna(alert_ip)
            and str(alert_ip).strip() not in [
                "",
                "Multiple/Unknown",
                "Unknown"
            ]
        )

        valid_user = (
            pd.notna(alert_user)
            and str(alert_user).strip() not in [
                "",
                "Multiple/Unknown",
                "Unknown"
            ]
        )

        if valid_ip:
            related_logs = related_logs[
                related_logs["source_ip"] == alert_ip
            ]

        elif valid_user:
            related_logs = related_logs[
                related_logs["username"] == alert_user
            ]

        else:
            related_logs = related_logs.iloc[0:0]

        # Show only failed logins for authentication
        # failure alerts.
        if alert_type in [
            "Possible Brute Force",
            "Repeated Account Failures"
        ]:
            related_logs = related_logs[
                related_logs["event_type"] == "Login Failed"
            ]

        # Account lockout alerts match the exact
        # lockout event when possible.
        elif alert_type == "Account Lockout":

            related_logs = related_logs[
                (related_logs["event_type"] == "Account Locked")
                & (
                    related_logs["timestamp"]
                    == selected_alert["timestamp"]
                )
            ]

        st.write(
            f"**Matching Events: {len(related_logs)}**"
        )

        if related_logs.empty:
            st.info("No related security events found.")

        else:
            st.dataframe(
                related_logs.sort_values(
                    "timestamp",
                    ascending=False
                ),
                width="stretch",
                hide_index=True,
                height=260
            )

        st.caption(
            "These are related records, not necessarily "
            "the exact events that triggered the detection rule."
        )


# =====================================
# TAB 3 - SECURITY LOG EXPLORER
# =====================================

with tab3:

    st.subheader("🔍 Security Log Explorer")

    st.write(
        "Investigate security events by filtering "
        "usernames, IP addresses, and event types."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        selected_user = st.selectbox(
            "Username",
            ["All"] + sorted(
                logs["username"].dropna().unique().tolist()
            ),
            key="log_username"
        )

    with col2:
        selected_ip = st.selectbox(
            "Source IP",
            ["All"] + sorted(
                logs["source_ip"].dropna().unique().tolist()
            ),
            key="log_ip"
        )

    with col3:
        selected_event = st.selectbox(
            "Event Type",
            ["All"] + sorted(
                logs["event_type"].dropna().unique().tolist()
            ),
            key="log_event"
        )

    filtered_logs = logs.copy()

    if selected_user != "All":
        filtered_logs = filtered_logs[
            filtered_logs["username"] == selected_user
        ]

    if selected_ip != "All":
        filtered_logs = filtered_logs[
            filtered_logs["source_ip"] == selected_ip
        ]

    if selected_event != "All":
        filtered_logs = filtered_logs[
            filtered_logs["event_type"] == selected_event
        ]

    st.metric(
        "Matching Security Events",
        len(filtered_logs)
    )

    st.dataframe(
        filtered_logs.sort_values(
            "timestamp",
            ascending=False
        ),
        width="stretch",
        hide_index=True,
        height=420
    )

    st.download_button(
        "📥 Download Filtered Logs",
        data=filtered_logs.to_csv(index=False),
        file_name="filtered_security_logs.csv",
        mime="text/csv",
        key="download_filtered_logs"
    )


# =====================================
# TAB 4 - REPORTS AND DOWNLOADS
# =====================================

with tab4:

    st.subheader("📥 Security Reports")

    st.write(
        "Review alert statistics and export "
        "security data for further investigation."
    )

    high_alerts = (
        alerts["severity"] == "High"
    ).sum()

    medium_alerts = (
        alerts["severity"] == "Medium"
    ).sum()

    low_alerts = (
        alerts["severity"] == "Low"
    ).sum()

    col1, col2, col3 = st.columns(3)

    col1.metric("High Severity", high_alerts)
    col2.metric("Medium Severity", medium_alerts)
    col3.metric("Low Severity", low_alerts)

    st.divider()

    st.markdown("### Download Security Reports")

    col1, col2 = st.columns(2)

    with col1:

        st.download_button(
            label="📥 Download All Security Alerts",
            data=alerts.to_csv(index=False),
            file_name="security_alerts.csv",
            mime="text/csv",
            width="stretch",
            key="download_alerts"
        )

    with col2:

        st.download_button(
            label="📥 Download All Security Logs",
            data=logs.to_csv(index=False),
            file_name="security_logs.csv",
            mime="text/csv",
            width="stretch",
            key="download_all_logs"
        )

    st.markdown("### Alert Summary")

    st.dataframe(
        severity_counts,
        width="stretch",
        hide_index=True
    )

    st.caption(
        "Reports contain simulated security events "
        "for educational and portfolio purposes."
    )

# -------------------------------------
# FOOTER
# -------------------------------------

st.divider()

st.caption(
    "SOC Security Monitoring Dashboard | "
    "Python • Pandas • Plotly • Streamlit | "
    "Simulated Security Data"
)
