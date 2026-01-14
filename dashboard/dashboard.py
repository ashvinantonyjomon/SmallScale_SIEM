# import streamlit as st
# import pandas as pd
# import sqlite3

# st.set_page_config(page_title="SIEM Dashboard", layout="wide")

# conn = sqlite3.connect("../backend/siem.db")

# st.title("SIEM Dashboard")

# # Logs
# st.header("Logs")
# logs = pd.read_sql("SELECT * FROM logs ORDER BY timestamp DESC", conn)
# st.dataframe(logs)

# # Alerts
# st.header("Alerts")
# alerts = pd.read_sql("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
# st.dataframe(alerts)

# # Metrics
# st.header("Metrics")
# st.metric("Total Logs", len(logs))
# st.metric("Total Alerts", len(alerts))

import streamlit as st
import pandas as pd
import sqlite3
import time
from streamlit_autorefresh import st_autorefresh


# ---------------- CONFIG ----------------
st.set_page_config(
    page_title="SIEM Dashboard",
    layout="wide",
)

REFRESH_INTERVAL = 2  # seconds

# ---------------- refresh ----------------
st_autorefresh(interval=REFRESH_INTERVAL * 1000, key="siem_refresh")

#-----------------DB------------------
@st.cache_resource
def get_connection():
    return sqlite3.connect(
        "../backend/siem.db",
        check_same_thread=False
    )

conn = get_connection()



# ---------------- AUTO REFRESH ----------------
# st.experimental_autorefresh(
#     interval=REFRESH_INTERVAL * 1000,
#     key="siem_refresh"
# )

# ---------------- TITLE ----------------
st.title("🛡️ Real-Time SIEM Dashboard")

# ---------------- LOAD DATA ----------------
logs = pd.read_sql(
    "SELECT * FROM logs ORDER BY timestamp DESC",
    conn
)

alerts = pd.read_sql(
    "SELECT * FROM alerts ORDER BY timestamp DESC",
    conn
)

# ---------------- METRICS ----------------
c1, c2, c3 = st.columns(3)

c1.metric("📄 Total Logs", len(logs))
c2.metric("🚨 Total Alerts", len(alerts))
c3.metric("⚠️ Critical Alerts", len(alerts[alerts["severity"] == "Critical"]))

st.divider()

# =========================================================
# 📊 EVENTS PER MINUTE (REAL SIEM GRAPH)
# =========================================================
st.subheader("📈 Events Per Minute")

if not logs.empty:
    logs["timestamp"] = pd.to_datetime(logs["timestamp"])
    logs["minute"] = logs["timestamp"].dt.floor("T")

    events_per_min = logs.groupby("minute").size()

    st.line_chart(events_per_min)

# =========================================================
# 🚨 ALERTS BY SEVERITY
# =========================================================
st.subheader("🚨 Alerts by Severity")

if not alerts.empty:
    severity_counts = alerts["severity"].value_counts()
    st.bar_chart(severity_counts)

# =========================================================
# 🖥 TOP HOSTS GENERATING LOGS
# =========================================================
st.subheader("🖥 Top Log Sources")

if not logs.empty:
    top_hosts = logs["hostname"].value_counts().head(5)
    st.bar_chart(top_hosts)

# =========================================================
# 🔥 ALERT TREND (ATTACK CONTINUITY)
# =========================================================
st.subheader("🔥 Alert Trend Over Time")

if not alerts.empty:
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])
    alerts["minute"] = alerts["timestamp"].dt.floor("T")

    alert_trend = alerts.groupby("minute").size()
    st.line_chart(alert_trend)

# =========================================================
# 📄 LIVE LOG STREAM
# =========================================================
st.subheader("📄 Live Logs")

st.dataframe(
    logs.head(50),
    use_container_width=True,
    height=300
)

# =========================================================
# 🚨 LIVE ALERT TABLE
# =========================================================
st.subheader("🚨 Active Alerts")

st.dataframe(
    alerts.head(50),
    use_container_width=True,
    height=300
)

