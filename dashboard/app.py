"""
dashboard/app.py
================
CodeAlpha Cybersecurity Internship - Task 4
Network Intrusion Detection System (NIDS) - Module 4: Security Dashboard
Read-only Streamlit dashboard that visualises alerts produced by main.py.
Launch from the PROJECT ROOT (not from this folder):
    streamlit run dashboard/app.py
    # or
    python -m streamlit run dashboard/app.py
Reads:
    logs/alerts.json
Writes:
    nothing (read-only by design)
"""
from __future__ import annotations
import json
from datetime import datetime
from pathlib import Path
import matplotlib
matplotlib.use("Agg")            # headless - no GUI thread needed
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
# ---------------------------------------------------------------------- #
# Paths
# ---------------------------------------------------------------------- #
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALERTS_JSON = PROJECT_ROOT / "logs" / "alerts.json"
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_COLORS = {
    "LOW":      "#4e9f3d",
    "MEDIUM":   "#f9a825",
    "HIGH":     "#e53935",
    "CRITICAL": "#8e0000",
}
ATTACK_COLORS = {
    "PORT_SCAN":            "#e53935",
    "REPEATED_CONNECTIONS": "#fb8c00",
    "POSSIBLE_DOS":         "#8e0000",
    "SUSPICIOUS_PORT":      "#1e88e5",
    "NULL_SCAN":            "#6d4c41",
}
DEFAULT_COLOR = "#757575"
# ---------------------------------------------------------------------- #
# Data loading
# ---------------------------------------------------------------------- #
@st.cache_data(ttl=5)                  # cache 5 seconds; manual refresh forces reload
def load_alerts() -> pd.DataFrame:
    if not ALERTS_JSON.exists():
        return pd.DataFrame()
    try:
        with ALERTS_JSON.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return pd.DataFrame()
    if not raw:
        return pd.DataFrame()
    df = pd.DataFrame(raw)
    # Normalise optional columns
    for col in ("src_port", "dst_port", "tcp_flags", "length"):
        if col not in df.columns:
            df[col] = None
    if "severity" not in df.columns:
        df["severity"] = "UNKNOWN"
    if "attack_type" not in df.columns:
        df["attack_type"] = "UNKNOWN"
    # Parse timestamp for time-series
    df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce")
    # Drop the nested dict for table display; keep as string
    if "details" in df.columns:
        df["details"] = df["details"].apply(
            lambda d: json.dumps(d, ensure_ascii=False) if isinstance(d, dict) else str(d)
        )
    return df
# ---------------------------------------------------------------------- #
# Chart helpers
# ---------------------------------------------------------------------- #
def pie_attack_types(df: pd.DataFrame):
    counts = df["attack_type"].value_counts()
    fig, ax = plt.subplots(figsize=(4.5, 4.5))
    colors = [ATTACK_COLORS.get(a, DEFAULT_COLOR) for a in counts.index]
    ax.pie(counts.values, labels=counts.index, autopct="%1.0f%%",
           colors=colors, startangle=90,
           wedgeprops={"edgecolor": "white", "linewidth": 1})
    ax.set_title("Attack types", fontsize=12)
    return fig
def bar_severity(df: pd.DataFrame):
    counts = df["severity"].value_counts().reindex(SEVERITY_ORDER, fill_value=0)
    fig, ax = plt.subplots(figsize=(5, 4.5))
    bars = ax.bar(counts.index, counts.values,
                  color=[SEVERITY_COLORS[s] for s in counts.index])
    ax.set_title("Alerts by severity", fontsize=12)
    ax.set_ylabel("Count")
    for bar, val in zip(bars, counts.values):
        if val:
            ax.text(bar.get_x() + bar.get_width() / 2, val, str(val),
                    ha="center", va="bottom", fontsize=10)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    return fig
def bar_top_sources(df: pd.DataFrame, top_n: int = 10):
    counts = df["src_ip"].value_counts().head(top_n)
    fig, ax = plt.subplots(figsize=(6, max(3, 0.35 * len(counts) + 1)))
    counts[::-1].plot(kind="barh", ax=ax, color="#1e88e5")
    ax.set_title(f"Top {len(counts)} source IPs", fontsize=12)
    ax.set_xlabel("Alerts")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    return fig
def line_timeline(df: pd.DataFrame):
    d = df.dropna(subset=["ts"]).copy()
    if d.empty:
        return None
    d["minute"] = d["ts"].dt.floor("min")
    counts = d.groupby("minute").size().sort_index()
    fig, ax = plt.subplots(figsize=(8, 3.2))
    ax.plot(counts.index, counts.values, marker="o",
            color="#e53935", linewidth=1.5, markersize=4)
    ax.fill_between(counts.index, counts.values, alpha=0.15, color="#e53935")
    ax.set_title("Alerts over time", fontsize=12)
    ax.set_ylabel("Alerts / minute")
    ax.tick_params(axis="x", rotation=30)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    return fig
# ---------------------------------------------------------------------- #
# Main page
# ---------------------------------------------------------------------- #
st.set_page_config(
    page_title="CodeAlpha NIDS Dashboard",
    page_icon="🛡️",
    layout="wide",
)
st.title("🛡️ Network Intrusion Detection System")
st.caption("CodeAlpha Cybersecurity Internship · Task 4 · live alert dashboard")
# --- sidebar controls ---
with st.sidebar:
    st.header("Controls")
    if st.button("🔄 Refresh now", use_container_width=True):
        st.cache_data.clear()
        st.rerun()
    auto_refresh = st.checkbox("Auto-refresh (every 5 s)", value=False)
    st.divider()
    st.header("Filters")
    df_all = load_alerts()
    if df_all.empty:
        st.info("No alerts yet. Run `python main.py` to start detecting.")
        st.stop()
    sev_options = ["ALL"] + sorted(df_all["severity"].unique().tolist())
    sel_sev = st.selectbox("Severity", sev_options, index=0)
    atk_options = ["ALL"] + sorted(df_all["attack_type"].unique().tolist())
    sel_atk = st.selectbox("Attack type", atk_options, index=0)
    src_options = ["ALL"] + sorted(df_all["src_ip"].dropna().unique().tolist())
    sel_src = st.selectbox("Source IP", src_options, index=0)
    st.divider()
    st.caption(f"Log file: `{ALERTS_JSON.relative_to(PROJECT_ROOT)}`")
    if ALERTS_JSON.exists():
        st.caption(f"Size: {ALERTS_JSON.stat().st_size} bytes")
# --- apply filters ---
df = df_all.copy()
if sel_sev != "ALL":
    df = df[df["severity"] == sel_sev]
if sel_atk != "ALL":
    df = df[df["attack_type"] == sel_atk]
if sel_src != "ALL":
    df = df[df["src_ip"] == sel_src]
if df.empty:
    st.warning("No alerts match the current filters.")
    st.stop()
# --- KPI row ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total alerts", len(df))
col2.metric("Unique sources", df["src_ip"].nunique())
col3.metric("Attack types", df["attack_type"].nunique())
high_crit = int(df["severity"].isin(["HIGH", "CRITICAL"]).sum())
col4.metric("High / Critical", high_crit)
st.divider()
# --- charts row 1 ---
c1, c2 = st.columns(2)
with c1:
    st.pyplot(pie_attack_types(df), use_container_width=True)
with c2:
    st.pyplot(bar_severity(df), use_container_width=True)
# --- charts row 2 ---
c3, c4 = st.columns([1, 1.4])
with c3:
    st.pyplot(bar_top_sources(df), use_container_width=True)
with c4:
    timeline = line_timeline(df)
    if timeline is not None:
        st.pyplot(timeline, use_container_width=True)
    else:
        st.info("Not enough timestamped alerts for a timeline yet.")
# --- alert table ---
st.subheader("Alert detail")
display_cols = [
    "timestamp", "severity", "attack_type",
    "src_ip", "src_port", "dst_ip", "dst_port",
    "protocol", "details",
]
display_cols = [c for c in display_cols if c in df.columns]
st.dataframe(
    df[display_cols].sort_values("timestamp", ascending=False),
    use_container_width=True,
    height=350,
)
# --- download button ---
st.download_button(
    label="⬇️ Download filtered alerts as CSV",
    data=df.drop(columns=["ts"], errors="ignore").to_csv(index=False),
    file_name=f"nids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
    mime="text/csv",
)
# --- footer ---
st.caption(
    "Detection rules: PORT_SCAN · REPEATED_CONNECTIONS · POSSIBLE_DOS · "
    "SUSPICIOUS_PORT · NULL_SCAN. Thresholds editable in "
    "`rules/detection_rules.json`."
)
# --- auto-refresh ---
if auto_refresh:
    import time
    time.sleep(5)
    st.cache_data.clear()
    st.rerun()