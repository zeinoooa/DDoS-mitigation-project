from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from alerts import Alert, dispatch_alert, format_alert_message
from detection import build_baseline, detect_window, save_baseline, summarize_window
from mitigation import MitigationPolicy, generate_mitigation_plan
from traffic import available_pcap_files, aggregate_windows, load_pcap_dataset, normalize_uploaded_dataset, parse_pcap_file


BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_DIR = BASE_DIR / "data" / "pcap"
BASELINE_PATH = BASE_DIR / "data" / "baseline_metrics.json"


st.set_page_config(
    page_title="DDoS Mitigation Console",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_data(show_spinner=False)
def load_pcaps(paths: tuple[str, ...], packet_limit_per_file: int) -> pd.DataFrame:
    return load_pcap_dataset([Path(path) for path in paths], packet_limit_per_file=packet_limit_per_file)


@st.cache_data(show_spinner=False)
def load_uploaded_pcap(name: str, content: bytes) -> pd.DataFrame:
    temp_path = BASE_DIR / "data" / "_uploaded_tmp.pcap"
    temp_path.write_bytes(content)
    try:
        return parse_pcap_file(temp_path)
    finally:
        temp_path.unlink(missing_ok=True)


@st.cache_data(show_spinner=False)
def prepare_windows(df: pd.DataFrame, window_seconds: int) -> pd.DataFrame:
    return aggregate_windows(df, window_seconds=window_seconds)


def metric_card(label: str, value: str, delta: str | None = None) -> None:
    st.metric(label, value, delta=delta)


def render_sidebar() -> tuple[pd.DataFrame, int, float, MitigationPolicy]:
    st.sidebar.header("Data Source")
    source_type = st.sidebar.radio("Input type", ["Bundled PCAP files", "Upload PCAP", "Upload CSV"], index=0)
    if source_type == "Bundled PCAP files":
        pcap_files = available_pcap_files(PCAP_DIR)
        if not pcap_files:
            st.sidebar.error("No PCAP files found in data/pcap.")
            return pd.DataFrame(), 10, 0.55, MitigationPolicy()
        labels = [path.name for path in pcap_files]
        default_names = [name for name in labels if name in {"normal.pcap", "normal2.pcap", "mirai.pcap"}]
        selected_names = st.sidebar.multiselect("PCAP files", labels, default=default_names or labels[:2])
        selected_paths = tuple(str(path) for path in pcap_files if path.name in selected_names)
        packet_limit = st.sidebar.number_input("Packet limit per PCAP", 1_000, 500_000, 120_000, 5_000)
        df = load_pcaps(selected_paths, int(packet_limit))
        st.sidebar.caption("Using raw PCAP packets from data/pcap.")
    elif source_type == "Upload PCAP":
        uploaded = st.sidebar.file_uploader("Upload PCAP", type=["pcap", "cap"])
        if uploaded is None:
            st.sidebar.info("Upload a PCAP file to start.")
            return pd.DataFrame(), 10, 0.55, MitigationPolicy()
        df = load_uploaded_pcap(uploaded.name, uploaded.getvalue())
        st.sidebar.caption("Using uploaded raw PCAP packets.")
    else:
        uploaded = st.sidebar.file_uploader("Upload CIC-style or normalized CSV", type=["csv"])
        if uploaded is None:
            st.sidebar.info("Upload a CSV file to start.")
            return pd.DataFrame(), 10, 0.55, MitigationPolicy()
        df = normalize_uploaded_dataset(pd.read_csv(uploaded))
        st.sidebar.caption("Using uploaded traffic CSV.")

    st.sidebar.header("Detection Settings")
    window_seconds = st.sidebar.select_slider("Rolling window", options=[5, 10, 15, 30], value=10)
    alert_threshold = st.sidebar.slider("Alert threshold", 0.20, 1.00, 0.45, 0.05)

    st.sidebar.header("Safeguards")
    whitelist_text = st.sidebar.text_area(
        "Whitelisted IPs",
        value="10.0.0.1\n10.0.0.2\n127.0.0.1",
        help="One IP per line. These sources are never blocked.",
    )
    whitelist = tuple(ip.strip() for ip in whitelist_text.splitlines() if ip.strip())
    policy = MitigationPolicy(
        whitelist=whitelist,
        soft_packet_limit=st.sidebar.number_input("Soft rate limit packets/sec", 50, 5000, 600, 50),
        hard_packet_limit=st.sidebar.number_input("Hard rate limit packets/sec", 50, 10000, 1200, 50),
        max_blocked_sources=st.sidebar.slider("Max blocked sources", 1, 20, 5),
    )
    return df, window_seconds, alert_threshold, policy


def render_notification_panel(alert: Alert | None) -> None:
    st.subheader("Notifications")
    provider = st.selectbox("Channel", ["Console preview", "Email (SMTP)", "Slack webhook"], index=0)
    recipient = st.text_input("Recipient / webhook label", value="TA demo")
    send_clicked = st.button("Send alert", type="primary", disabled=alert is None)

    if alert is None:
        st.info("No active high-confidence attack in the selected window.")
        return

    st.code(format_alert_message(alert), language="text")
    if send_clicked:
        status = dispatch_alert(alert, provider=provider, recipient=recipient)
        if status.ok:
            st.success(status.message)
        else:
            st.warning(status.message)


df, window_seconds, alert_threshold, policy = render_sidebar()
st.title("DDoS Mitigation Console")
st.caption("Baseline modeling, rolling traffic analysis, anomaly scoring, mitigation planning, and alerting.")

if df.empty:
    st.error("No traffic data is loaded. Select PCAP files or upload a dataset from the sidebar.")
    st.stop()

windows = prepare_windows(df, window_seconds)
baseline = build_baseline(windows)
save_baseline(baseline, BASELINE_PATH)

if windows.empty:
    st.error("No traffic windows are available. Select a PCAP with IPv4 packets or upload a supported dataset.")
    st.stop()

selected_index = st.slider(
    "Time navigation",
    min_value=0,
    max_value=len(windows) - 1,
    value=min(len(windows) // 2, len(windows) - 1),
    format="window %d",
)

current = windows.iloc[selected_index]
result = detect_window(current, baseline, alert_threshold=alert_threshold)
summary = summarize_window(current)
plan = generate_mitigation_plan(current, result, policy)

status_col, score_col, packets_col, sources_col, top_col = st.columns(5)
status_col.metric("Status", "ATTACK" if result.is_attack else "Normal")
score_col.metric("Anomaly score", f"{result.score:.2f}", delta=f"threshold {alert_threshold:.2f}")
packets_col.metric("Packets/sec", f"{summary.packets_per_second:,.0f}")
sources_col.metric("Unique sources", f"{summary.unique_sources:,.0f}")
top_col.metric("Top source share", f"{summary.top_source_ratio:.0%}")

if result.is_attack:
    st.error(f"{result.attack_type} detected in selected window.")
else:
    st.success("Selected window is within the learned baseline.")

left, right = st.columns([1.35, 1])

with left:
    st.subheader("Traffic Trend")
    trend = windows.copy()
    trend["selected"] = trend.index == selected_index
    fig = px.line(
        trend,
        x="window_start",
        y=["packets_per_second", "requests_per_second", "syn_ratio"],
        labels={"value": "metric value", "window_start": "time", "variable": "metric"},
    )
    fig.add_vrect(
        x0=current["window_start"],
        x1=current["window_end"],
        fillcolor="red" if result.is_attack else "green",
        opacity=0.18,
        line_width=0,
    )
    st.plotly_chart(fig, use_container_width=True)

    st.subheader("Protocol Distribution")
    proto_data = pd.DataFrame(
        {
            "protocol": ["TCP", "UDP", "ICMP"],
            "packets": [current["tcp_packets"], current["udp_packets"], current["icmp_packets"]],
        }
    )
    st.plotly_chart(px.bar(proto_data, x="protocol", y="packets", color="protocol"), use_container_width=True)

with right:
    st.subheader("Detection Indicators")
    indicators = pd.DataFrame(
        [
            {"indicator": item.name, "value": item.value, "baseline": item.baseline, "score": item.score}
            for item in result.indicators
        ]
    )
    st.dataframe(indicators, use_container_width=True, hide_index=True)

    st.subheader("Mitigation Plan")
    if plan.actions:
        for action in plan.actions:
            st.markdown(f"**{action.title}**")
            st.caption(action.reason)
            st.code(action.command, language="bash")
    else:
        st.info("No mitigation required for this window.")

    st.subheader("Safeguards")
    st.write(
        {
            "whitelist": list(policy.whitelist),
            "restriction_level": plan.restriction_level,
            "blocked_sources": plan.blocked_sources,
        }
    )

st.subheader("Source Concentration")
source_rows = current["top_sources"]
if isinstance(source_rows, list) and source_rows:
    st.dataframe(pd.DataFrame(source_rows), use_container_width=True, hide_index=True)
else:
    st.info("No source distribution available for this window.")

active_alert = None
if result.is_attack:
    active_alert = Alert(
        attack_type=result.attack_type,
        anomaly_score=result.score,
        window_start=str(current["window_start"]),
        affected_service=f"{current['dst_ip']}:{int(current['top_dst_port'])}",
        indicators=[item.name for item in result.indicators if item.score > 0.35],
        source_ips=plan.blocked_sources,
        mitigation_status=plan.restriction_level,
        commands=[action.command for action in plan.actions],
    )

render_notification_panel(active_alert)

with st.expander("Baseline Model"):
    st.json(baseline.to_dict())

with st.expander("Docker run command"):
    image_name = os.getenv("IMAGE_NAME", "ddos-mitigation")
    st.code(
        f"docker build -t {image_name} .\n"
        f"docker run --rm -p 8501:8501 --cap-add=NET_ADMIN {image_name}",
        language="bash",
    )
