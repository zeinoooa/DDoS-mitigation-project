from __future__ import annotations

import os
import time
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from alerts import Alert, dispatch_alert, format_alert_message
from detection import build_baseline, detect_window, save_baseline, summarize_window
from mitigation import MitigationPolicy, generate_mitigation_plan
from traffic import (
    available_pcap_files,
    aggregate_windows,
    load_pcap_dataset,
    normalize_uploaded_dataset,
    parse_pcap_file,
)


BASE_DIR = Path(__file__).resolve().parent.parent
PCAP_DIR = BASE_DIR / "data" / "pcap"
BASELINE_PATH = BASE_DIR / "data" / "baseline_metrics.json"
COOLDOWN_SECONDS = 90


st.set_page_config(
    page_title="DDoS Mitigation Console",
    page_icon="shield",
    layout="wide",
    initial_sidebar_state="expanded",
)


@st.cache_data(show_spinner=False)
def load_pcaps(paths: tuple[str, ...], packet_limit_per_file: int) -> pd.DataFrame:
    return load_pcap_dataset([Path(p) for p in paths], packet_limit_per_file=packet_limit_per_file)


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


def render_sidebar():
    st.sidebar.header("Data Source")
    source_type = st.sidebar.radio("Input type", ["Bundled PCAP files", "Upload PCAP", "Upload CSV"], index=0)

    if source_type == "Bundled PCAP files":
        pcap_files = available_pcap_files(PCAP_DIR)
        if not pcap_files:
            st.sidebar.error("No PCAP files found in data/pcap.")
            return pd.DataFrame(), 10, 0.45, MitigationPolicy()
        labels = [p.name for p in pcap_files]
        default_names = [n for n in labels if n in {"normal.pcap", "normal2.pcap", "mirai.pcap"}]
        selected_names = st.sidebar.multiselect("PCAP files", labels, default=default_names or labels[:2])
        selected_paths = tuple(str(p) for p in pcap_files if p.name in selected_names)
        packet_limit = st.sidebar.number_input("Packet limit per PCAP", 1_000, 500_000, 120_000, 5_000)
        df = load_pcaps(selected_paths, int(packet_limit))
        st.sidebar.caption("Using raw PCAP packets from data/pcap.")
    elif source_type == "Upload PCAP":
        uploaded = st.sidebar.file_uploader("Upload PCAP", type=["pcap", "cap"])
        if uploaded is None:
            st.sidebar.info("Upload a PCAP file to start.")
            return pd.DataFrame(), 10, 0.45, MitigationPolicy()
        df = load_uploaded_pcap(uploaded.name, uploaded.getvalue())
        st.sidebar.caption("Using uploaded raw PCAP.")
    else:
        uploaded = st.sidebar.file_uploader("Upload CSV", type=["csv"])
        if uploaded is None:
            st.sidebar.info("Upload a CSV file to start.")
            return pd.DataFrame(), 10, 0.45, MitigationPolicy()
        df = normalize_uploaded_dataset(pd.read_csv(uploaded))
        st.sidebar.caption("Using uploaded CSV.")

    st.sidebar.header("Detection Settings")
    window_seconds = st.sidebar.select_slider("Rolling window (s)", options=[5, 10, 15, 30], value=10)
    alert_threshold = st.sidebar.slider("Alert threshold", 0.20, 1.00, 0.45, 0.05)

    st.sidebar.header("Safeguards")
    whitelist_text = st.sidebar.text_area(
        "Whitelisted IPs (never blocked)",
        value="10.0.0.1\n10.0.0.2\n127.0.0.1",
        help="One IP per line.",
    )
    whitelist = tuple(ip.strip() for ip in whitelist_text.splitlines() if ip.strip())

    blacklist_text = st.sidebar.text_area(
        "Blacklisted IPs (always dropped)",
        value="",
        help="One IP per line. Always blocked regardless of score.",
    )
    blacklist = tuple(ip.strip() for ip in blacklist_text.splitlines() if ip.strip())

    policy = MitigationPolicy(
        whitelist=whitelist,
        blacklist=blacklist,
        soft_packet_limit=st.sidebar.number_input("Soft rate limit (pkt/s)", 50, 5000, 600, 50),
        hard_packet_limit=st.sidebar.number_input("Hard rate limit (pkt/s)", 50, 10000, 1200, 50),
        max_blocked_sources=st.sidebar.slider("Max blocked sources", 1, 20, 5),
    )
    return df, window_seconds, alert_threshold, policy


def render_score_timeline(all_results, alert_threshold, time_range):
    st.subheader("Anomaly Score Over Time")
    score_df = pd.DataFrame(all_results)
    score_df = score_df[
        (score_df["window_idx"] >= time_range[0]) &
        (score_df["window_idx"] <= time_range[1])
    ]
    if score_df.empty:
        st.info("No windows in selected range.")
        return

    fig = go.Figure()
    for _, row in score_df[score_df["is_attack"]].iterrows():
        fig.add_vrect(x0=row["window_start"], x1=row["window_end"],
                      fillcolor="red", opacity=0.10, line_width=0)

    fig.add_trace(go.Scatter(
        x=score_df["window_start"],
        y=score_df["score"],
        mode="lines+markers",
        name="Anomaly score",
        line=dict(color="#e74c3c", width=2),
        marker=dict(
            color=["#e74c3c" if v else "#2ecc71" for v in score_df["is_attack"]],
            size=6,
        ),
        hovertemplate="<b>%{x}</b><br>Score: %{y:.3f}<br>Attack: %{customdata}<extra></extra>",
        customdata=score_df["attack_type"],
    ))
    fig.add_hline(y=alert_threshold, line_dash="dash", line_color="orange",
                  annotation_text=f"Threshold ({alert_threshold:.2f})",
                  annotation_position="top right")
    fig.update_layout(
        xaxis_title="Time", yaxis_title="Anomaly score",
        yaxis=dict(range=[0, 1.05]), height=300,
        margin=dict(t=20, b=20),
    )
    st.plotly_chart(fig, use_container_width=True)


def render_notification_panel(alert, alert_threshold):
    st.subheader("Notifications")

    if "last_alert_time" not in st.session_state:
        st.session_state.last_alert_time = 0.0
    if "attack_was_active" not in st.session_state:
        st.session_state.attack_was_active = False
    if "alert_history" not in st.session_state:
        st.session_state.alert_history = []

    provider = st.selectbox("Channel", ["Console preview", "Email (SMTP)", "Slack webhook"], index=0)
    recipient = st.text_input("Recipient address / webhook label", value="")

    now = time.time()
    cooldown_remaining = max(0.0, COOLDOWN_SECONDS - (now - st.session_state.last_alert_time))
    send_clicked = st.button("Send alert", type="primary", disabled=alert is None)

    if alert is None:
        st.info("No active attack in the selected window.")
        if st.session_state.attack_was_active:
            if st.session_state.alert_history:
                st.success(
                    f"Attack ended. Summary: {len(st.session_state.alert_history)} alert(s) sent this session."
                )
            st.session_state.attack_was_active = False
        return

    st.session_state.attack_was_active = True
    st.code(format_alert_message(alert), language="text")

    if cooldown_remaining > 0:
        st.caption(
            f"Cool-down active — subsequent identical alerts suppressed. "
            f"Next allowed in {cooldown_remaining:.0f}s (configurable, currently {COOLDOWN_SECONDS}s)."
        )

    if send_clicked:
        status = dispatch_alert(alert, provider=provider, recipient=recipient)
        st.session_state.last_alert_time = now
        st.session_state.alert_history.append({
            "time": pd.Timestamp.now().strftime("%H:%M:%S"),
            "attack_type": alert.attack_type,
            "score": f"{alert.anomaly_score:.2f}",
            "channel": provider,
            "status": "sent" if status.ok else "failed",
        })
        if status.ok:
            st.success(status.message)
        else:
            st.warning(status.message)

    if st.session_state.alert_history:
        with st.expander("Alert history (this session)"):
            st.dataframe(
                pd.DataFrame(st.session_state.alert_history),
                use_container_width=True, hide_index=True,
            )


# ── Main app ─────────────────────────────────────────────────────────────────

result_sidebar = render_sidebar()
df, window_seconds, alert_threshold, policy = result_sidebar

st.title("DDoS Mitigation Console")
st.caption("Baseline modeling · Rolling traffic analysis · Anomaly scoring · Mitigation planning · Alerting")

if df.empty:
    st.error("No traffic data loaded. Select PCAP files or upload a dataset from the sidebar.")
    st.stop()

windows = prepare_windows(df, window_seconds)
baseline = build_baseline(windows)
save_baseline(baseline, BASELINE_PATH)

if windows.empty:
    st.error("No traffic windows available.")
    st.stop()

# Pre-compute scores for ALL windows (needed for score timeline + drill-down)
all_results = []
for idx, row in windows.iterrows():
    r = detect_window(row, baseline, alert_threshold=alert_threshold)
    all_results.append({
        "window_idx": int(idx),
        "window_start": row["window_start"],
        "window_end": row["window_end"],
        "score": r.score,
        "is_attack": r.is_attack,
        "attack_type": r.attack_type,
    })

# ── Range slider: both ends draggable (D.2) ───────────────────────────────────
n = len(windows)
st.markdown("### Time Navigation")
time_range = st.slider(
    "Select time range (drag both ends independently)",
    min_value=0,
    max_value=n - 1,
    value=(0, n - 1),
    help="Filter charts to a specific time range. Min = first packet, max = last packet.",
)
start_idx, end_idx = time_range

selected_index = st.slider(
    "Inspect specific window",
    min_value=start_idx,
    max_value=end_idx,
    value=min((start_idx + end_idx) // 2, end_idx),
    format="window %d",
)

current = windows.iloc[selected_index]
result = detect_window(current, baseline, alert_threshold=alert_threshold)
summary = summarize_window(current)
plan = generate_mitigation_plan(current, result, policy)

# ── Status bar ────────────────────────────────────────────────────────────────
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Status", "ATTACK" if result.is_attack else "Normal")
c2.metric("Anomaly score", f"{result.score:.2f}", delta=f"threshold {alert_threshold:.2f}")
c3.metric("Packets/sec", f"{summary.packets_per_second:,.0f}")
c4.metric("Unique sources", f"{summary.unique_sources:,.0f}")
c5.metric("Top source share", f"{summary.top_source_ratio:.0%}")
c6.metric("Window time", str(current["window_start"]).split(".")[0])

if result.is_attack:
    st.error(f"ATTACK: {result.attack_type} detected in window {selected_index} "
             f"({str(current['window_start']).split('.')[0]})")
else:
    st.success("Selected window is within the learned baseline.")

if policy.blacklist:
    st.warning(f"Blacklisted IPs (always dropped): {', '.join(policy.blacklist)}")

# ── Anomaly score timeline (D.3) ──────────────────────────────────────────────
render_score_timeline(all_results, alert_threshold, (start_idx, end_idx))

st.divider()

# ── Charts row 1 ──────────────────────────────────────────────────────────────
filtered_windows = windows.iloc[start_idx:end_idx + 1].copy()
col1, col2 = st.columns(2)

with col1:
    st.subheader("Traffic Trend")
    fig = px.line(
        filtered_windows, x="window_start",
        y=["packets_per_second", "requests_per_second", "syn_ratio"],
        labels={"value": "metric", "window_start": "time", "variable": "metric"},
    )
    fig.add_vrect(x0=current["window_start"], x1=current["window_end"],
                  fillcolor="red" if result.is_attack else "green", opacity=0.18, line_width=0)
    fig.update_layout(height=280, margin=dict(t=20, b=20))
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("Bandwidth (Mbps) Over Time")
    fig2 = px.area(
        filtered_windows, x="window_start", y="mbps",
        labels={"mbps": "Mbps", "window_start": "time"},
        color_discrete_sequence=["#3498db"],
    )
    fig2.add_vrect(x0=current["window_start"], x1=current["window_end"],
                   fillcolor="red" if result.is_attack else "green", opacity=0.18, line_width=0)
    fig2.update_layout(height=280, margin=dict(t=20, b=20))
    st.plotly_chart(fig2, use_container_width=True)

# ── Charts row 2 ──────────────────────────────────────────────────────────────
col3, col4 = st.columns(2)

with col3:
    st.subheader("Protocol Distribution (Selected Window)")
    proto_data = pd.DataFrame({
        "protocol": ["TCP", "UDP", "ICMP"],
        "packets": [current["tcp_packets"], current["udp_packets"], current["icmp_packets"]],
    })
    fig3 = px.pie(proto_data, names="protocol", values="packets", hole=0.4,
                  color_discrete_sequence=["#2ecc71", "#e74c3c", "#f39c12"])
    fig3.update_layout(height=280, margin=dict(t=20, b=20))
    st.plotly_chart(fig3, use_container_width=True)

with col4:
    st.subheader("Unique Source IPs Over Time")
    fig4 = px.line(
        filtered_windows, x="window_start", y="unique_sources",
        labels={"unique_sources": "unique IPs", "window_start": "time"},
        color_discrete_sequence=["#9b59b6"],
    )
    fig4.add_vrect(x0=current["window_start"], x1=current["window_end"],
                   fillcolor="red" if result.is_attack else "green", opacity=0.18, line_width=0)
    fig4.update_layout(height=280, margin=dict(t=20, b=20))
    st.plotly_chart(fig4, use_container_width=True)

st.divider()

# ── Detection indicators + Mitigation ─────────────────────────────────────────
det_col, mit_col = st.columns([1, 1])

with det_col:
    st.subheader("Detection Indicators")
    indicators_df = pd.DataFrame([
        {
            "indicator": item.name,
            "observed": round(item.value, 4),
            "baseline (p95)": round(item.baseline, 4),
            "deviation score": round(item.score, 4),
            "status": "TRIGGERED" if item.score > 0 else "OK",
        }
        for item in result.indicators
    ])
    st.dataframe(indicators_df, use_container_width=True, hide_index=True)

    # ── Alert drill-down (D.5) ────────────────────────────────────────────────
    attack_windows_in_range = [
        r for r in all_results
        if r["is_attack"] and start_idx <= r["window_idx"] <= end_idx
    ]
    if attack_windows_in_range:
        st.subheader("Alert Drill-Down")
        alert_options = {
            f"Window {r['window_idx']} | {str(r['window_start']).split('.')[0]} | score {r['score']:.2f}": r
            for r in attack_windows_in_range
        }
        chosen_label = st.selectbox("Click an alert to inspect details", list(alert_options.keys()))
        chosen = alert_options[chosen_label]
        chosen_window = windows.iloc[chosen["window_idx"]]
        chosen_result = detect_window(chosen_window, baseline, alert_threshold=alert_threshold)
        chosen_plan = generate_mitigation_plan(chosen_window, chosen_result, policy)

        with st.container(border=True):
            st.markdown(f"**Attack type:** {chosen_result.attack_type}")
            st.markdown(
                f"**Time:** {str(chosen_window['window_start']).split('.')[0]} — "
                f"{str(chosen_window['window_end']).split('.')[0]}"
            )
            st.markdown(
                f"**Anomaly score:** `{chosen_result.score:.3f}` "
                f"(threshold `{alert_threshold:.2f}`, excess `+{chosen_result.score - alert_threshold:.3f}`)"
            )
            triggered = [i for i in chosen_result.indicators if i.score > 0]
            if triggered:
                st.markdown("**Triggered indicators:**")
                for ind in triggered:
                    st.markdown(
                        f"- **{ind.name}**: observed `{ind.value:.4f}` "
                        f"vs baseline p95 `{ind.baseline:.4f}` → score `{ind.score:.3f}`"
                    )
            if chosen_plan.blocked_sources:
                st.markdown(f"**Contributing source IPs:** `{'`, `'.join(chosen_plan.blocked_sources)}`")
            st.markdown(f"**Mitigation triggered:** {chosen_plan.restriction_level}")

with mit_col:
    st.subheader("Mitigation Plan")
    if plan.actions:
        st.markdown(f"**Restriction level:** `{plan.restriction_level}`")
        for action in plan.actions:
            with st.container(border=True):
                st.markdown(f"**{action.title}**")
                st.caption(action.reason)
                st.code(action.command, language="bash")
    else:
        st.info("No mitigation required for this window.")

    # ── Safeguards panel with whitelist + blacklist (C.3, C.4, D.4) ───────────
    st.subheader("Safeguards")
    wl_col, bl_col = st.columns(2)
    with wl_col:
        st.markdown("**Whitelist** (never blocked)")
        for ip in policy.whitelist:
            st.markdown(f"- `{ip}`")
    with bl_col:
        st.markdown("**Blacklist** (always dropped)")
        if policy.blacklist:
            for ip in policy.blacklist:
                st.markdown(f"- `{ip}`")
            st.markdown("**Blacklist DROP rules:**")
            for ip in policy.blacklist:
                st.code(f"sudo iptables -A INPUT -s {ip} -j DROP", language="bash")
        else:
            st.caption("No IPs blacklisted. Add in sidebar.")

st.divider()

# ── Source concentration ───────────────────────────────────────────────────────
st.subheader("Source Concentration (Selected Window)")
source_rows = current["top_sources"]
if isinstance(source_rows, list) and source_rows:
    src_df = pd.DataFrame(source_rows)
    src_df["blacklisted"] = src_df["src_ip"].isin(policy.blacklist)
    src_df["whitelisted"] = src_df["src_ip"].isin(policy.whitelist)
    st.dataframe(src_df, use_container_width=True, hide_index=True)
else:
    st.info("No source distribution available for this window.")

st.divider()

# ── Notifications ──────────────────────────────────────────────────────────────
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

render_notification_panel(active_alert, alert_threshold)

# ── Baseline + Docker expanders ────────────────────────────────────────────────
with st.expander("Baseline Model (learned from normal traffic)"):
    st.json(baseline.to_dict())

with st.expander("Docker run command"):
    image_name = os.getenv("IMAGE_NAME", "ddos-mitigation")
    st.code(
        f"docker build -t {image_name} .\n"
        f"docker run --rm -p 8501:8501 --cap-add=NET_ADMIN {image_name}",
        language="bash",
    )