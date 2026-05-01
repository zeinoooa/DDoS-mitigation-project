from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


NORMALIZED_COLUMNS = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "dst_port",
    "packets",
    "bytes",
    "flow_duration_ms",
    "syn_packets",
    "requests",
    "label",
}


def load_or_create_demo_dataset(path: Path) -> pd.DataFrame:
    if path.exists():
        return normalize_uploaded_dataset(pd.read_csv(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    df = generate_demo_traffic()
    df.to_csv(path, index=False)
    return df


def generate_demo_traffic(seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows: list[dict[str, object]] = []
    start = pd.Timestamp("2026-05-02 09:00:00")
    customer_ips = [f"172.16.{i // 255}.{i % 255}" for i in range(1, 520)]
    bot_ips = [f"198.51.100.{i}" for i in range(1, 80)] + [f"203.0.113.{i}" for i in range(1, 80)]

    for second in range(0, 1080):
        timestamp = start + pd.Timedelta(seconds=second)
        attack = _attack_for_second(second)
        if attack == "BENIGN":
            flows = int(rng.poisson(18))
        elif attack == "SYN_FLOOD":
            flows = int(rng.poisson(95))
        elif attack == "HTTP_FLOOD":
            flows = int(rng.poisson(80))
        else:
            flows = int(rng.poisson(110))

        for _ in range(max(flows, 1)):
            row = _make_flow(rng, timestamp, attack, customer_ips, bot_ips)
            rows.append(row)
    return pd.DataFrame(rows)


def _attack_for_second(second: int) -> str:
    if 360 <= second < 480:
        return "SYN_FLOOD"
    if 650 <= second < 760:
        return "HTTP_FLOOD"
    if 900 <= second < 970:
        return "UDP_FLOOD"
    return "BENIGN"


def _make_flow(rng, timestamp, attack: str, customer_ips: list[str], bot_ips: list[str]) -> dict[str, object]:
    dst_ip = "10.0.0.10"
    if attack == "BENIGN":
        src_ip = rng.choice(customer_ips)
        protocol = rng.choice(["TCP", "UDP", "ICMP"], p=[0.82, 0.14, 0.04])
        dst_port = int(rng.choice([80, 443, 22, 53, 8080], p=[0.32, 0.46, 0.05, 0.10, 0.07]))
        packets = int(max(1, rng.poisson(8)))
        byte_count = int(packets * rng.integers(500, 1300))
        syn_packets = int(rng.binomial(packets, 0.08 if protocol == "TCP" else 0.0))
        requests = int(rng.poisson(2 if dst_port in {80, 443, 8080} else 0.2))
    elif attack == "SYN_FLOOD":
        src_ip = rng.choice(bot_ips[:75])
        protocol = "TCP"
        dst_port = 80
        packets = int(max(1, rng.poisson(24)))
        byte_count = int(packets * rng.integers(60, 120))
        syn_packets = int(max(1, packets * rng.uniform(0.78, 0.98)))
        requests = int(rng.poisson(1))
    elif attack == "HTTP_FLOOD":
        hot_bots = bot_ips[75:120]
        src_ip = rng.choice(hot_bots)
        protocol = "TCP"
        dst_port = int(rng.choice([80, 443], p=[0.65, 0.35]))
        packets = int(max(1, rng.poisson(14)))
        byte_count = int(packets * rng.integers(600, 1400))
        syn_packets = int(rng.binomial(packets, 0.04))
        requests = int(max(1, rng.poisson(20)))
    else:
        src_ip = rng.choice(bot_ips)
        protocol = "UDP"
        dst_port = int(rng.choice([53, 123, 1900]))
        packets = int(max(1, rng.poisson(45)))
        byte_count = int(packets * rng.integers(900, 1500))
        syn_packets = 0
        requests = int(rng.poisson(0.5))

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "dst_port": dst_port,
        "packets": packets,
        "bytes": byte_count,
        "flow_duration_ms": int(rng.integers(20, 2000)),
        "syn_packets": syn_packets,
        "requests": requests,
        "label": attack,
    }


def normalize_uploaded_dataset(df: pd.DataFrame) -> pd.DataFrame:
    if NORMALIZED_COLUMNS.issubset(df.columns):
        normalized = df.copy()
    else:
        normalized = _normalize_cic_like(df)

    normalized["timestamp"] = pd.to_datetime(normalized["timestamp"], errors="coerce")
    if normalized["timestamp"].isna().all():
        normalized["timestamp"] = pd.Timestamp("2026-05-02 09:00:00") + pd.to_timedelta(np.arange(len(normalized)), unit="s")
    normalized["timestamp"] = normalized["timestamp"].ffill().fillna(pd.Timestamp("2026-05-02 09:00:00"))
    normalized["protocol"] = normalized["protocol"].astype(str).str.upper()
    normalized["label"] = normalized["label"].fillna("UNKNOWN").astype(str).str.upper()
    for column in ["dst_port", "packets", "bytes", "flow_duration_ms", "syn_packets", "requests"]:
        normalized[column] = pd.to_numeric(normalized[column], errors="coerce").fillna(0)
    return normalized


def _normalize_cic_like(df: pd.DataFrame) -> pd.DataFrame:
    clean = df.copy()
    clean.columns = [column.strip() for column in clean.columns]
    n = len(clean)
    timestamps = clean.get("Timestamp")
    if timestamps is None:
        timestamps = pd.Timestamp("2026-05-02 09:00:00") + pd.to_timedelta(np.arange(n), unit="s")
    protocol_raw = clean.get("Protocol", "TCP")
    protocol = pd.Series(protocol_raw).replace({6: "TCP", 17: "UDP", 1: "ICMP"}).astype(str)
    fwd_packets = pd.to_numeric(clean.get("Total Fwd Packets", 0), errors="coerce").fillna(0)
    bwd_packets = pd.to_numeric(clean.get("Total Backward Packets", 0), errors="coerce").fillna(0)
    flow_bytes = pd.to_numeric(clean.get("Flow Bytes/s", 0), errors="coerce").replace([np.inf, -np.inf], 0).fillna(0)
    duration = pd.to_numeric(clean.get("Flow Duration", 1000), errors="coerce").fillna(1000)
    packets = (fwd_packets + bwd_packets).clip(lower=1)
    bytes_total = (flow_bytes * (duration / 1_000_000)).clip(lower=packets * 64)
    syn = pd.to_numeric(clean.get("SYN Flag Count", 0), errors="coerce").fillna(0)
    label = clean.get("Label", pd.Series(["UNKNOWN"] * n))
    requests = clean.get("Fwd Header Length", fwd_packets)
    if not isinstance(requests, pd.Series):
        requests = pd.Series([requests] * n)
    return pd.DataFrame(
        {
            "timestamp": timestamps,
            "src_ip": clean.get("Source IP", [f"192.0.2.{(i % 250) + 1}" for i in range(n)]),
            "dst_ip": clean.get("Destination IP", "10.0.0.10"),
            "protocol": protocol,
            "dst_port": clean.get("Destination Port", clean.get("Dst Port", 80)),
            "packets": packets,
            "bytes": bytes_total,
            "flow_duration_ms": duration / 1000,
            "syn_packets": syn,
            "requests": pd.to_numeric(requests, errors="coerce").fillna(0),
            "label": label,
        }
    )


def aggregate_windows(df: pd.DataFrame, window_seconds: int = 10) -> pd.DataFrame:
    work = normalize_uploaded_dataset(df)
    work = work.sort_values("timestamp")
    start = work["timestamp"].min()
    work["window_id"] = ((work["timestamp"] - start).dt.total_seconds() // window_seconds).astype(int)
    grouped = work.groupby("window_id", sort=True)
    rows = []
    for window_id, group in grouped:
        packet_sum = float(group["packets"].sum())
        byte_sum = float(group["bytes"].sum())
        protocol_packets = group.groupby("protocol")["packets"].sum().to_dict()
        source_packets = group.groupby("src_ip")["packets"].sum().sort_values(ascending=False)
        port_packets = group.groupby("dst_port")["packets"].sum().sort_values(ascending=False)
        top_sources = [
            {"src_ip": str(ip), "packets": int(count), "share": float(count / max(packet_sum, 1.0))}
            for ip, count in source_packets.head(8).items()
        ]
        labels = group["label"].astype(str).str.upper()
        attack_label = labels[labels != "BENIGN"].mode()
        rows.append(
            {
                "window_id": int(window_id),
                "window_start": start + pd.Timedelta(seconds=int(window_id) * window_seconds),
                "window_end": start + pd.Timedelta(seconds=(int(window_id) + 1) * window_seconds),
                "dst_ip": str(group["dst_ip"].mode().iloc[0]),
                "packets": packet_sum,
                "bytes": byte_sum,
                "flows": int(len(group)),
                "packets_per_second": packet_sum / window_seconds,
                "requests_per_second": float(group["requests"].sum()) / window_seconds,
                "mbps": (byte_sum * 8) / (window_seconds * 1_000_000),
                "tcp_packets": float(protocol_packets.get("TCP", 0)),
                "udp_packets": float(protocol_packets.get("UDP", 0)),
                "icmp_packets": float(protocol_packets.get("ICMP", 0)),
                "syn_ratio": float(group["syn_packets"].sum() / max(packet_sum, 1.0)),
                "udp_ratio": float(protocol_packets.get("UDP", 0) / max(packet_sum, 1.0)),
                "unique_sources": int(group["src_ip"].nunique()),
                "top_source_ratio": float(source_packets.iloc[0] / max(packet_sum, 1.0)),
                "top_dst_port": int(port_packets.index[0]),
                "top_port_ratio": float(port_packets.iloc[0] / max(packet_sum, 1.0)),
                "top_sources": top_sources,
                "attack_label": str(attack_label.iloc[0]) if not attack_label.empty else "BENIGN",
            }
        )
    return pd.DataFrame(rows)
