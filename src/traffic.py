from __future__ import annotations

import ipaddress
import struct
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


PCAP_LABELS = {
    "normal": "BENIGN",
    "normal2": "BENIGN",
    "mirai": "DDOS_MIRAI",
    "replayattacks": "DDOS_REPLAY",
}


def available_pcap_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("*.pcap"))


def load_pcap_dataset(paths: list[Path], packet_limit_per_file: int = 120_000) -> pd.DataFrame:
    frames = []
    offset_seconds = 0.0
    for path in paths:
        parsed = parse_pcap_file(path, packet_limit=packet_limit_per_file)
        if parsed.empty:
            continue
        parsed = parsed.sort_values("timestamp")
        first_ts = parsed["timestamp"].min()
        parsed["timestamp"] = (
            pd.Timestamp("2026-05-02 09:00:00")
            + pd.to_timedelta(offset_seconds, unit="s")
            + (parsed["timestamp"] - first_ts)
        )
        offset_seconds += max((parsed["timestamp"].max() - parsed["timestamp"].min()).total_seconds(), 60.0) + 30.0
        frames.append(parsed)

    if not frames:
        return pd.DataFrame(columns=sorted(NORMALIZED_COLUMNS))
    return normalize_uploaded_dataset(pd.concat(frames, ignore_index=True))


def parse_pcap_file(path: Path, packet_limit: int = 120_000) -> pd.DataFrame:
    label = label_for_pcap(path)
    rows = []
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            return pd.DataFrame(columns=sorted(NORMALIZED_COLUMNS))
        endian, ts_scale = _pcap_format(header[:4])
        if endian is None:
            raise ValueError(f"{path.name} is not a classic PCAP file.")
        linktype = struct.unpack(f"{endian}HHIIII", header[4:24])[-1]

        count = 0
        while count < packet_limit:
            packet_header = handle.read(16)
            if len(packet_header) < 16:
                break
            ts_sec, ts_frac, included_len, _original_len = struct.unpack(f"{endian}IIII", packet_header)
            packet = handle.read(included_len)
            if len(packet) < included_len:
                break
            parsed = _parse_packet(packet, linktype)
            if parsed is None:
                continue
            timestamp = pd.Timestamp.fromtimestamp(ts_sec + (ts_frac / ts_scale))
            parsed.update(
                {
                    "timestamp": timestamp,
                    "packets": 1,
                    "bytes": included_len,
                    "flow_duration_ms": 1,
                    "label": label,
                    "source_file": path.name,
                }
            )
            rows.append(parsed)
            count += 1

    return pd.DataFrame(rows)


def label_for_pcap(path: Path) -> str:
    stem = path.stem.lower()
    return PCAP_LABELS.get(stem, "ATTACK")


def _pcap_format(magic: bytes) -> tuple[str | None, float]:
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
    }
    return formats.get(magic, (None, 1_000_000.0))


def _parse_packet(packet: bytes, linktype: int) -> dict[str, object] | None:
    if linktype == 1:
        if len(packet) < 14:
            return None
        ethertype = int.from_bytes(packet[12:14], "big")
        offset = 14
        if ethertype == 0x8100 and len(packet) >= 18:
            ethertype = int.from_bytes(packet[16:18], "big")
            offset = 18
    elif linktype == 113:
        if len(packet) < 16:
            return None
        ethertype = int.from_bytes(packet[14:16], "big")
        offset = 16
    else:
        return None

    if ethertype != 0x0800:
        return None
    return _parse_ipv4(packet[offset:])


def _parse_ipv4(payload: bytes) -> dict[str, object] | None:
    if len(payload) < 20:
        return None
    version = payload[0] >> 4
    ihl = (payload[0] & 0x0F) * 4
    if version != 4 or len(payload) < ihl:
        return None
    protocol_number = payload[9]
    src_ip = str(ipaddress.IPv4Address(payload[12:16]))
    dst_ip = str(ipaddress.IPv4Address(payload[16:20]))
    transport = payload[ihl:]

    dst_port = 0
    syn_packets = 0
    requests = 0
    if protocol_number == 6 and len(transport) >= 20:
        protocol = "TCP"
        dst_port = int.from_bytes(transport[2:4], "big")
        flags = transport[13]
        syn_packets = 1 if flags & 0x02 and not flags & 0x10 else 0
        requests = 1 if dst_port in {80, 443, 8080} else 0
    elif protocol_number == 17 and len(transport) >= 8:
        protocol = "UDP"
        dst_port = int.from_bytes(transport[2:4], "big")
        requests = 1 if dst_port in {53, 123, 1900} else 0
    elif protocol_number == 1:
        protocol = "ICMP"
    else:
        protocol = f"IP-{protocol_number}"

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "dst_port": dst_port,
        "syn_packets": syn_packets,
        "requests": requests,
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
