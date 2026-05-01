from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


FEATURES = (
    "packets_per_second",
    "mbps",
    "requests_per_second",
    "syn_ratio",
    "udp_ratio",
    "top_source_ratio",
    "top_port_ratio",
    "unique_sources",
)


WEIGHTS = {
    "packets_per_second": 0.18,
    "mbps": 0.14,
    "requests_per_second": 0.16,
    "syn_ratio": 0.14,
    "udp_ratio": 0.08,
    "top_source_ratio": 0.14,
    "top_port_ratio": 0.10,
    "unique_sources": 0.06,
}


@dataclass(frozen=True)
class IndicatorScore:
    name: str
    value: float
    baseline: float
    score: float


@dataclass(frozen=True)
class DetectionResult:
    is_attack: bool
    score: float
    attack_type: str
    indicators: list[IndicatorScore]


@dataclass(frozen=True)
class WindowSummary:
    packets_per_second: float
    unique_sources: int
    top_source_ratio: float


class BaselineModel:
    def __init__(self, stats: dict[str, dict[str, float]]) -> None:
        self.stats = stats

    def score_feature(self, name: str, value: float) -> IndicatorScore:
        metric = self.stats[name]
        mean = metric["mean"]
        std = max(metric["std"], 1e-9)
        p95 = metric["p95"]
        if value <= p95:
            score = 0.0
        else:
            score = min((value - p95) / (3.0 * std), 1.0)
        return IndicatorScore(name=name, value=float(value), baseline=float(p95), score=float(score))

    def to_dict(self) -> dict[str, dict[str, float]]:
        return self.stats


def build_baseline(windows: pd.DataFrame) -> BaselineModel:
    if "attack_label" in windows.columns and (windows["attack_label"] == "BENIGN").any():
        baseline_rows = windows[windows["attack_label"] == "BENIGN"].copy()
    else:
        baseline_rows = windows.head(max(10, len(windows) // 3)).copy()

    stats: dict[str, dict[str, float]] = {}
    for feature in FEATURES:
        values = pd.to_numeric(baseline_rows[feature], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0)
        stats[feature] = {
            "mean": float(values.mean()),
            "std": float(values.std(ddof=0) or 1.0),
            "p95": float(values.quantile(0.95)),
        }
    return BaselineModel(stats)


def infer_attack_type(window, indicators: list[IndicatorScore]) -> str:
    scores = {item.name: item.score for item in indicators}
    if scores.get("syn_ratio", 0) >= 0.35:
        return "SYN flood"
    if scores.get("requests_per_second", 0) >= 0.35 and int(window.get("top_dst_port", 0)) in {80, 443, 8080}:
        return "HTTP application-layer flood"
    if scores.get("udp_ratio", 0) >= 0.35 or int(window.get("udp_packets", 0)) > int(window.get("tcp_packets", 0)):
        return "UDP volumetric flood"
    if scores.get("top_source_ratio", 0) >= 0.35:
        return "source concentration attack"
    return "traffic anomaly"


def detect_window(window, baseline: BaselineModel, alert_threshold: float = 0.55) -> DetectionResult:
    indicators = [baseline.score_feature(feature, float(window[feature])) for feature in FEATURES]
    weighted_score = sum(item.score * WEIGHTS[item.name] for item in indicators)
    score = min(weighted_score / sum(WEIGHTS.values()), 1.0)
    is_attack = score >= alert_threshold
    attack_type = infer_attack_type(window, indicators) if is_attack else "none"
    return DetectionResult(is_attack=is_attack, score=float(score), attack_type=attack_type, indicators=indicators)


def summarize_window(window) -> WindowSummary:
    return WindowSummary(
        packets_per_second=float(window["packets_per_second"]),
        unique_sources=int(window["unique_sources"]),
        top_source_ratio=float(window["top_source_ratio"]),
    )
