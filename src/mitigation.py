from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class MitigationPolicy:
    whitelist: tuple[str, ...] = ("10.0.0.1", "10.0.0.2", "127.0.0.1")
    soft_packet_limit: int = 600
    hard_packet_limit: int = 1200
    max_blocked_sources: int = 5


@dataclass(frozen=True)
class MitigationAction:
    title: str
    command: str
    reason: str


@dataclass(frozen=True)
class MitigationPlan:
    restriction_level: str
    blocked_sources: list[str]
    actions: list[MitigationAction]


class TokenBucket:
    """Token bucket used by the demo API and to explain rate-limit behavior."""

    def __init__(self, capacity: int, fill_rate: float) -> None:
        self.capacity = capacity
        self.tokens = float(capacity)
        self.fill_rate = fill_rate
        self.timestamp = time.time()

    def consume(self, tokens: int = 1) -> bool:
        now = time.time()
        elapsed = now - self.timestamp
        self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
        self.timestamp = now
        if tokens <= self.tokens:
            self.tokens -= tokens
            return True
        return False


def is_whitelisted(ip: str, whitelist: Iterable[str]) -> bool:
    return ip in set(whitelist)


def hashlimit_rule(ip: str, packets_per_second: int) -> str:
    return (
        "sudo iptables -A INPUT "
        f"-s {ip} "
        "-m hashlimit "
        f"--hashlimit {packets_per_second}/second "
        "--hashlimit-burst 100 "
        "--hashlimit-mode srcip "
        f"--hashlimit-name ddos_{ip.replace('.', '_')} "
        "-j ACCEPT"
    )


def drop_rule(ip: str) -> str:
    return f"sudo iptables -A INPUT -s {ip} -j DROP"


def syn_limit_rule(limit_per_second: int) -> str:
    return (
        "sudo iptables -A INPUT -p tcp --syn "
        "-m limit "
        f"--limit {limit_per_second}/second "
        "--limit-burst 200 -j ACCEPT"
    )


def generate_mitigation_plan(window, detection_result, policy: MitigationPolicy) -> MitigationPlan:
    if not detection_result.is_attack:
        return MitigationPlan(restriction_level="none", blocked_sources=[], actions=[])

    top_sources = window.get("top_sources", [])
    suspicious_sources: list[str] = []
    for row in top_sources if isinstance(top_sources, list) else []:
        ip = row.get("src_ip")
        if ip and not is_whitelisted(ip, policy.whitelist):
            suspicious_sources.append(ip)
        if len(suspicious_sources) >= policy.max_blocked_sources:
            break

    if detection_result.score >= 0.85:
        restriction = "hard block"
        per_source_limit = policy.hard_packet_limit
    elif detection_result.score >= 0.65:
        restriction = "strict rate limit"
        per_source_limit = policy.soft_packet_limit
    else:
        restriction = "watch and lenient rate limit"
        per_source_limit = max(policy.soft_packet_limit * 2, policy.hard_packet_limit)

    actions: list[MitigationAction] = []
    if detection_result.attack_type == "SYN flood":
        actions.append(
            MitigationAction(
                title="Global SYN guard",
                command=syn_limit_rule(limit_per_second=per_source_limit),
                reason="SYN packet share is above the learned baseline.",
            )
        )

    for ip in suspicious_sources:
        if restriction == "hard block":
            command = drop_rule(ip)
            title = "Block attacking source"
            reason = "High anomaly score and concentrated traffic from this source."
        else:
            command = hashlimit_rule(ip, packets_per_second=per_source_limit)
            title = "Rate limit suspicious source"
            reason = "Gradual mitigation keeps legitimate traffic available while reducing attack impact."
        actions.append(MitigationAction(title=title, command=command, reason=reason))

    if not actions:
        actions.append(
            MitigationAction(
                title="Service-level token bucket",
                command=f"TokenBucket(capacity={per_source_limit}, fill_rate={per_source_limit / 2:.1f})",
                reason="No non-whitelisted dominant source was found, so apply service-level shaping.",
            )
        )

    return MitigationPlan(restriction_level=restriction, blocked_sources=suspicious_sources, actions=actions)
