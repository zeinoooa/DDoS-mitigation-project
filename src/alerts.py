from __future__ import annotations

import os
import smtplib
from dataclasses import dataclass
from email.message import EmailMessage

import requests


@dataclass(frozen=True)
class Alert:
    attack_type: str
    anomaly_score: float
    window_start: str
    affected_service: str
    indicators: list[str]
    source_ips: list[str]
    mitigation_status: str
    commands: list[str]


@dataclass(frozen=True)
class AlertStatus:
    ok: bool
    message: str


def format_alert_message(alert: Alert) -> str:
    indicators = ", ".join(alert.indicators) or "none"
    sources = ", ".join(alert.source_ips) or "distributed / no dominant source"
    commands = "\n".join(f"- {command}" for command in alert.commands) or "- no mitigation command generated"
    return (
        f"DDoS alert: {alert.attack_type}\n"
        f"Window: {alert.window_start}\n"
        f"Affected service: {alert.affected_service}\n"
        f"Anomaly score: {alert.anomaly_score:.2f}\n"
        f"Indicators: {indicators}\n"
        f"Suspicious sources: {sources}\n"
        f"Mitigation status: {alert.mitigation_status}\n"
        f"Recommended actions:\n{commands}"
    )


def dispatch_alert(alert: Alert, provider: str, recipient: str) -> AlertStatus:
    message = format_alert_message(alert)
    if provider == "Console preview":
        return AlertStatus(ok=True, message=f"Preview alert generated for {recipient}.")
    if provider == "Slack webhook":
        return _send_slack(message)
    if provider == "Email (SMTP)":
        return _send_email(message, recipient)
    return AlertStatus(ok=False, message="Unsupported alert provider.")


def _send_slack(message: str) -> AlertStatus:
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        return AlertStatus(ok=False, message="Set SLACK_WEBHOOK_URL to send real Slack alerts. Preview is available.")
    response = requests.post(webhook, json={"text": message}, timeout=10)
    if response.ok:
        return AlertStatus(ok=True, message="Slack alert sent.")
    return AlertStatus(ok=False, message=f"Slack rejected the alert with HTTP {response.status_code}.")


def _send_email(message: str, recipient: str) -> AlertStatus:
    host = os.getenv("SMTP_HOST")
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM", user or "ddos-console@example.local")
    port = int(os.getenv("SMTP_PORT", "587"))
    if not host or not user or not password or "@" not in recipient:
        return AlertStatus(
            ok=False,
            message="Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD, and an email recipient to send real email alerts.",
        )

    email = EmailMessage()
    email["Subject"] = "DDoS mitigation alert"
    email["From"] = sender
    email["To"] = recipient
    email.set_content(message)
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        smtp.starttls()
        smtp.login(user, password)
        smtp.send_message(email)
    return AlertStatus(ok=True, message="Email alert sent.")
