# DDoS Mitigation Tool

Streamlit dashboard for baseline traffic modeling, rolling anomaly detection, mitigation planning, and alert notifications.

## Features

- Establishes a baseline from benign traffic windows using mean, standard deviation, and 95th percentile statistics.
- Aggregates traffic in rolling windows with packet rate, bandwidth, protocol distribution, source concentration, port concentration, and SYN/request ratios.
- Computes a weighted composite anomaly score and classifies likely SYN flood, UDP volumetric flood, HTTP application flood, or source concentration attacks.
- Recommends gradual mitigation actions: token bucket shaping, `iptables` hashlimit rate limiting, SYN guards, and hard source blocks.
- Applies safeguards through configurable whitelisted IPs and maximum blocked source counts.
- Provides a live dashboard with time slider, anomaly indicators, charts, source tables, mitigation commands, and alert preview/sending.
- Supports optional Slack and SMTP alerts through environment variables.

## Run Locally

```bash
pip install -r requirements.txt
streamlit run src/app.py
```

Open `http://localhost:8501`.

## Run With Docker

```bash
docker build -t ddos-mitigation .
docker run --rm -p 8501:8501 --cap-add=NET_ADMIN ddos-mitigation
```

Or:

```bash
docker compose up --build
```

The app displays recommended firewall commands by default. The dashboard does not execute `iptables` commands automatically, which keeps the TA demo safe on laptops and containers.

## Dataset

The app creates `data/demo_traffic.csv` automatically if it is missing. The deterministic demo includes:

- Normal traffic.
- SYN flood from `09:06:00` to `09:08:00`.
- HTTP application-layer flood from `09:10:50` to `09:12:40`.
- UDP volumetric flood from `09:15:00` to `09:16:10`.

You can also upload a CSV. Native columns are:

```text
timestamp,src_ip,dst_ip,protocol,dst_port,packets,bytes,flow_duration_ms,syn_packets,requests,label
```

The uploader also maps common CIC-style columns such as `Flow Duration`, `Total Fwd Packets`, `Destination Port`, `Protocol`, `SYN Flag Count`, and `Label`.

## Alert Configuration

Slack:

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
```

Email:

```bash
export SMTP_HOST="smtp.example.com"
export SMTP_PORT="587"
export SMTP_USER="user@example.com"
export SMTP_PASSWORD="app-password"
export SMTP_FROM="ddos-console@example.com"
```

If these variables are not set, the dashboard still provides a console preview suitable for grading.

## Demo Script

1. Start the container and open the dashboard.
2. Keep the bundled demo dataset selected.
3. Move the time slider through normal windows first and show the low anomaly score.
4. Move to the SYN flood, HTTP flood, or UDP flood windows.
5. Explain the indicator table, anomaly score, attack type, and source concentration table.
6. Show generated `iptables` and token bucket recommendations.
7. Use "Console preview" in Notifications and click "Send alert".

## Team Subprojects

- Baseline and Monitoring: `src/traffic.py` rolling aggregation and baseline inputs.
- Detection and Algorithms: `src/detection.py` statistical baseline and composite score.
- Mitigation and Firewall: `src/mitigation.py` token bucket, whitelist safeguards, and `iptables` rules.
- Dashboard and Alerts: `src/app.py` and `src/alerts.py`.
