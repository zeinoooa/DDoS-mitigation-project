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

The default data source is raw PCAP files in:

```text
data/pcap/
```

The dashboard includes a built-in classic PCAP parser for Ethernet/IPv4/TCP/UDP/ICMP packets, so it does not require `tshark` for the demo. By default, the sidebar selects benign captures and the Mirai capture:

```text
normal.pcap
normal2.pcap
mirai.pcap
```

Labels are inferred from filenames:

- `normal.pcap` and `normal2.pcap` -> `BENIGN`
- `mirai.pcap` -> `DDOS_MIRAI`
- `replayAttacks.pcap` -> `DDOS_REPLAY`
- other PCAP files -> `ATTACK`

The app still supports uploading CSV files if needed. Native CSV columns are:

```text
timestamp,src_ip,dst_ip,protocol,dst_port,packets,bytes,flow_duration_ms,syn_packets,requests,label
```

The CSV uploader also maps common CIC-style columns such as `Flow Duration`, `Total Fwd Packets`, `Destination Port`, `Protocol`, `SYN Flag Count`, and `Label`.

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
2. Keep "Bundled PCAP files" selected.
3. Use `normal.pcap`, `normal2.pcap`, and `mirai.pcap` for the main DDoS demo.
4. Move the time slider through normal windows first and show the low anomaly score.
5. Move into the Mirai attack windows and show the higher anomaly score.
6. Explain the indicator table, anomaly score, attack type, and source concentration table.
7. Show generated `iptables` and token bucket recommendations.
8. Use "Console preview" in Notifications and click "Send alert".

## Team Subprojects

- Baseline and Monitoring: `src/traffic.py` rolling aggregation and baseline inputs.
- Detection and Algorithms: `src/detection.py` statistical baseline and composite score.
- Mitigation and Firewall: `src/mitigation.py` token bucket, whitelist safeguards, and `iptables` rules.
- Dashboard and Alerts: `src/app.py` and `src/alerts.py`.
