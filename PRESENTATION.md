# 20-Minute Presentation Plan

## 1. Problem and Architecture

- DDoS attacks overload a service with abnormal traffic volume, protocol behavior, or application requests.
- The project uses a Streamlit dashboard over rolling traffic windows.
- Data flow: traffic rows -> rolling aggregation -> baseline model -> composite anomaly score -> mitigation plan -> alert.

## 2. Baseline and Monitoring

- File: `src/traffic.py`
- Raw PCAP files are parsed directly from `data/pcap`.
- The app aggregates every 5, 10, 15, or 30 seconds.
- Metrics include packet rate, Mbps, protocol packet counts, SYN ratio, request rate, source concentration, port concentration, and unique source count.
- The baseline is learned from benign windows when labels are present; otherwise it uses the first third of the dataset.

## 3. Detection Algorithm

- File: `src/detection.py`
- Each indicator is compared with the benign 95th percentile and standard deviation.
- Indicator scores are weighted into one composite anomaly score.
- Attack type is inferred from the dominant indicators:
  - High SYN ratio -> SYN flood.
  - High request rate on web ports -> HTTP application-layer flood.
  - High UDP ratio or UDP volume -> UDP volumetric flood.
  - High top-source ratio -> source concentration attack.

## 4. Mitigation Strategy

- File: `src/mitigation.py`
- The tool recommends gradual safeguards before hard blocking.
- Whitelisted IPs are never blocked.
- Medium scores produce `iptables` hashlimit rate limiting.
- High scores produce source drop rules.
- SYN floods also produce a global SYN guard rule.
- The `TokenBucket` class demonstrates the rate-limiting algorithm.

## 5. Alerts and Dashboard

- Files: `src/app.py`, `src/alerts.py`
- Dashboard controls:
  - Select bundled PCAP files, upload PCAP files, or upload CSV files.
  - Move the time slider between normal and attack windows.
  - Adjust rolling window size, alert threshold, whitelist, and rate limits.
- Alert channels:
  - Console preview works without secrets.
  - Slack works with `SLACK_WEBHOOK_URL`.
  - Email works with SMTP environment variables.

## 6. Live Demo Steps

1. Run `docker compose up --build` or `streamlit run src/app.py`.
2. Open `http://localhost:8501`.
3. Keep "Bundled PCAP files" selected.
4. Select `normal.pcap`, `normal2.pcap`, and `mirai.pcap`.
5. Show a normal window and explain why the score is low.
6. Move into the Mirai attack windows and show the high anomaly score.
7. Show indicator table, top sources, mitigation commands, and alert preview.

## 7. Expected TA Questions

- Why use percentiles? They are robust against normal traffic variance and easier to explain than a black-box model.
- How are false positives reduced? Multiple weighted indicators are combined instead of alerting on one metric.
- Why not execute `iptables` automatically? The demo is safer and repeatable; production deployment can execute the generated commands with admin approval.
- How are legitimate users protected? Whitelisting, gradual rate limits, max blocked source count, and token bucket shaping reduce overblocking.
- Can it use PCAP files? Yes. The app parses classic Ethernet/IPv4 PCAP files and extracts source IP, destination IP, protocol, ports, bytes, SYN flags, and request-like counters.
