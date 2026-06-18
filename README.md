# realtime-ips-engine 🛡️

A lightweight, stateful **Intrusion Prevention System (IPS)** built from scratch in Python. The engine continuously tails live Linux authentication logs (`/var/log/auth.log`), maintains an in-memory rolling sliding-window of event telemetry, scores behavioral patterns using custom heuristics, and instantly drops active threats at the kernel layer via direct `iptables` hooks — with no third-party SIEM required.

---

## 🏗️ Architecture & Lab Layout

```
┌─────────────────────────────────┐     Host-Only Network      ┌──────────────────────────────┐
│       Ubuntu (Defender)         │◄──── 192.168.3.x/24 ───────│      Kali (Attacker)         │
│                                 │                             │                              │
│  /var/log/auth.log              │                             │  hydra -l victimuser         │
│       ↓                         │                             │       -P rockyou.txt         │
│  src/parse/log_parser.py        │                             │       ssh://192.168.3.128    │
│       ↓                         │                             └──────────────────────────────┘
│  src/features/window_manager.py │
│       ↓                         │
│  src/detection/engine.py        │
│       ↓                         │
│  iptables -I INPUT 1 -s IP DROP │  ◄── Active kernel-level block
└─────────────────────────────────┘
```
![Network Flow Diagram](https://raw.githubusercontent.com/KingLinux24/realtime-ips-engine/main/architecture.png)
The environment simulates a real-world edge-defense scenario...
Both VMs use **dual network adapters**:
- **Adapter 1 (NAT):** Internet access for updates and installs
- **Adapter 2 (Host-Only):** Isolated private subnet for attack/defense traffic

---

## ✨ Features

- **Live Stream Processing** — Tails `/var/log/auth.log` in real time, reacting within milliseconds of each new entry
- **Adaptive Regex Parser** — Handles both legacy syslog timestamps and modern ISO-8601 formats (`2026-06-18T09:48:05.191401+05:30`)
- **Stateful Sliding Window** — Tracks failures, successes, failure rate, and unique user targeting per IP over a rolling 5-minute window
- **Heuristic Threat Scoring** — Detects brute force, account takeover (success-after-failures), and password spraying with configurable thresholds
- **Active Kernel Defense** — Bypasses UFW wrappers (which conflict with Docker's iptables chains) and injects `DROP` rules directly into the Linux kernel

---

## 📁 Project Structure

```
realtime-ips-engine/
├── src/
│   ├── parse/
│   │   └── log_parser.py        # Regex-based SSH log parser
│   ├── features/
│   │   └── window_manager.py    # In-memory sliding window state tracker
│   ├── detection/
│   │   └── engine.py            # Signal detection and severity scoring
│   └── monitor.py               # Master daemon: tails logs, fires alerts, blocks IPs
├── .venv/
├── requirements.txt
└── README.md
```

---

## 🚀 Quickstart

### 1. Clone & Set Up Environment

```bash
git clone https://github.com/KingLinux24/realtime-ips-engine.git
cd realtime-ips-engine
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Create a Test Target User (Ubuntu)

```bash
sudo adduser victimuser
sudo systemctl enable --now ssh
```

### 3. Run the IPS Daemon

The engine reads `/var/log/auth.log` and calls `iptables`, so it requires root:

```bash
sudo PYTHONPATH=. .venv/bin/python src/monitor.py
```

### 4. Simulate an Attack (Kali)

```bash
# Brute force against a single account
hydra -l victimuser -P /usr/share/wordlists/fasttrack.txt ssh://192.168.3.128 -t 4

# Password spraying across multiple users
hydra -L users.txt -p 'Password123' ssh://192.168.3.128 -t 4
```

### 5. Verify the Block (Ubuntu)

```bash
sudo iptables -L INPUT -n --line-numbers
# Expected output:
# 1    DROP    all  --  192.168.3.129    0.0.0.0/0
```

### 6. Unblock (Reset)

```bash
sudo iptables -D INPUT 1
```

---

## 📊 Detection Signals & Thresholds

| Signal | Condition | Weight |
|---|---|---|
| `high_failures_single_user` | ≥10 failures and failure_rate > 0.8 | 3 |
| `success_after_failures` | ≥5 failures and ≥1 success | 5 |
| `password_spraying` | ≥3 unique users targeted from one IP | 4 |

**Severity levels:**
- `low` — score 1–2
- `medium` — score 3–5
- `high` — score ≥6 (triggers active block)

---

## 🔔 Sample Alert Output

```json
[!!!] SOC ALERT DETECTED [Severity: MEDIUM]
{
  "timestamp": "2026-06-18T10:06:13.641265",
  "src_ip": "192.168.3.129",
  "user": "victimuser",
  "metrics": {
    "failures": 96,
    "successes": 0,
    "failure_rate": 1.0,
    "unique_users": 1
  },
  "signals": ["high_failures_single_user"],
  "severity": "medium",
  "confidence": 0.7
}

[!] ACTIVE DEFENSE TRIGGERED: Blocking IP 192.168.3.129 via native iptables...
[+] Successfully isolated attacker 192.168.3.129 at the kernel level.
```

---

## ⚙️ Requirements

```
pandas
watchdog
```

Install:
```bash
pip install pandas watchdog
```

---

## 🧠 Key Engineering Decisions

### Why bypass UFW?
During testing, `ufw insert` commands returned `"Rules updated"` but silently failed to register kernel blocks — caused by Docker hijacking the underlying `iptables-restore` chains. The fix was to call `iptables -I INPUT 1 -s {ip} -j DROP` directly, bypassing the wrapper entirely and guaranteeing packet drops at the kernel level regardless of what other services are managing routing tables.

### Why not use a cron job?
Batch processing introduces a detection lag proportional to the cron interval (minutes). This engine uses a `follow_log()` function that emulates `tail -f` behavior — sleeping 100ms between reads — so the reaction time is near-instantaneous.

### Why in-memory windows instead of a database?
For a single-host IPS, writing to disk on every log event would bottleneck performance. An in-memory `defaultdict` of timestamped tuples is cleaned every event cycle, keeping RAM usage flat and latency at zero.

---

## 🚧 Limitations & False Positive Scenarios

- **Shared IPs / NAT Environments:** Corporate proxies or NAT gateways may cause multiple legitimate users to appear as one high-volume source IP
- **Mis-typed Passwords:** A single user repeatedly mis-typing their own password can trip the `high_failures_single_user` threshold
- **VPN Reconnections:** VPN clients that rapidly cycle auth attempts on reconnect can mimic spraying patterns
- **Threshold Tuning Required:** Default thresholds are calibrated for a small lab; production deployments need adjustment based on baseline traffic volume

---

## 🔭 Extending the System

- **Geo Anomaly Detection:** Flag logins from countries not in the user's historical profile
- **ML Upgrade:** Replace rule thresholds with an Isolation Forest trained on baseline traffic to catch novel attack patterns
- **Multi-Source Parsing:** Extend `log_parser.py` to ingest Nginx/Apache access logs for web-layer attack correlation
- **Alert Export:** Add a FastAPI endpoint to expose live incidents as JSON for SIEM integration
- **Notification Hooks:** Send alerts to Slack or email when a block fires

---

## ⚠️ Disclaimer

This project is strictly **defensive and educational**. All attack simulations were performed in an isolated virtual lab environment against machines and accounts owned by the author. Do not use these techniques against systems you do not own or have explicit permission to test.

---

## 👤 Author

**KingLinux24** — [GitHub](https://github.com/KingLinux24)

*Built as part of a hands-on cybersecurity homelab series.*
