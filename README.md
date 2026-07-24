# CodeAlpha Task 4: Network Intrusion Detection System (NIDS)

A comprehensive Python-based Network Intrusion Detection System featuring real-time packet analysis, signature/threshold detection rules, SQLite alert persistence, attack simulation, and a dark cyber threat monitoring dashboard.

---

## Key Features

- **Real-Time Threat Detection**: Evaluates streaming network packets against 5+ security detection rules:
  1. `PORT_SCAN`: High-frequency TCP SYN packet detection (>10 packets/sec).
  2. `PING_FLOOD`: ICMP Echo Request flooding detection (>20 packets/2 sec).
  3. `SQL_INJECTION`: Web application payload inspection matching SQLi signatures (`UNION`, `SELECT`, `DROP`, `--`).
  4. `BRUTE_FORCE_SSH`: Rapid connection spike detection on SSH Port 22 (>5 connections/3 sec).
  5. `ARP_SPOOFING`: Detects IP address to MAC address binding anomalies (ARP cache poisoning).
- **Whitelist Management**: Integrated `whitelist.txt` to exclude trusted hosts (localhost, gateway) and minimize false positives.
- **SQLite Database Persistence**: All triggered security alerts are persisted in `nids_alerts.db` with timestamps, severity levels, target IPs, and raw payloads.
- **Modern PyQt5 Threat Dashboard**:
  - **Color-Coded Alert Feed**: Red (`HIGH`), Orange (`MEDIUM`), Blue (`LOW`), and Gray (`INFO`).
  - **Live Threat Analytics**: Embedded Matplotlib bar chart (Top 5 Attacking IPs) and donut chart (Attack Type Distribution).
  - **Automated IP Blocking**: "Block IP" feature that logs malicious source IPs to `blocklist.txt`.
  - **Payload Inspector**: Clickable alert drawer displaying matched rule signatures and hex evidence dumps.
- **Automated Attack Simulator (`attack_sim.py`)**: Safe local attack generator over `127.0.0.1` for testing and live video demonstration.

---

## Architecture Diagram

```
+------------------------------------------------------------------+
|                     Scapy Packet Sniffer Thread                  |
+------------------------------------------------------------------+
                               | Raw Packets
                               v
+------------------------------------------------------------------+
|               Signature & Threshold Rule Engine (rules.py)       |
|  - SQL Injection Detector   - Port Scan Tracker                  |
|  - Ping Flood Counter       - SSH Connection Monitor             |
|  - ARP Spoofing Inspector   - Whitelist Filter (whitelist.txt)   |
+------------------------------------------------------------------+
                               | Triggered Alerts
                               v
+------------------------------------+-----------------------------+
| SQLite Alert Storage (db.py)       |  PyQt5 Dashboard Queue      |
| Table: nids_alerts.db              |  (dashboard.py)             |
+------------------------------------+-----------------------------+
```

---

## Installation & Setup

### Prerequisites
- Python 3.10+
- **Windows**: Install [Npcap Driver](https://npcap.com/) (select *"Install Npcap in WinPcap API-compatible Mode"*). Run terminal as Administrator.
- **Linux**: Python 3 environment. Run with `sudo` or set `CAP_NET_RAW` capabilities.

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## How to Run

### 1. Launch the NIDS Dashboard

**Windows (Administrator Command Prompt or PowerShell):**
```cmd
python dashboard.py
```

**Linux / macOS:**
```bash
sudo python3 dashboard.py
```

Click **🛡️ Start Monitoring** in the top control bar to begin live network monitoring.

---

### 2. Run the Attack Simulator (Demo Mode)

Open a **second terminal window** while the NIDS dashboard is running and execute:

```bash
python attack_sim.py --attack all
```

#### Individual Attack Test Options:
```bash
python attack_sim.py --attack portscan     # Simulate Port Scan
python attack_sim.py --attack pingflood    # Simulate ICMP Ping Flood
python attack_sim.py --attack sqli         # Simulate SQL Injection payload
python attack_sim.py --attack ssh          # Simulate SSH Brute Force attempt
python attack_sim.py --attack arp          # Simulate ARP Spoofing packet
```

*Watch the NIDS GUI update instantly with color-coded alerts and dynamic threat charts!*

---

## Detection Rules Configuration

| Rule ID | Attack Type | Threshold / Condition | Default Severity |
| :--- | :--- | :--- | :--- |
| **Rule 1** | `SQL_INJECTION` | Payload contains `SELECT`, `UNION`, `DROP`, `--` | **HIGH** |
| **Rule 2** | `PORT_SCAN` | >10 SYN packets from same IP within 1.0 second | **HIGH** |
| **Rule 3** | `PING_FLOOD` | >20 ICMP packets from same IP within 2.0 seconds | **MEDIUM** |
| **Rule 4** | `BRUTE_FORCE_SSH` | >5 TCP connections to Port 22 within 3.0 seconds | **MEDIUM** |
| **Rule 5** | `ARP_SPOOFING` | Conflicting MAC address assigned to existing IP | **HIGH** |

---

## Repository Structure

```
CodeAlpha_NIDS/
├── rules.py          # Attack signature & threshold rule engine
├── ids_engine.py     # Core packet capture & detection orchestrator
├── db.py             # SQLite persistence & export module (nids_alerts.db)
├── attack_sim.py     # Scapy attack simulation generator for testing
├── dashboard.py      # PyQt5 dark threat monitoring GUI
├── whitelist.txt     # Whitelisted IP addresses
├── blocklist.txt     # Simulated blocked IP address log
├── requirements.txt  # Python package dependencies
└── README.md         # Documentation & user guide
```

---

*Author: Satyam Kamble | CodeAlpha Cyber Security Internship*
