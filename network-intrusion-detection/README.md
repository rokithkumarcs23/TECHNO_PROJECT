# Network Intrusion Detection System (NIDS) – Threat Detection and Security Monitoring

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/UI-Streamlit-red.svg)](https://streamlit.io/)
[![Packet Engine](https://img.shields.io/badge/Packet%20Engine-Scapy-green.svg)](https://scapy.net/)
[![Storage](https://img.shields.io/badge/Database-SQLite3-lightgrey.svg)](https://www.sqlite.org/)
[![License](https://img.shields.io/badge/License-MIT-purple.svg)]()

A complete, production-grade **Network Intrusion Detection System (NIDS)** featuring rule-based threat detection, packet telemetry analysis, an interactive cyber dark Streamlit dashboard, and persistent SQLite event history logging.

The system supports both **offline PCAP/PCAPNG file inspection** (default mode, requiring zero elevated administrator privileges) and **authorized live network monitoring** via Scapy.

---

## Table of Contents
1. [Project Overview](#project-overview)
2. [Problem Statement](#problem-statement)
3. [Objectives](#objectives)
4. [Key Features](#key-features)
5. [Technology Stack](#technology-stack)
6. [Architecture & Workflow](#architecture--workflow)
7. [Project Folder Structure](#project-folder-structure)
8. [Installation & Setup](#installation--setup)
   - [Windows (PowerShell)](#windows-powershell)
   - [Linux / macOS](#linux--macos)
9. [Running the Application](#running-the-application)
   - [Offline PCAP Analysis (Default)](#offline-pcap-analysis-default)
   - [Authorized Live Network Capture](#authorized-live-network-capture)
10. [Detection Engine Rules & Default Thresholds](#detection-engine-rules--default-thresholds)
11. [Dashboard Sections & Features](#dashboard-sections--features)
12. [Running Unit Tests](#running-unit-tests)
13. [Demonstration Guide](#demonstration-guide)
14. [Security, Ethics & Privacy](#security-ethics--privacy)
15. [Known Limitations & Future Enhancements](#known-limitations--future-enhancements)

---

## Project Overview
Modern network perimeters face continuous reconnaissance, unauthorized access attempts, and distributed denial-of-service disruptions. This Network Intrusion Detection System (NIDS) provides cybersecurity operators and security analysts with immediate visibility into malicious traffic patterns. It processes raw packet byte streams, reconstructs transport flows, evaluates rolling detection windows, and stores forensic evidence in a relational SQLite audit log.

---

## Problem Statement
Small-to-medium enterprise networks and academic environments often lack accessible intrusion detection tooling. Traditional enterprise systems (e.g., Zeek, Suricata, Snort) require complex configuration files, dedicated Linux daemons, and separate elasticsearch pipelines. This project addresses the need for a self-contained, modular Python-based NIDS that can be deployed instantly for both demonstration and forensic analysis.

---

## Objectives
- **Monitor Network Traffic**: Ingest raw packet streams both from static PCAP files and live network adapters.
- **Rule-Based Threat Detection**: Implement rolling-window state machines for port scans, brute-force indicators, and traffic floods.
- **Persistent Event Auditing**: Store alert metadata, timestamps, and structured forensic evidence in SQLite.
- **Interactive SOC Dashboard**: Provide real-time metrics, interactive Plotly visualizations, packet inspection tables, and CSV exports in Streamlit.
- **Safe & Ethical**: Default to unprivileged offline analysis without requiring malicious attack traffic.

---

## Key Features
- **Dual Capture Modes**:
  - **Offline PCAP Mode (Default)**: Ingest `.pcap` and `.pcapng` files without root/admin privileges.
  - **Live Capture Mode**: Real-time packet sniffing on selected interfaces (Npcap / libpcap).
- **Rule-Based Threat Classification**:
  - **Port Scanning**: Cardinality detection of distinct destination ports probed within short time windows.
  - **Suspected Brute-Force Indicators**: Frequency of TCP connection attempts to sensitive authentication ports (SSH, RDP, MySQL, FTP).
  - **Suspected Traffic Flooding**: High packet rate burst detection.
  - **Normal Baseline**: Rejection of benign traffic without false positives.
- **Duplicate Suppression**: Sliding cooldown intervals prevent alert storming.
- **Forensic Packet Inspector**: Searchable, filterable packet metadata grid with TCP flag decoding.
- **Plotly Visualizations**: Protocol distributions, traffic volume timelines, top talkers, and threat breakdowns.
- **Persistent SQLite Database**: Parameterized queries, automatic schema initialization, and CSV export.

---

## Technology Stack
| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.10+ | Core application logic and detection algorithms |
| **Packet Engine** | Scapy | Live packet sniffing, PCAP parsing, protocol extraction |
| **Data Processing** | Pandas & NumPy | High-performance aggregations, time-series binning |
| **Web Dashboard** | Streamlit | SOC dark-themed interface, metric cards, controls |
| **Visualizations** | Plotly | Interactive charts (pie, area, bar, timelines) |
| **Database** | SQLite3 | Persistent storage of alerts and forensic evidence |
| **Testing** | Pytest | Automated unit testing with synthetic fixtures |

---

## Architecture & Workflow

```
       +---------------------------------------------+
       |             Ingestion Source                |
       |  (Offline PCAP File OR Live Network Sniff)  |
       +---------------------------------------------+
                              |
                              v
       +---------------------------------------------+
       |         modules/packet_capture.py           |
       |  - Scapy Reader / Sniffer                   |
       |  - Defensive Layer Parsing (IP/TCP/UDP/ARP) |
       +---------------------------------------------+
                              |
                              v
       +---------------------------------------------+
       |         modules/packet_analyzer.py          |
       |  - Bandwidth & Packet Rates                 |
       |  - Protocol Distribution                    |
       |  - Time-series Resampling                   |
       +---------------------------------------------+
                              |
                              v
       +---------------------------------------------+
       |         modules/detection_engine.py         |
       |  - Rolling Time-Window Deques               |
       |  - Port Scan Detection                      |
       |  - Brute-Force Connection Indicators        |
       |  - Traffic Flooding Detection               |
       |  - Cooldown Deduplication Engine            |
       +---------------------------------------------+
                              |
                              v
              +---------------+---------------+
              |                               |
              v                               v
+---------------------------+   +---------------------------+
|    modules/database.py    |   |          app.py           |
|  - SQLite Alerts Table    |   |  - Streamlit Dashboard    |
|  - Parameterized Queries  |   |  - Real-time Threat Feed  |
|  - CSV Export             |   |  - Plotly Visualizations  |
+---------------------------+   +---------------------------+
```

---

## Project Folder Structure

```
network-intrusion-detection/
│
├── app.py                      # Main Streamlit web application & SOC interface
├── requirements.txt            # Python dependencies (Scapy, Pandas, Streamlit, etc.)
├── README.md                   # Complete architectural and operational documentation
├── .gitignore                  # Git ignore rules for virtualenvs, caches, and DBs
│
├── modules/
│   ├── __init__.py             # Package declaration
│   ├── packet_capture.py       # Offline PCAP reading and live network packet capture
│   ├── packet_analyzer.py      # Statistical aggregation, metrics, and protocol summaries
│   ├── detection_engine.py     # Rule-based threat engine with rolling time windows
│   ├── alert_manager.py        # Coordinates session alerts, deduplication, and persistence
│   └── database.py             # SQLite persistence, parameterized queries, and exports
│
├── data/
│   ├── sample_placeholder.txt  # Instructions on sample PCAPs
│   ├── generate_sample_pcap.py # Utility script to generate safe synthetic attack PCAPs
│   └── sample_traffic.pcap     # Generated demonstration capture file
│
├── tests/
│   ├── test_detection.py       # Unit tests for port scan, brute force, flood, & cooldowns
│   └── test_database.py        # Unit tests for SQLite CRUD, indices, filtering, & CSV export
│
└── assets/
    └── README.txt              # Static assets and diagram placeholder
```

---

## Installation & Setup

### Windows (PowerShell)

1. Open PowerShell and navigate to the project directory:
   ```powershell
   cd "network-intrusion-detection"
   ```

2. Create a virtual environment:
   ```powershell
   python -m venv .venv
   ```

3. Activate the virtual environment:
   ```powershell
   .venv\Scripts\Activate.ps1
   ```
   *(If script execution is restricted on your machine, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

4. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

---

### Linux / macOS

1. Open a terminal and navigate to the project directory:
   ```bash
   cd network-intrusion-detection
   ```

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. *(Optional - Live Capture only)* Enable packet capture capabilities without root:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
   ```

---

## Running the Application

### Offline PCAP Analysis (Default)
To launch the interactive dashboard, run:
```bash
streamlit run app.py
```
Streamlit will launch locally and display the local URL:
```
Local URL: http://localhost:8501
Network URL: http://192.168.x.x:8501
```

1. Open `http://localhost:8501` in your browser.
2. In the sidebar under **PCAP File Ingestion**, click **"⚡ Demo Attacks"** to automatically generate and analyze a synthetic capture file.
3. Or upload any `.pcap` or `.pcapng` file using the file uploader and click **"Analyze Uploaded PCAP"**.

---

### Authorized Live Network Capture
Live monitoring captures packets directly from physical or virtual network interfaces:
1. **Windows Requirements**:
   - Install **Npcap** from [https://npcap.com/](https://npcap.com/) with the option **"Install Npcap in WinPcap API-compatible Mode"** enabled.
   - Run PowerShell / Command Prompt as **Administrator**.
2. In the dashboard sidebar, switch **Capture & Ingestion Mode** to **"Live Network Capture"**.
3. Select the desired network adapter from the dropdown.
4. Set packet count and timeout limits, then click **"🔴 Start Live Capture"**.

---

## Detection Engine Rules & Default Thresholds

| Threat Category | Default Threshold | Detection Logic | Severity Classification |
| :--- | :--- | :--- | :--- |
| **Port Scanning** | $> 20$ unique ports in $10.0$s | Cardinality of distinct destination ports probed by a single source IP in sliding window. | **High** if $\ge 40$ ports;<br>**Medium** otherwise. |
| **Suspected Brute-Force** | $> 10$ attempts in $60.0$s | Frequency of connection attempts / TCP SYN packets targeting sensitive services (SSH, RDP, FTP, MySQL). | **High** if critical service (SSH/RDP) or $\ge 20$ attempts;<br>**Medium** otherwise. |
| **Suspected Flooding** | $> 100$ packets in $5.0$s | Excessive packet rate ($>20$ pkts/s) from a single source host. | **High** if $\ge 200$ packets;<br>**Medium** otherwise. |
| **Normal Traffic** | Below thresholds | Regular web browsing, DNS queries, and background traffic. | **Normal / No Alert** |
| **Alert Cooldown** | $20.0$ seconds | Suppresses duplicate alerts for identical `(source_ip, attack_type, target)` during active bursts. | N/A |

*Note: All thresholds can be customized directly in the dashboard sidebar under **Rule Configuration**.*

---

## Dashboard Sections & Features

1. **System Health & SOC Banner**:
   - Displays real-time operational status: `SYSTEM HEALTHY`, `ELEVATED ACTIVITY`, or `CRITICAL THREATS DETECTED`.
2. **Executive Metric Cards**:
   - Total Packets Analyzed, Total Alerts, Port Scans, Brute-Force Indicators, and Flooding Alerts.
3. **🚨 Security Alerts Feed**:
   - Color-coded severity cards (Red for High, Amber for Medium, Green for Low).
   - Expandable JSON forensic evidence displaying triggering criteria and targeted ports.
   - Live filtering by attack category, severity, and source IP.
4. **📊 Traffic Analytics Tab**:
   - Interactive Plotly Donut chart for protocol distribution.
   - Time-series traffic volume timeline.
   - Top talkers (Source IPs) and targeted services (Destination Ports).
   - Threat breakdown charts.
5. **🔍 Packet Inspector Tab**:
   - Tabular grid of all parsed packets (source, destination, protocol, ports, size, TCP flags).
   - Filter by protocol, IP address search, or SYN-only packets.
6. **🗃️ Persistent Event History (SQLite)**:
   - Full audit trail stored in SQLite.
   - Filter by severity and attack category.
   - **CSV Export**: Direct one-click download of filtered security events.
7. **📖 Security & Methodology Tab**:
   - Detailed documentation on detection algorithms, permissions, and ethical guidelines.

---

## Running Unit Tests
A complete Pytest suite validates detection logic, baseline behavior, out-of-order timestamps, and database operations.

Run the test suite with:
```powershell
pytest -v
```

Expected test output:
```
tests/test_detection.py::test_normal_traffic_baseline PASSED
tests/test_detection.py::test_port_scan_detection_triggered PASSED
tests/test_detection.py::test_port_scan_below_threshold_ignored PASSED
tests/test_detection.py::test_brute_force_indicator_triggered PASSED
tests/test_detection.py::test_traffic_flooding_detection_triggered PASSED
tests/test_detection.py::test_duplicate_alert_suppression PASSED
tests/test_detection.py::test_out_of_order_timestamp_handling PASSED
tests/test_database.py::test_db_initialization_and_single_insert PASSED
tests/test_database.py::test_batch_insertion_and_filtering PASSED
tests/test_database.py::test_alert_counts_aggregation PASSED
tests/test_database.py::test_csv_export_and_clear PASSED
```

---

## Demonstration Guide

### Step 1: Generate Synthetic PCAP
Run the synthetic PCAP generator script:
```powershell
python data/generate_sample_pcap.py
```
This produces `data/sample_traffic.pcap` containing:
- 36 normal web & DNS packets from `192.168.1.20`.
- 25-port scan from attacker `192.168.1.105` against `192.168.1.50`.
- 15 repeated SSH connection attempts from `10.0.0.45` against `192.168.1.10`.
- 120-packet traffic flood from `172.16.0.99` against `192.168.1.1`.

### Step 2: View in Dashboard
1. Launch `streamlit run app.py`.
2. Click **"⚡ Demo Attacks"** in the sidebar.
3. Observe:
   - **Packets Analyzed**: ~196 packets.
   - **Total Alerts Detected**: 3 alerts.
   - **Port Scans Detected**: 1 (`192.168.1.105` probing 25 ports).
   - **Brute-Force Indicators**: 1 (`10.0.0.45` targeting SSH port 22).
   - **Traffic Floods**: 1 (`172.16.0.99` firing 120 packets).
4. Review the Plotly protocol charts, filter the alert feed, and download the CSV report.

---

## Security, Ethics & Privacy
- **Authorization**: Only monitor network communications on equipment you own or have explicit authorization to audit.
- **Defensive Design**: This system contains zero offensive exploit code, credential scanners, or denial-of-service tools.
- **Privacy Preservation**: The analyzer inspects packet headers and protocol metadata. Full packet payloads, credentials, and message contents are neither logged nor retained.
- **Indicator Nature**: TCP connection counts serve as preliminary operational indicators; confirming successful compromises requires inspecting application-level authorization logs.

---

## Known Limitations & Future Enhancements
- **Encrypted Payloads**: HTTPS/TLS payloads are encrypted; inspection relies purely on L3/L4 telemetry (IP, port, packet timing, size).
- **Asymmetric Routing**: In complex enterprise backbones, asymmetrical routing may require distributed sensor aggregation.
- **Future Enhancements**:
  - Integration with Snort/Suricata rule formats.
  - Machine-learning anomaly detection (e.g., Isolation Forests for volumetric deviations).
  - Webhook integration for Slack / Discord / PagerDuty incident alerting.
