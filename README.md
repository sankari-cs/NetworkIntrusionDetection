# ðŸ›¡ï¸ Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System that monitors live network traffic, detects suspicious activities in real time, and visualises alerts on an interactive dashboard.


---

## ðŸ“‹ Table of Contents

- [Features](#-features)
- [Detection Rules](#-detection-rules)
- [Architecture](#-architecture)
- [Technologies](#-technologies)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sample Output](#-sample-output)
- [Testing](#-testing)
- [Project Structure](#-project-structure)
- [Limitations](#-limitations)
- [Future Improvements](#-future-improvements)
- [Author](#-author)
- [License](#-license)

---

## âœ¨ Features

| Feature | Description |
|---|---|
| **Live packet capture** | Sniffs TCP / UDP / ICMP packets using Scapy + Npcap on Windows |
| **Real-time detection** | Five independent detection rules with configurable thresholds |
| **Alert persistence** | Every alert saved to `logs/alerts.csv` **and** `logs/alerts.json` |
| **Interactive dashboard** | Streamlit + Matplotlib â€” KPIs, pie/bar/line charts, filterable table, CSV export |
| **Configurable rules** | All thresholds in `rules/detection_rules.json` â€” no code edits needed |
| **Loopback support** | Detects attacks against `127.0.0.1` for safe lab testing |
| **Self-testing** | Built-in `--synthetic` mode + 5 automated test scenarios |
| **Cooldown suppression** | Prevents alert floods from a single source |

---

## ðŸŽ¯ Detection Rules

| Rule | Trigger | Default threshold | Severity |
|---|---|---|---|
| **PORT_SCAN** | One source sends SYNs to many distinct destination ports | â‰¥ 10 ports / 10 s | HIGH |
| **REPEATED_CONNECTIONS** | Many SYNs to the same target from one source | â‰¥ 15 attempts / 10 s | MEDIUM |
| **POSSIBLE_DOS** | High packet rate from one source | â‰¥ 150 packets / 3 s | HIGH |
| **SUSPICIOUS_PORT** | Traffic to a risky port (telnet, SMB, RDP, etc.) | Any | LOW |
| **NULL_SCAN** | TCP packet with no flags set | Any | HIGH |

All thresholds are editable in `rules/detection_rules.json`.

---

## ðŸ—ï¸ Architecture

## ðŸ—ï¸ Architecture
Network Interface (Wi-Fi / Ethernet / Loopback)
â”‚
â–¼
packet_sniffer.py Scapy + Npcap
â€¢ capture â€¢ parse IP / protocol
â€¢ extract ports â€¢ timestamp
â”‚
â–¼ flat dict per packet
intrusion_detector.py 5 stateful rules + 30 s cooldown
â€¢ port scan â€¢ repeated connections
â€¢ DoS rate â€¢ suspicious port
â€¢ null scan
â”‚
â–¼ alert dicts
alert_manager.py
â€¢ logs/alerts.csv
â€¢ logs/alerts.json
â”‚
â–¼
dashboard/app.py Streamlit
â€¢ KPIs â€¢ charts â€¢ filterable table

text

---

## ðŸ§° Technologies

- **Python 3.11** â€” core language
- **Scapy 2.8** â€” packet capture and parsing
- **Npcap** â€” Windows packet capture driver (required)
- **Streamlit 1.66** â€” interactive dashboard
- **Pandas 3.1** â€” data handling
- **Matplotlib 3.11** â€” charts
- **Git / GitHub** â€” version control

---

## âš™ï¸ Installation

### Prerequisites

1. **Windows 10/11** (Linux/macOS also work â€” see notes below)
2. **Python 3.8+** on PATH â€” [python.org](https://www.python.org/downloads/windows/)
3. **Npcap 1.90+** installed as Administrator â€” [npcap.com](https://npcap.com/)
   - Leave "WinPcap API-compatible Mode" **checked** (default)
   - Leave "Restrict to Administrators" **checked** (default)

### Setup

```powershell
git clone https://github.com/sankari-cs/NetworkIntrusionDetection.git
cd CodeAlpha_NetworkIntrusionDetection

python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt

# Verify Scapy sees Npcap
python -c "from scapy.all import conf; print('use_pcap =', conf.use_pcap)"
# Expected: use_pcap = True
Linux / macOS note
Npcap is Windows-only. On Linux/macOS, install libpcap:

bash
sudo apt install libpcap-dev    # Ubuntu/Debian
brew install libpcap            # macOS
Run capture with sudo python main.py (raw sockets require root).

ðŸš€ Usage
Quick self-test (no admin, no network capture)
powershell
python main.py --synthetic
Feeds 15 scripted packets through the real pipeline. Expect 3 alerts.

Print current alert stats
powershell
python main.py --stats
Clear all logs
powershell
python main.py --clear
Live capture (requires Administrator PowerShell)
powershell
# Default interface
python main.py

# Specific interface
python main.py --iface "Wi-Fi"

# Loopback (for localhost testing)
python main.py --iface "Loopback Pseudo-Interface 1" --filter "tcp"

# Stop after 60 seconds
python main.py --duration 60

# Stop after 500 packets
python main.py --limit 500
Launch the dashboard
powershell
python -m streamlit run .\dashboard\app.py
Opens http://localhost:8501 in your browser.

ðŸ“Š Sample Output
Live detection (loopback attack)
text
[ HIGH ] PORT_SCAN              127.0.0.1:52341 -> 127.0.0.1:15009  distinct_ports=10, window_seconds=10
[ LOW  ] SUSPICIOUS_PORT        127.0.0.1:52342 -> 127.0.0.1:23     dst_port=23, port_name=telnet
[ LOW  ] SUSPICIOUS_PORT        127.0.0.1:52343 -> 127.0.0.1:445    dst_port=445, port_name=smb
[ LOW  ] SUSPICIOUS_PORT        127.0.0.1:52344 -> 127.0.0.1:3389   dst_port=3389, port_name=rdp
[ HIGH ] REPEATED_CONNECTIONS   127.0.0.1:52350 -> 127.0.0.1:9999   attempts=15, window_seconds=10

======================================================================
 NIDS SESSION SUMMARY
======================================================================
 Packets processed : 287
 Alerts raised     : 5
 Alerts by type    :
     SUSPICIOUS_PORT          3
     PORT_SCAN                1
     REPEATED_CONNECTIONS     1
 Logs              : logs/alerts.csv, logs/alerts.json
======================================================================
Synthetic mode
text
$ python main.py --synthetic
Synthetic mode - piping 15 fake packets through the real pipeline.

[ HIGH ] PORT_SCAN              10.0.0.99:50009 -> 10.0.0.1:10009  distinct_ports=10
[ LOW  ] SUSPICIOUS_PORT        10.0.0.10:40000 -> 10.0.0.4:23     dst_port=23, port_name=telnet
[ LOW  ] SUSPICIOUS_PORT        10.0.0.11:40001 -> 10.0.0.5:445    dst_port=445, port_name=smb

 Packets processed : 14
 Alerts raised     : 3
Dashboard
https://screenshots/dashboard.png

âœ… Testing
Automated tests (all included in source files)
Test suite	Command	Expected
Intrusion detector	python intrusion_detector.py	5/5 scenarios PASS
Alert manager	python alert_manager.py	9/9 checks PASS
End-to-end pipeline	python main.py --synthetic	3 alerts raised
Manual test scenarios
Scenario	How to reproduce	Expected
Normal traffic	Browse the web while running main.py	0 alerts
Port scan	Connect to 15 distinct localhost ports	PORT_SCAN
Repeated connections	20Ã— Connect('127.0.0.1', 9999)	REPEATED_CONNECTIONS
Suspicious port	Connect('127.0.0.1', 23)	SUSPICIOUS_PORT
DoS pattern	High-rate traffic from one source	POSSIBLE_DOS
All testing was done against localhost / private lab only â€” no public targets.

ðŸ“ Project Structure
text
CodeAlpha_NetworkIntrusionDetection/
â”œâ”€â”€ main.py                    # Entry point â€” wires everything together
â”œâ”€â”€ packet_sniffer.py          # Scapy capture + parsing
â”œâ”€â”€ intrusion_detector.py      # 5 detection rules + self-test
â”œâ”€â”€ alert_manager.py           # CSV/JSON persistence + self-test
â”œâ”€â”€ rules/
â”‚   â””â”€â”€ detection_rules.json   # Configurable thresholds
â”œâ”€â”€ dashboard/
â”‚   â””â”€â”€ app.py                 # Streamlit dashboard
â”œâ”€â”€ logs/                      # Runtime alerts (gitignored, except .gitkeep)
â”œâ”€â”€ reports/                   # Exported reports
â”œâ”€â”€ screenshots/               # Dashboard + session screenshots
â”œâ”€â”€ requirements.txt
â”œâ”€â”€ .gitignore
â”œâ”€â”€ LICENSE
â””â”€â”€ README.md
âš ï¸ Limitations
Windows-first: tested on Windows 11 with Npcap. Linux/macOS work but require libpcap + root.

IPv4 only: IPv6 packets are currently ignored.

Rule-based: uses fixed thresholds rather than ML. Simple to audit; easier to evade.

Single-threaded detection: suitable for moderate traffic; high-throughput links would need a queue.

No PCAP export: alerts are logged, but raw packets aren't saved. Wireshark is recommended for deep analysis.

Npcap free edition licensed for up to 5 systems (see npcap.com).

ðŸ”® Future Improvements
ML anomaly detection â€” Isolation Forest or LSTM to catch unknown attack patterns

IPv6 support â€” parse and detect on IPv6 traffic

Email/Slack notifications â€” real-time alerts outside the dashboard

PCAP retention â€” save raw packets for post-incident forensics

GeoIP enrichment â€” map source IPs to countries

Suricata integration â€” use community rulesets in parallel

Docker deployment â€” one-command start on any OS

S

ðŸ‘¤ Author
[Sankari A]
LinkedIn Â· GitHub

ðŸ“„ License
MIT License â€” see LICENSE file for details.

