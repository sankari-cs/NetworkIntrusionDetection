# Network Intrusion Detection System (NIDS)

A Python-based **Network Intrusion Detection System (NIDS)** that monitors live network traffic, identifies suspicious activities in real time, and generates security alerts through an interactive monitoring dashboard.

The system uses Scapy for packet capture and a configurable rule-based detection engine to identify common network attack patterns, including port scanning, repeated connection attempts, potential denial-of-service activity, suspicious port access, and TCP NULL scans.

It also provides persistent alert logging, synthetic testing, and data visualization to support network security monitoring and analysis.

---

## Table of Contents

1. [Features](#features)
2. [Detection Rules](#detection-rules)
3. [System Architecture](#system-architecture)
4. [Technologies Used](#technologies-used)
5. [Installation](#installation)
6. [Usage](#usage)
7. [Sample Output](#sample-output)
8. [Testing](#testing)
9. [Project Structure](#project-structure)
10. [Limitations](#limitations)
11. [Future Improvements](#future-improvements)
12. [Author](#author)
13. [License](#license)

---

## Features

| Feature | Description |
|---|---|
| Live Packet Capture | Captures TCP, UDP, and ICMP network packets using Scapy and Npcap on Windows. |
| Real-Time Detection | Identifies suspicious network activities using five independent detection rules. |
| Alert Persistence | Stores generated security alerts in CSV and JSON formats. |
| Interactive Dashboard | Provides security KPIs, charts, alert filtering, and CSV export using Streamlit and Matplotlib. |
| Configurable Detection Rules | Allows detection thresholds to be modified through `rules/detection_rules.json`. |
| Loopback Support | Supports localhost monitoring for safe security testing. |
| Synthetic Testing | Includes a synthetic packet mode for testing without live network capture. |
| Automated Test Scenarios | Provides built-in tests for detection rules and alert management. |
| Alert Cooldown | Reduces duplicate alerts using a configurable cooldown mechanism. |

---

## Detection Rules

The system implements five independent rule-based detection mechanisms.

| Detection Rule | Description | Default Threshold | Severity |
|---|---|---|---|
| `PORT_SCAN` | Detects a source sending TCP SYN packets to multiple distinct destination ports. | 10 or more ports within 10 seconds | HIGH |
| `REPEATED_CONNECTIONS` | Identifies repeated TCP SYN connection attempts from one source to the same destination. | 15 or more attempts within 10 seconds | MEDIUM |
| `POSSIBLE_DOS` | Detects unusually high packet rates originating from a single source. | 150 or more packets within 3 seconds | HIGH |
| `SUSPICIOUS_PORT` | Identifies traffic directed toward predefined potentially risky service ports. | Any matching packet | LOW |
| `NULL_SCAN` | Detects TCP packets containing no TCP control flags. | Any matching packet | HIGH |

### Monitored Suspicious Ports

Examples include:

- **23** - Telnet
- **445** - SMB
- **3389** - Remote Desktop Protocol (RDP)
The complete suspicious-port list and detection thresholds are configurable.

**Configuration file:** `rules/detection_rules.json`

---

## System Architecture

The system follows a modular architecture consisting of packet capture, intrusion detection, alert management, and dashboard visualization.

```text
+------------------------------------------+
|           Network Interface              |
|        Wi-Fi / Ethernet / Loopback       |
+--------------------+---------------------+
                     |
                     v
+------------------------------------------+
|             packet_sniffer.py            |
|                                          |
|  - Captures network packets              |
|  - Parses IP and protocol information    |
|  - Extracts source/destination ports     |
+--------------------+---------------------+
                     |
                     | Parsed packet data
                     v
+------------------------------------------+
|           intrusion_detector.py          |
|                                          |
|  - PORT_SCAN                             |
|  - REPEATED_CONNECTIONS                  |
|  - POSSIBLE_DOS                          |
|  - SUSPICIOUS_PORT                       |
|  - NULL_SCAN                             |
|  - Alert cooldown management             |
+--------------------+---------------------+
                     |
                     | Generated alerts
                     v
+------------------------------------------+
|              alert_manager.py            |
|                                          |
|  - CSV alert persistence                 |
|  - JSON alert persistence                |
|  - Alert statistics                      |
+--------------------+---------------------+
                     |
                     v
+------------------------------------------+
|             dashboard/app.py             |
|              Streamlit                   |
|                                          |
|  - Security KPIs                         |
|  - Alert distribution charts             |
|  - Time-based visualizations             |
|  - Filterable alert table                |
|  - CSV export                             |
+------------------------------------------+
```

### Processing Workflow

1. **Packet Capture:** Scapy captures network traffic from the selected interface.
2. **Packet Parsing:** Relevant IP addresses, protocols, and port information are extracted.
3. **Intrusion Detection:** The detection engine evaluates packet data against configured security rules.
4. **Alert Generation:** Suspicious activities generate structured security alerts.
5. **Alert Storage:** Alerts are saved in CSV and JSON formats.
6. **Visualization:** Streamlit presents alert statistics and visualizations through an interactive dashboard.

---

## Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.11 | Core programming language |
| Scapy 2.8 | Network packet capture and parsing |
| Npcap | Windows packet capture driver |
| Streamlit 1.66 | Interactive security dashboard |
| Pandas 3.1 | Alert data processing and analysis |
| Matplotlib 3.11 | Data visualization |
| Git and GitHub | Version control and project hosting |

---

## Installation

### Prerequisites

- Windows 10 or Windows 11 (primary tested environment).
- Python 3.8 or later.
- Git.
- Npcap 1.90 or later for Windows packet capture.
- Administrator privileges for live packet capture.

### Step 1: Install Npcap

Download and install Npcap:

https://npcap.com/

During installation:

- Keep **WinPcap API-compatible Mode** enabled.
- Keep **Restrict to Administrators** enabled.
- Complete the installation using administrator privileges.

### Step 2: Clone the Repository

```powershell
git clone https://github.com/sankari-cs/NetworkIntrusionDetection.git

cd NetworkIntrusionDetection
```

### Step 3: Create a Virtual Environment

```powershell
python -m venv .venv
```

### Step 4: Activate the Virtual Environment

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

.\.venv\Scripts\Activate.ps1
```

### Step 5: Install Dependencies

```powershell
pip install -r requirements.txt
```

### Step 6: Verify Npcap Support

```powershell
python -c "from scapy.all import conf; print('use_pcap =', conf.use_pcap)"
```

Expected output:

```text
use_pcap = True
```

---

### Linux and macOS Support

Npcap is specific to Windows. Linux and macOS systems use libpcap-compatible packet capture support.

For Ubuntu/Debian:

```bash
sudo apt update
sudo apt install libpcap-dev
```

For macOS with Homebrew:

```bash
brew install libpcap
```

Live packet capture may require elevated privileges depending on the operating system and capture configuration.

---

## Usage

### 1. Run Synthetic Mode

Synthetic mode processes predefined test packets through the detection pipeline without requiring administrator privileges or live network capture.

```powershell
python main.py --synthetic
```

Expected behavior:

- Processes synthetic packet data.
- Executes the actual detection pipeline.
- Generates alerts for predefined suspicious activities.
- Saves alerts to CSV and JSON files.

### 2. Display Alert Statistics

```powershell
python main.py --stats
```

Displays the current alert statistics.

### 3. Clear Alert Logs

```powershell
python main.py --clear
```

Clears the existing alert logs.

**Note:** This operation removes previously recorded alert data.

### 4. Start Live Packet Capture

Open PowerShell as Administrator and activate the virtual environment.

**Capture using the default interface:**

```powershell
python main.py
```

**Capture using a specific network interface:**

```powershell
python main.py --iface "Wi-Fi"
```

**Capture loopback traffic:**

```powershell
python main.py --iface "Loopback Pseudo-Interface 1" --filter "tcp"
```

**Capture for a specified duration:**

```powershell
python main.py --duration 60
```

**Stop after processing a specified number of packets:**

```powershell
python main.py --limit 500
```

### 5. Launch the Interactive Dashboard

Open another PowerShell terminal, activate the virtual environment, and execute:

```powershell
python -m streamlit run .\dashboard\app.py
```

Open the following address in your browser:

http://localhost:8501

The dashboard provides:

- Total packets and alert statistics.
- Alert severity distribution.
- Detection-rule distribution charts.
- Time-based alert visualizations.
- Filterable security alert records.
- CSV export functionality.

---

## Sample Output

### Live Detection Example

The following output illustrates suspicious activities detected during localhost testing.

```text
[ HIGH ] PORT_SCAN
127.0.0.1:52341 -> 127.0.0.1:15009
distinct_ports=10, window_seconds=10

[ LOW  ] SUSPICIOUS_PORT
127.0.0.1:52342 -> 127.0.0.1:23
dst_port=23, port_name=telnet

[ LOW  ] SUSPICIOUS_PORT
127.0.0.1:52343 -> 127.0.0.1:445
dst_port=445, port_name=smb

[ LOW  ] SUSPICIOUS_PORT
127.0.0.1:52344 -> 127.0.0.1:3389
dst_port=3389, port_name=rdp

[ HIGH ] REPEATED_CONNECTIONS
127.0.0.1:52350 -> 127.0.0.1:9999
attempts=15, window_seconds=10
```

### Session Summary

```text
======================================================================
                     NIDS SESSION SUMMARY
======================================================================

Packets processed : 287
Alerts raised     : 5

Alerts by type:

SUSPICIOUS_PORT          3
PORT_SCAN                1
REPEATED_CONNECTIONS     1

Logs:
logs/alerts.csv
logs/alerts.json

======================================================================
```

### Synthetic Mode Output

Command:

```powershell
python main.py --synthetic
```

Example:

```text
Synthetic mode - piping 15 fake packets through the real pipeline.

[ HIGH ] PORT_SCAN
10.0.0.99:50009 -> 10.0.0.1:10009
distinct_ports=10

[ LOW  ] SUSPICIOUS_PORT
10.0.0.10:40000 -> 10.0.0.4:23
dst_port=23, port_name=telnet

[ LOW  ] SUSPICIOUS_PORT
10.0.0.11:40001 -> 10.0.0.5:445
dst_port=445, port_name=smb

Packets processed : 14
Alerts raised     : 3
```

*Note: Sample outputs are illustrative. Actual packet counts and alerts depend on the traffic and test configuration.*

---

## Testing

The project includes built-in tests for the detection engine, alert manager, and complete detection pipeline.

### Automated Tests

| Test Component | Command | Expected Result |
|---|---|---|
| Intrusion Detector | `python intrusion_detector.py` | 5/5 scenarios PASS |
| Alert Manager | `python alert_manager.py` | 9/9 checks PASS |
| End-to-End Pipeline | `python main.py --synthetic` | 3 alerts generated |

### Manual Testing Scenarios

| Scenario | Testing Method | Expected Detection |
|---|---|---|
| Normal Traffic | Browse websites while monitoring traffic. | No suspicious alerts under normal conditions. |
| Port Scan | Send SYN packets to 15 distinct localhost ports. | `PORT_SCAN` |
| Repeated Connections | Attempt 20 connections to `127.0.0.1:9999`. | `REPEATED_CONNECTIONS` |
| Suspicious Port | Generate traffic to localhost port 23. | `SUSPICIOUS_PORT` |
| DoS Pattern | Generate a high packet rate from a single test source. | `POSSIBLE_DOS` |

All security testing should be performed against localhost, private lab environments, or systems for which explicit authorization has been obtained.

---

## Project Structure

```text
NetworkIntrusionDetection/
|
|-- main.py
|-- packet_sniffer.py
|-- intrusion_detector.py
|-- alert_manager.py
|
|-- rules/
|   |-- detection_rules.json
|
|-- dashboard/
|   |-- app.py
|
|-- logs/
|   |-- .gitkeep
|
|-- reports/
|
|-- requirements.txt
|-- .gitignore
|-- LICENSE
|-- README.md
```

### Main Components

| File | Responsibility |
|---|---|
| `main.py` | Application entry point and pipeline orchestration. |
| `packet_sniffer.py` | Captures and parses network packets using Scapy. |
| `intrusion_detector.py` | Implements the five intrusion detection rules. |
| `alert_manager.py` | Handles alert generation, storage, and statistics. |
| `rules/detection_rules.json` | Stores configurable detection thresholds. |
| `dashboard/app.py` | Implements the Streamlit monitoring dashboard. |
| `logs/` | Stores generated CSV and JSON alert logs. |
| `reports/` | Stores exported reports. |
| `requirements.txt` | Lists Python dependencies. |

---

## Limitations

1. **Windows-First Implementation:** The project was primarily developed and tested on Windows 11 using Npcap. Linux and macOS require their respective packet capture dependencies and permissions.

2. **IPv4 Support:** The current implementation focuses on IPv4 traffic. IPv6 packet analysis is not currently supported.

3. **Rule-Based Detection:** Detection relies on predefined rules and fixed thresholds. Sophisticated attacks may evade these rules.

4. **Single-Threaded Processing:** The current detection pipeline is designed for moderate traffic volumes. High-throughput environments may require asynchronous or parallel processing.

5. **No PCAP Retention:** The system stores security alerts but does not currently maintain raw packet capture files for forensic analysis.

6. **Potential False Positives:** Legitimate high-volume connections or unusual network behavior may trigger alerts.

---

## Future Improvements

The following enhancements are planned for future versions:

- **Machine Learning Integration:** Implement Isolation Forest or other anomaly detection algorithms to identify previously unseen network behavior.
- **IPv6 Support:** Extend packet parsing and detection capabilities to IPv6 networks.
- **Email and Slack Notifications:** Send real-time alerts to external notification channels.
- **PCAP Retention:** Introduce packet capture storage for forensic investigation.
- **GeoIP Enrichment:** Add geographic information for publicly routable source IP addresses.
- **Suricata Integration:** Integrate Suricata for signature-based intrusion detection.
- **Docker Deployment:** Provide containerized deployment for easier setup and portability.
- **Advanced Analytics:** Introduce historical traffic analysis and detection performance metrics.

---

## Author

**Sankari A**

B.Sc. Computer Science with Cyber Security

GitHub: [sankari-cs](https://github.com/sankari-cs)

---

## License

This project is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for details.

---

**Disclaimer:** This project is developed for educational purposes, cybersecurity learning, and authorized network monitoring. Do not use it to monitor or test networks without appropriate permission.
