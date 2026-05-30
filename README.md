# 🔍 Network Packet Sniffer & Analyzer

A real-time network packet capture and threat detection tool
built from scratch in Python. Captures live traffic, decodes
protocols, automatically detects suspicious patterns, and
generates a forensics-grade HTML report.

> Built as part of a cybersecurity portfolio.
> Inspired by Wireshark — but terminal-based, security-focused,
> and automated.

---

## ✨ Features

- 📡 **Live packet capture** — TCP, UDP, ICMP, ARP, DNS, HTTP
- 🎨 **Real-time dashboard** — color-coded terminal UI via Rich
- 🚨 **Automatic threat detection** — 5 detection engines:
  - Port scan detection
  - Brute force detection (SSH, FTP, RDP)
  - ARP spoofing detection
  - DNS tunneling detection
  - Suspicious port flagging (Metasploit, Tor, backdoors)
- 🔬 **Deep packet decoding** — HTTP credentials, DNS queries,
  TCP flags, ARP tables
- 📊 **HTML forensics report** — risk score, protocol stats,
  full packet log, threat timeline
- 🎯 **BPF filtering** — capture only what you need

---

## 🗂️ Project Structure

```
network-sniffer/
├── main.py             ← CLI entry point
├── sniffer.py          ← Core packet capture engine
├── decoder.py          ← Protocol decoding logic
├── detector.py         ← Threat detection engine
├── dashboard.py        ← Rich terminal UI
├── report_generator.py ← HTML report generation
├── requirements.txt    ← Dependencies
└── .gitignore
```

---

## ⚙️ Tech Stack

- **Python** — core language
- **Scapy** — packet capture and protocol decoding
- **Rich** — real-time terminal dashboard
- **Click** — professional CLI argument handling
- **Jinja2** — HTML report generation

---

## 🚀 How to Run

### Prerequisites

```bash
pip install -r requirements.txt
```

> ⚠️ **Must run as Administrator on Windows** for raw
> packet capture access.

### Basic usage

```bash
# Run with default interface
python main.py

# Specify interface
python main.py --interface Wi-Fi

# Capture only HTTP traffic
python main.py --filter "tcp port 80"

# Capture 100 packets then stop
python main.py --count 100

# Run for 30 seconds and generate report
python main.py --timeout 30 --report

# List available interfaces
python main.py --list-interfaces

# Simple mode without live dashboard
python main.py --no-dashboard
```

---

## 🚨 Threat Detection

| Threat | How Detected |
|---|---|
| Port Scan | 1 IP hits 10+ ports on same target |
| Brute Force | 20+ SYNs to same port in 3 seconds |
| ARP Spoofing | Same IP claims two different MACs |
| DNS Tunneling | DNS queries longer than 50 characters |
| Suspicious Ports | Metasploit (4444), Tor (9050), Telnet (23) |

---

## 📊 Report

Run with `--report` flag to generate a full HTML forensics
report after capture including:

- Risk score (0–100)
- Protocol breakdown
- Full threat alert timeline
- Last 100 packets log
- Unique source/destination IPs

---

## ⚠️ Legal Disclaimer

This tool is for **educational purposes and authorized
network monitoring only**. Only use on networks you own
or have explicit permission to monitor. Unauthorized
packet capture is illegal.

---

## ⚠️ Known Limitations

- HTTP decoding only works on unencrypted traffic (port 80)
- HTTPS (port 443) payload is encrypted and cannot be decoded
- Requires Administrator/root privileges
- Performance may vary on high-traffic networks

---

## 👤 Author

**Arsalan Khan Pathan** | B-Tech EXTC | Cybersecurity Enthusiast
GitHub: [@ArsalanKhan-76](https://github.com/ArsalanKhan-76)