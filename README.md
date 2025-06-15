# 🌐 Network Packet Analyzer

This is a simple Python-based packet sniffer that captures and analyzes network traffic in real-time.

Completed as **Task-05** for the **Cyber Security Internship Program** at **Prodigy InfoTech**.

## ⚠️ Ethical Disclaimer

This tool is built **strictly for educational purposes**.  
Use it **only** on networks you own or have explicit permission to monitor. Unauthorized sniffing is illegal.

## ✅ Features

- Captures live network packets using `scapy`.
- Displays:
  - Source and Destination IP addresses
  - Protocol (TCP/UDP)
  - First 50 bytes of the payload (if available)

## 📦 Requirements

- Python 3.x
- Scapy  
Install it with:
```bash
pip install scapy
