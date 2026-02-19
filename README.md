# 💎 DiamondSecur v1.0
**Advanced Linux Security Auditor & Threat Hunter**  

[![GitHub stars](https://img.shields.io/github/stars/Devilman24/DiamondSecur?style=social)](https://github.com/Devilman24/DiamondSecur/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/Devilman24/DiamondSecur?style=social)](https://github.com/Devilman24/DiamondSecur/network)
[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Issues](https://img.shields.io/github/issues/Devilman24/DiamondSecur)](https://github.com/Devilman24/DiamondSecur/issues)
[![Workflow Status](https://img.shields.io/github/actions/workflow/status/Devilman24/DiamondSecur/python-app.yml?branch=main)](https://github.com/Devilman24/DiamondSecur/actions)
[![Hack the Planet](https://img.shields.io/badge/hacker-ready-red)](https://github.com/Devilman24/DiamondSecur)

---

## 🧩 About DiamondSecur

**DiamondSecur** is a lightweight but **powerful Linux security auditing tool**.  
It tracks suspicious behavior in **real-time**: reverse shells, rootkits, and system persistence.  
Designed for **hackers, sysadmins, and security enthusiasts** who want a quick and stealthy Linux scanner.  

---

## 🚀 Key Features

- **🔍 Directory Scan** – Scans for malicious scripts or files within a specific folder.  
- **⚡ Process Scan** – Analyzes running commands (searching for `-i`, `/dev/tcp`).  
- **🛡️ Rootkit Hunt** – Compares system APIs with visible processes to detect hidden ghosts.  
- **📡 Network Audit** – Lists suspicious ESTABLISHED sockets and non-standard port connections.  
- **🗝️ Check SUID Files** – Inspects SUID files for potential privilege escalation.  
- **📅 Check Crontab** – Lists scheduled tasks for current and system users.  

## 🛠️ Installation & Usage

### 1️⃣ Prerequisites
- **Python 3.10+**  
- Linux native commands: `ss`, `ps`, `find`  

### 2️⃣ Quick Setup
```bash
# Clone the repository
git clone https://github.com/Devilman24/DiamondSecur.git
cd DiamondSecur
```
# (Optional) Install dependencies
```text
pip install -r requirements.txt
```

### 3️⃣ Execution

For a full scan (including sensitive directories), run as root:
```bash
sudo python3 DiamondSecur.py
```

## 📊 Interactive Menu

Once launched, DiamondSecur provides a simple and intuitive interface:

| Option | Function | Description |
| :--- | :--- | :--- |
| **1** | `Directory Scan` | Scans for malicious scripts or files within a specific folder. |
| **2** | `Process Scan` | Analyzes running commands (searching for `-i`, `/dev/tcp`). |
| **3** | `Rootkit Hunt` | Compares system APIs with visible processes to detect hidden ghosts. |
| **4** | `Network Audit` | Lists suspicious ESTABLISHED sockets and non-standard port connections. |
| **5** | `Check SUID Files` | Inspects SUID files for potential privilege escalation. |
| **6** | `Check Crontab` | Lists scheduled tasks for current and system users. |
| **7** | `Exit` | Closes the tool safely. |

## 📁 Project Structure

```text
DiamondSecur/
├── DiamondSecur.py    # Main scanning engine (Python)
├── requirements.txt   # Minimal dependencies
├── scan_results.json  # Generated reports after scan
└── README.md          # Documentation
```

## ⚠️ Disclaimer

This tool is provided for educational and auditing purposes only.

The author is not responsible for any misuse or damage caused to your system.

###  Contribution & License

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

**Author:** [Devilman24](https://github.com/Devilman24)  
**License:** [MIT](LICENSE)

---
