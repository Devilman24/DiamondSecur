# ==========================================
# DiamondSecur
# Advanced Linux Security Scanner
# Author: Devilman24
# Version: 1.0
# ==========================================

import os
import re
import hashlib
import json
import subprocess
import ipaddress
from datetime import datetime, timedelta

# =========================
# METADATA
# =========================

TOOL_NAME = "DiamondSecur"
VERSION = "1.0"
AUTHOR = "Devilman24"

# =========================
# CONFIGURATION
# =========================

RECENT_DAYS = 7
MAX_FILE_SIZE = 5 * 1024 * 1024

EXCLUDED_DIRS = ["/proc", "/sys", "/dev", "/run"]
SENSITIVE_PATHS = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]

SUSPICIOUS_PORTS = {"4444", "1337", "6666", "9001"}

dangerous_patterns = [
    r"rm\s+-rf\s+\/",
    r":\s*(){\s*:|\s*;};",
    r"wget\s+http",
    r"curl\s+http",
    r"nc\s+-e",
    r"/dev/tcp/\S+/\d+",
    r"useradd\s+",
    r"chattr\s+\+i",
    r"eval\s+",
    r"base64\s+-d",
    r"openssl\s+enc",
]

reverse_shell_patterns = [
    r"nc\s+.*-e",
    r"bash\s+-i",
    r"python\s+-c",
    r"perl\s+-e",
    r"php\s+-r",
    r"ruby\s+-e",
]

compiled_patterns = [re.compile(p) for p in dangerous_patterns]
compiled_reverse_shell = [re.compile(p) for p in reverse_shell_patterns]

# =========================
# UTILITIES
# =========================

def is_root():
    return os.getuid() == 0


def hash_file(filepath):
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None


def is_recent(filepath, days=RECENT_DAYS):
    try:
        return datetime.now() - datetime.fromtimestamp(
            os.path.getmtime(filepath)
        ) < timedelta(days=days)
    except:
        return False


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return True

# =========================
# FILE SCAN
# =========================

def scan_file(filepath):
    if not os.path.isfile(filepath):
        return []

    if os.path.getsize(filepath) > MAX_FILE_SIZE:
        return []

    if filepath.endswith((".png", ".jpg", ".jpeg", ".gif", ".so", ".bin", ".exe")):
        return []

    findings = []

    try:
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                for pattern in compiled_patterns:
                    if pattern.search(line):
                        findings.append(f"Dangerous Pattern: {pattern.pattern}")
                        return findings
    except:
        pass

    return findings


def scan_directory(directory):
    directory = os.path.expanduser(directory)

    if not os.path.isdir(directory):
        print("❌ Invalid directory.")
        return {}

    report = {}

    for root, _, files in os.walk(directory):

        if any(root.startswith(ex) for ex in EXCLUDED_DIRS):
            continue

        for file in files:
            filepath = os.path.join(root, file)

            try:
                findings = []
                risk_score = 0

                pattern_hits = scan_file(filepath)
                recent = is_recent(filepath)

                if pattern_hits:
                    findings.extend(pattern_hits)
                    risk_score += 5

                if recent and any(filepath.startswith(p) for p in SENSITIVE_PATHS):
                    findings.append("Recently modified (Sensitive Zone)")
                    risk_score += 3

                if risk_score == 0:
                    continue

                report[filepath] = {
                    "hash": hash_file(filepath),
                    "risk_score": risk_score,
                    "findings": findings
                }

            except PermissionError:
                continue

    return report

# =========================
# PROCESS SCAN
# =========================

def scan_processes():
    suspicious = []

    try:
        result = subprocess.run(["ps", "aux"], stdout=subprocess.PIPE, text=True)
        for line in result.stdout.splitlines():

            for pattern in compiled_reverse_shell:
                if pattern.search(line):
                    suspicious.append(f"Reverse shell detected: {line}")

            if "/tmp/" in line or "/dev/shm/" in line:
                suspicious.append(f"Process launched from temporary directory: {line}")

    except Exception as e:
        suspicious.append(f"Process scan error: {e}")

    return suspicious

# =========================
# ROOTKIT DETECTION
# =========================

def detect_rootkits():
    findings = []

    try:
        proc_ids = {p for p in os.listdir("/proc") if p.isdigit()}
        result = subprocess.run(["ps", "-e"], stdout=subprocess.PIPE, text=True)
        ps_ids = set(re.findall(r"^\s*(\d+)", result.stdout, re.MULTILINE))

        hidden = proc_ids - ps_ids

        if hidden:
            findings.append(f"Potentially hidden processes: {list(hidden)[:10]}")
        else:
            findings.append("No hidden processes detected.")

    except:
        findings.append("Unable to detect hidden processes.")

    return findings

# =========================
# NETWORK SCAN
# =========================

def scan_ports_connections():
    findings = []

    try:
        result = subprocess.run(["ss", "-tunap"], stdout=subprocess.PIPE, text=True)

        for line in result.stdout.splitlines():
            if "ESTAB" not in line:
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            remote = parts[4]

            if ":" in remote:
                ip, port = remote.rsplit(":", 1)

                if port in SUSPICIOUS_PORTS:
                    findings.append(f"Connection to suspicious port {port}: {line}")
                elif not is_private_ip(ip):
                    findings.append(f"External connection detected: {line}")

        if not findings:
            findings.append("No suspicious connections detected.")

    except:
        findings.append("Unable to analyze network connections.")

    return findings

# =========================
# EXTRA CHECKS
# =========================

def check_suid_files():
    findings = []

    try:
        result = subprocess.run(
            ["find", "/", "-perm", "-4000", "-type", "f"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        suid_files = result.stdout.splitlines()

        if suid_files:
            findings.append("SUID files detected:")
            findings.extend(suid_files[:20])
        else:
            findings.append("No SUID files found.")

    except Exception as e:
        findings.append(f"SUID check error: {e}")

    return findings


def check_crontab():
    findings = []

    try:
        result = subprocess.run(["crontab", "-l"],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)

        if result.returncode == 0 and result.stdout.strip():
            findings.append("User Crontab:")
            findings.append(result.stdout.strip())
        else:
            findings.append("No user crontab found.")
    except:
        findings.append("Unable to read user crontab.")

    cron_paths = ["/etc/crontab", "/etc/cron.d"]

    for path in cron_paths:
        if os.path.exists(path):
            findings.append(f"Present: {path}")

    return findings

# =========================
# SAVE REPORT
# =========================

def save_report(report, filename):
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"✅ Report saved: {filename}")

# =========================
# MAIN
# =========================

def main():

    print("\n" + "="*45)
    print(f"{TOOL_NAME} v{VERSION}")
    print("Advanced Linux Security Scanner")
    print(f"Author: {AUTHOR}")
    print("="*45)

    if not is_root():
        print("⚠ Warning: It is recommended to run this script as root for a full scan.\n")

    while True:
        print("\n1. Scan a directory")
        print("2. Scan processes")
        print("3. Rootkit detection")
        print("4. Network scan")
        print("5. Check SUID files")
        print("6. Check crontab")
        print("7. Exit")

        choice = input("Choice: ")

        if choice == "1":
            directory = input("Directory: ")
            report = scan_directory(directory)
            print(f"{len(report)} suspicious files detected.")
            save_report(report, "scan_report.json")

        elif choice == "2":
            for r in scan_processes():
                print(r)

        elif choice == "3":
            for r in detect_rootkits():
                print(r)

        elif choice == "4":
            for r in scan_ports_connections():
                print(r)

        elif choice == "5":
            for r in check_suid_files():
                print(r)

        elif choice == "6":
            for r in check_crontab():
                print(r)

        elif choice == "7":
            print("Exiting...")
            break

        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
