#!/usr/bin/env python3
"""
Cloud Security Audit Tool (Phase-1 Project) - Enhanced Version

Author: Yousuf Khan
Objective: Phase-1 portfolio-ready project for AI-Enabled Cloud Network Security Automation Roadmap
Description: 
    This tool performs a basic security audit of a target system.
    Features include:
    - SSH service status check (macOS/Linux)
    - Running services check (top 10)
    - TCP port scanning (supports custom ports and ranges)
    - Generates color-coded terminal output
    - Logs all output to a timestamped log file
    - Saves a timestamped report for portfolio demonstration
Usage:
    python3 main_audit.py [--target <IP>] [--ports 22 80 443 1000-1010] [--output-dir <folder>]
"""

import subprocess
from datetime import datetime
import socket
import logging
import platform
import argparse
import ipaddress
import os
import re  # for parsing port ranges

# ----------------------
# CLI Arguments
# ----------------------
parser = argparse.ArgumentParser(description="Cloud Security Audit Tool")
parser.add_argument(
    "--target",
    type=str,
    default="127.0.0.1",
    help="Target IP to scan (default: 127.0.0.1)"
)
parser.add_argument(
    "--ports",
    type=str,
    nargs="+",
    default=["22","80","443","5000","5432"],
    help="Ports to scan (support ranges e.g., 20-25 80 443)"
)
parser.add_argument(
    "--output-dir",
    type=str,
    default=".",
    help="Directory to save report and log files (default: current folder)"
)
args = parser.parse_args()

target_ip = args.target
raw_ports = args.ports
output_dir = args.output_dir

# ----------------------
# Ensure output directory exists
# ----------------------
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# ----------------------
# Validate IP address
# ----------------------
try:
    ipaddress.ip_address(target_ip)
except ValueError:
    print(f"Invalid target IP: {target_ip}")
    exit(1)

# ----------------------
# Parse ports (support ranges like 20-25)
# ----------------------
ports_to_scan = []
for port_str in raw_ports:
    if '-' in port_str:
        start, end = port_str.split('-')
        ports_to_scan.extend(range(int(start), int(end)+1))
    else:
        ports_to_scan.append(int(port_str))
ports_to_scan = sorted(set(ports_to_scan))  # remove duplicates

# ----------------------
# Logging Setup
# ----------------------
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_filename = f"{output_dir}/security_audit_log_{timestamp}.txt"

logging.basicConfig(
    filename=log_filename,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode='w'
)

# ----------------------
# Terminal Colors
# ----------------------
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# ----------------------
# Detect Operating System
# ----------------------
current_os = platform.system()
logging.info(f"Detected OS: {current_os}")

# ----------------------
# SSH Service Check
# ----------------------
def check_ssh_status():
    try:
        if current_os == "Darwin":
            cmd = ["systemsetup", "-getremotelogin"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            status = "ENABLED" if "On" in result.stdout else "DISABLED"
        elif current_os == "Linux":
            result = subprocess.run(["systemctl", "is-active", "ssh"], capture_output=True, text=True)
            status = "ENABLED" if result.stdout.strip() == "active" else "DISABLED"
        else:
            return f"{Colors.WARNING}Unsupported OS for SSH check{Colors.ENDC}"

        msg = f"SSH Service: {status}"
        logging.info(msg)
        color = Colors.FAIL if status == "ENABLED" else Colors.OKGREEN
        return f"{color}{msg}{Colors.ENDC}"

    except Exception as e:
        error_msg = f"SSH Service: ERROR - {e}"
        logging.error(error_msg)
        return f"{Colors.WARNING}{error_msg}{Colors.ENDC}"

# ----------------------
# Running Services Check
# ----------------------
def check_running_services():
    try:
        if current_os == "Darwin":
            result = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
            services = result.stdout.strip().split("\n")
        elif current_os == "Linux":
            result = subprocess.run(["systemctl", "list-units", "--type=service", "--state=running"], capture_output=True, text=True)
            lines = result.stdout.strip().split("\n")
            services = [line.split()[0] for line in lines[1:-5]]
        else:
            return [f"{Colors.WARNING}Unsupported OS for services check{Colors.ENDC}"]

        top_services = ["Running Services (top 10):"] + services[:10]
        for service in top_services:
            logging.info(service)
        return top_services

    except Exception as e:
        error_msg = f"Error checking services: {e}"
        logging.error(error_msg)
        return [f"{Colors.WARNING}{error_msg}{Colors.ENDC}"]

# ----------------------
# Port Scanner with color-coded terminal & report-friendly tags
# ----------------------
def scan_ports(target=target_ip, ports=ports_to_scan):
    scan_results = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((target, port))
            status = "OPEN" if result == 0 else "CLOSED"
            msg = f"Port {port}: {status}"
            logging.info(msg)
            # Terminal color
            color_msg = f"{Colors.FAIL}{msg}{Colors.ENDC}" if status == "OPEN" else f"{Colors.OKGREEN}{msg}{Colors.ENDC}"
            # Append both terminal color msg and report-friendly
            scan_results.append((color_msg, msg))
        except Exception as e:
            msg = f"Port {port}: ERROR - {e}"
            scan_results.append((f"{Colors.WARNING}{msg}{Colors.ENDC}", msg))
            logging.error(msg)
        finally:
            sock.close()
    return scan_results

# ----------------------
# Generate Report
# ----------------------
def generate_report():
    report_filename = f"{output_dir}/security_audit_report_{timestamp}.txt"
    with open(report_filename, "w") as f:
        f.write("=== Cloud Security Audit Report ===\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write(f"OS Detected: {current_os}\n")
        f.write(f"Target IP: {target_ip}\n\n")

        # SSH
        f.write("--- SSH Status ---\n")
        f.write(check_ssh_status() + "\n\n")

        # Services
        f.write("--- Running Services ---\n")
        for service in check_running_services():
            f.write(service + "\n")
        f.write("\n")

        # Port scan
        f.write("--- Port Scan ---\n")
        for terminal_msg, report_msg in scan_ports():
            f.write(report_msg + "\n")

    print(f"{Colors.HEADER}Scan complete. Report saved as {report_filename}{Colors.ENDC}")
    print(f"{Colors.HEADER}Log saved as {log_filename}{Colors.ENDC}")

# ----------------------
# Main
# ----------------------
if __name__ == "__main__":
    generate_report()
