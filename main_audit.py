import socket
import argparse
import os
from datetime import datetime


# -----------------------------
# Helper: Parse Port Ranges
# -----------------------------
def parse_ports(port_args):
    ports = set()
    for item in port_args:
        if "-" in item:
            start, end = item.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(item))
    return sorted(ports)


# -----------------------------
# Helper: Check if Port is Open
# -----------------------------
def is_port_open(target, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            return result == 0
    except Exception:
        return False


# -----------------------------
# Helper: Detect Exposure Type
# -----------------------------
def get_exposure_type(target):
    if target in ["127.0.0.1", "localhost"]:
        return "LOCAL-ONLY"
    return "PUBLIC"


# -----------------------------
# Core Audit Logic
# -----------------------------
def run_audit(target, ports, output_dir):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    report_path = os.path.join(output_dir, f"security_audit_report_{timestamp}.txt")
    log_path = os.path.join(output_dir, f"security_audit_log_{timestamp}.txt")

    exposure_type = get_exposure_type(target)

    report_lines = []
    log_lines = []

    report_lines.append("=== Security Audit Report ===")
    report_lines.append(f"Target: {target}")
    report_lines.append(f"Scan Time: {timestamp}")
    report_lines.append("")

    print("\nStarting Port Scan...\n")

    for port in ports:
        open_status = is_port_open(target, port)

        if open_status:
            status = "OPEN"
            report_line = f"Port {port}: {status} ({exposure_type})"
            print(f"\033[91m{report_line}\033[0m")  # Red
        else:
            status = "CLOSED"
            report_line = f"Port {port}: {status}"
            print(f"\033[92m{report_line}\033[0m")  # Green

        report_lines.append(report_line)
        log_lines.append(f"{datetime.now()} - Port {port} - {status}")

    # SSH Detection
    ssh_status = "ENABLED" if is_port_open(target, 22) else "DISABLED"
    report_lines.append("")
    report_lines.append(f"SSH Status: {ssh_status}")

    # Write Report
    with open(report_path, "w") as report_file:
        report_file.write("\n".join(report_lines))

    # Write Log
    with open(log_path, "w") as log_file:
        log_file.write("\n".join(log_lines))

    print("\nScan complete.")
    print(f"Report saved to: {report_path}")
    print(f"Log saved to: {log_path}")


# -----------------------------
# Application Entry Point
# -----------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Security Audit Tool - Phase 1"
    )

    parser.add_argument(
        "--target",
        type=str,
        default="127.0.0.1",
        help="Target IP address (default: 127.0.0.1)"
    )

    parser.add_argument(
        "--ports",
        nargs="+",
        default=["22", "80", "443", "5000", "5432"],
        help="Ports to scan (e.g., 22 80 443 or 20-25)"
    )

    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports",
        help="Directory to save reports (default: ./reports)"
    )

    args = parser.parse_args()

    ports = parse_ports(args.ports)

    run_audit(args.target, ports, args.output_dir)


# Only execute when run directly
if __name__ == "__main__":
    main()
