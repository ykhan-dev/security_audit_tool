"""
report_generator.py
===================

Generates structured audit reports for the Cloud Security Audit Tool.

Supports:
    - Human-readable TXT report
    - JSON export for structured security data
    - CSV export for spreadsheet analysis
    - LOG file with timestamped entries

Enhancement (Phase 1 Upgrade):
    - Includes severity classification
    - Includes actionable security recommendations
    - Structured for portfolio-ready reporting

Author: Yousuf Khan
Phase: 1 – Security Intelligence Reporting Upgrade
"""

import os
import json
import csv
from datetime import datetime


# ==========================================================
# Generate All Reports
# ==========================================================

def generate_reports(port_results, target, ssh_status, output_dir):
    """
    Generate TXT, JSON, CSV, and LOG reports from structured audit results.

    Args:
        port_results (list of dict): List of scanned port data
        target (str): Target IP address
        ssh_status (str): SSH status ("ENABLED"/"DISABLED")
        output_dir (str): Directory where reports will be saved

    Each port_data dict contains:
        {
            "port": int,
            "status": str,
            "service": str,
            "server": str,
            "severity": str,
            "banner": str,
            "recommendation": str
        }
    """

    # ------------------------------------------------------
    # Ensure Output Directory Exists
    # ------------------------------------------------------
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    txt_file = os.path.join(output_dir, f"security_audit_report_{timestamp}.txt")
    json_file = os.path.join(output_dir, f"security_audit_report_{timestamp}.json")
    csv_file = os.path.join(output_dir, f"security_audit_report_{timestamp}.csv")
    log_file = os.path.join(output_dir, f"security_audit_log_{timestamp}.txt")

    # ======================================================
    # 1. TXT Report (Human-Readable)
    # ======================================================
    with open(txt_file, "w") as f:
        f.write("=== Cloud Security Audit Report ===\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Target IP: {target}\n")
        f.write("=" * 50 + "\n\n")

        for port_data in port_results:
            f.write(f"Port {port_data['port']}: {port_data['status']}\n")

            if port_data.get("service"):
                f.write(f"  → Service: {port_data['service']} [{port_data.get('severity', 'N/A')}]\n")

            if port_data.get("server"):
                f.write(f"  → Server: {port_data['server']}\n")

            if port_data.get("banner"):
                f.write(f"  → Service Banner: {port_data['banner']}\n")

            if port_data.get("recommendation"):
                f.write(f"  → Recommendation: {port_data['recommendation']}\n")

            f.write("\n")

        f.write("=" * 50 + "\n")
        f.write(f"SSH Status: {ssh_status}\n")

    # ======================================================
    # 2. JSON Report (Structured Security Intelligence)
    # ======================================================
    json_data = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "ssh_status": ssh_status,
        "ports": port_results
    }

    with open(json_file, "w") as f:
        json.dump(json_data, f, indent=4)

    # ======================================================
    # 3. CSV Report (Spreadsheet-Friendly)
    # ======================================================
    csv_headers = [
        "Port",
        "Status",
        "Service",
        "Server",
        "Severity",
        "Banner",
        "Recommendation"
    ]

    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=csv_headers)
        writer.writeheader()

        for port_data in port_results:
            writer.writerow({
                "Port": port_data["port"],
                "Status": port_data["status"],
                "Service": port_data.get("service", ""),
                "Server": port_data.get("server", ""),
                "Severity": port_data.get("severity", ""),
                "Banner": port_data.get("banner", ""),
                "Recommendation": port_data.get("recommendation", "")
            })

    # ======================================================
    # 4. LOG File (Timestamped Security Events)
    # ======================================================
    with open(log_file, "w") as f:
        for port_data in port_results:
            log_line = (
                f"{datetime.now().isoformat()} | "
                f"Port {port_data['port']} | "
                f"Status: {port_data['status']} | "
                f"Service: {port_data.get('service', 'N/A')} | "
                f"Severity: {port_data.get('severity', 'N/A')} | "
                f"Recommendation: {port_data.get('recommendation', 'N/A')}"
            )
            f.write(log_line + "\n")

        f.write(f"{datetime.now().isoformat()} | SSH Status: {ssh_status}\n")

    # ------------------------------------------------------
    # Console Summary
    # ------------------------------------------------------
    print("\nReports generated successfully:")
    print(f" - TXT:  {txt_file}")
    print(f" - JSON: {json_file}")
    print(f" - CSV:  {csv_file}")
    print(f" - LOG:  {log_file}")
