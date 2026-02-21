#!/usr/bin/env python3
"""
Cloud Security Audit Tool (Phase-1 Project) - Modular & Structured Version

Author: Yousuf Khan
Phase: 1 – Security Intelligence Upgrade

Description:
    This tool performs a threaded TCP port scan on a target host and produces
    structured audit reports in TXT, JSON, CSV, and LOG formats. It includes:
    - Banner grabbing
    - Service fingerprinting
    - Severity classification
    - SSH detection
    - Threaded scanning for speed
    - Color-coded terminal output

Usage:
    python3 main.py --target 127.0.0.1 --ports 22 80 8080 --output-dir reports

Modules:
    scanner.port_scanner - Handles low-level port scanning and intelligence gathering
    report_generator    - Handles report generation (TXT, JSON, CSV, LOG)
    utils.helpers       - Provides CLI argument parsing, colors, and utility functions
"""

import logging
from utils.helpers import Colors, parse_args, parse_ports, ensure_output_dir, validate_ip
from scanner.port_scanner import run_audit
from report_generator import generate_reports


def main():
    """
    Main entry point for the Cloud Security Audit Tool.

    Workflow:
        1. Parse CLI arguments for target, ports, and output directory.
        2. Validate the target IP and ensure output directory exists.
        3. Parse ports (supporting single ports and ranges).
        4. Perform threaded audit via run_audit().
        5. Generate reports (TXT, JSON, CSV, LOG) from structured results.
    """

    # ----------------------
    # Parse CLI Arguments
    # ----------------------
    args = parse_args()

    # ----------------------
    # Ensure Output Directory Exists
    # ----------------------
    ensure_output_dir(args.output_dir)

    # ----------------------
    # Validate Target IP
    # ----------------------
    validate_ip(args.target)

    # ----------------------
    # Parse Ports (supports ranges like 20-25)
    # ----------------------
    ports_to_scan = parse_ports(args.ports)

    # ----------------------
    # Run Threaded Audit
    # ----------------------
    # Returns a dict with:
    #   {
    #       "target": str,
    #       "timestamp": str,
    #       "ports": List[port_data],
    #       "ssh_status": str
    #   }
    audit_results = run_audit(args.target, ports_to_scan, args.output_dir, Colors)

    # ----------------------
    # Generate Reports
    # ----------------------
    # Uses structured port data for:
    #   - TXT report
    #   - JSON export
    #   - CSV export
    #   - LOG file
    generate_reports(audit_results["ports"], args.target, audit_results["ssh_status"], args.output_dir)

    print(f"{Colors.HEADER}All reports generated successfully in '{args.output_dir}'{Colors.ENDC}")


# ----------------------
# Entry Point
# ----------------------
if __name__ == "__main__":
    main()
