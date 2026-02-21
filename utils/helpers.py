"""
utils.helpers
=============

Common helper utilities for Cloud Security Audit Tool.

Includes:
    - Terminal color codes for CLI output
    - CLI argument parsing
    - IP validation
    - Port parsing (supports ranges)
    - Output directory creation

Author: Yousuf Khan
Phase: 1 – Security Intelligence Upgrade
"""

import os
import ipaddress
import argparse

# ==========================================================
# Terminal Colors
# ==========================================================
class Colors:
    """
    ANSI color codes for terminal output.
    Usage:
        print(f"{Colors.OKGREEN}This is green text{Colors.ENDC}")
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


# ==========================================================
# CLI Argument Parsing
# ==========================================================
def parse_args():
    """
    Parse command-line arguments for target IP, ports, and output directory.

    Returns:
        argparse.Namespace: Parsed arguments
            - target (str): Target IP (default 127.0.0.1)
            - ports (list of str): List of ports or ranges
            - output_dir (str): Output folder for reports/logs
    """
    parser = argparse.ArgumentParser(description="Cloud Security Audit Tool - Threaded")
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
        default=["22", "80", "443", "5000", "5432"],
        help="Ports to scan (supports ranges, e.g., 20-25 80 443)"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="reports",
        help="Directory to save report and log files (default: ./reports)"
    )
    return parser.parse_args()


# ==========================================================
# Ensure Output Directory Exists
# ==========================================================
def ensure_output_dir(output_dir: str):
    """
    Create the output directory if it doesn't exist.

    Args:
        output_dir (str): Path to the directory
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)


# ==========================================================
# Validate Target IP
# ==========================================================
def validate_ip(ip: str):
    """
    Validate that the target IP is a valid IPv4 or IPv6 address.

    Args:
        ip (str): Target IP address

    Raises:
        SystemExit: If the IP address is invalid
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"{Colors.FAIL}Invalid target IP: {ip}{Colors.ENDC}")
        exit(1)


# ==========================================================
# Parse Ports (supports ranges like 20-25)
# ==========================================================
def parse_ports(raw_ports):
    """
    Convert user-specified ports into a sorted list of integers.

    Args:
        raw_ports (list of str): List of ports or ranges (e.g., ["22","80","1000-1010"])

    Returns:
        list of int: Sorted unique port numbers
    """
    ports_to_scan = []
    for port_str in raw_ports:
        if '-' in port_str:
            start, end = port_str.split('-')
            ports_to_scan.extend(range(int(start), int(end) + 1))
        else:
            ports_to_scan.append(int(port_str))
    return sorted(set(ports_to_scan))
