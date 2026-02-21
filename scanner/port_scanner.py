"""
scanner.port_scanner
====================

Threaded TCP Port Scanner with:
    - Banner grabbing
    - Service fingerprinting
    - Severity classification
    - Structured return data including actionable recommendations

Author: Yousuf Khan
Phase: 1 – Portfolio-ready Security Audit Upgrade
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict
from datetime import datetime

from scanner.banner_grabber import grab_banner

# ==========================================================
# Core Networking Logic
# ==========================================================

def is_port_open(target: str, port: int) -> bool:
    """
    Determine whether a TCP port is open on the target host.

    Args:
        target (str): Target IP address
        port (int): Port number to check

    Returns:
        bool: True if open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0

    except Exception as e:
        logging.warning(f"Error checking port {port}: {e}")
        return False

# ==========================================================
# Service Fingerprinting & Recommendations
# ==========================================================

def fingerprint_service(port: int, banner: str) -> Dict:
    """
    Perform service fingerprinting and assign severity & actionable recommendation.

    Args:
        port (int): Port number
        banner (str): Captured banner text

    Returns:
        Dict: {
            "service": str,
            "server": str or None,
            "severity": str,
            "recommendation": str
        }
    """
    service = "UNKNOWN"
    server = None
    severity = "MEDIUM"
    recommendation = "No specific recommendation."

    banner_lower = banner.lower() if banner else ""

    # -----------------------------
    # SSH Detection
    # -----------------------------
    if port == 22 or "ssh" in banner_lower:
        service = "SSH"
        severity = "HIGH"
        recommendation = "Ensure SSH uses key-based authentication and non-default port."

    # -----------------------------
    # HTTP / Web Services
    # -----------------------------
    elif "http" in banner_lower or port in [80, 443, 8000, 8080]:
        service = "HTTP"
        severity = "LOW"
        recommendation = "Check for outdated web server versions and enforce HTTPS."

        # Extract server header if present
        if "server:" in banner_lower:
            for line in banner.splitlines():
                if line.lower().startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    break

    # -----------------------------
    # Database Ports
    # -----------------------------
    elif port in [3306, 5432]:
        service = "DATABASE"
        severity = "HIGH"
        recommendation = "Ensure DB is not exposed publicly and uses strong credentials."

    # -----------------------------
    # Unknown Service
    # -----------------------------
    else:
        service = "UNKNOWN"
        severity = "MEDIUM"
        recommendation = "Investigate unknown open service for potential vulnerabilities."

    return {
        "service": service,
        "server": server,
        "severity": severity,
        "recommendation": recommendation
    }

# ==========================================================
# Single Port Scan
# ==========================================================

def scan_port(target: str, port: int, color_class) -> Dict:
    """
    Scan a single port, grab banner, fingerprint service, and assign severity & recommendation.

    Args:
        target (str): Target IP
        port (int): Port to scan
        color_class: Terminal color helper class

    Returns:
        Dict: {
            "port": int,
            "status": "OPEN"/"CLOSED",
            "service": str,
            "server": str or None,
            "severity": str,
            "banner": str or None,
            "recommendation": str
        }
    """
    # Default structure for closed port
    port_data = {
        "port": port,
        "status": "CLOSED",
        "service": None,
        "server": None,
        "severity": "INFO",
        "banner": None,
        "recommendation": "Port is closed, no action needed."
    }

    # Check if port is open
    if is_port_open(target, port):
        port_data["status"] = "OPEN"
        print(f"{color_class.FAIL}Port {port}: OPEN{color_class.ENDC}")
        logging.info(f"Port {port}: OPEN")

        # Grab banner
        banner = grab_banner(target, port)
        port_data["banner"] = banner

        # Fingerprint service and get severity + recommendation
        fingerprint = fingerprint_service(port, banner)
        port_data["service"] = fingerprint["service"]
        port_data["server"] = fingerprint["server"]
        port_data["severity"] = fingerprint["severity"]
        port_data["recommendation"] = fingerprint["recommendation"]

        # Terminal output
        print(f"  → Service: {port_data['service']} [{port_data['severity']}]")
        if port_data["server"]:
            print(f"  → Server: {port_data['server']}")
        if banner:
            print(f"  → Service Banner: {banner}")
        print(f"  → Recommendation: {port_data['recommendation']}")

        logging.info(
            f"Port {port} | Service: {port_data['service']} | Severity: {port_data['severity']} | "
            f"Recommendation: {port_data['recommendation']}"
        )
    else:
        print(f"{color_class.OKGREEN}Port {port}: CLOSED{color_class.ENDC}")
        logging.info(f"Port {port}: CLOSED")

    return port_data

# ==========================================================
# Threaded Audit Runner
# ==========================================================

def run_audit(target: str, ports: List[int], output_dir: str, color_class) -> Dict:
    """
    Execute threaded port scanning and return structured audit results.

    Args:
        target (str): Target IP
        ports (List[int]): List of ports to scan
        output_dir (str): Reserved for future extensibility
        color_class: Terminal color helper class

    Returns:
        Dict: {
            "target": str,
            "timestamp": str,
            "ports": List[port_data],
            "ssh_status": str
        }
    """
    print(f"{color_class.HEADER}Starting Threaded Port Scan...{color_class.ENDC}")
    logging.info(f"Starting threaded scan on {target}")

    port_results = []

    # ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(scan_port, target, port, color_class) for port in ports]
        for future in futures:
            port_results.append(future.result())

    # Determine SSH overall status
    ssh_status = "ENABLED" if is_port_open(target, 22) else "DISABLED"
    logging.info(f"SSH Status: {ssh_status}")
    print(f"{color_class.OKBLUE}SSH Status: {ssh_status}{color_class.ENDC}")

    return {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "ports": port_results,
        "ssh_status": ssh_status
    }
