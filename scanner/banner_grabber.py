# scanner/banner_grabber.py

"""
Banner grabbing module for the Cloud Security Audit Tool.
Responsible for retrieving service banners from open TCP ports.
"""

import socket


def grab_banner(target: str, port: int) -> str:
    """
    Attempt to retrieve the service banner from an open TCP port.

    Args:
        target (str): Target IP address
        port (int): TCP port number

    Returns:
        str: Banner string or "Banner grab failed"
    """
    banner = ""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)
        sock.connect((target, port))

        # Send HTTP HEAD request for common web ports
        if port in [80, 8080, 8000, 443]:
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            except Exception:
                pass

        try:
            banner = sock.recv(1024).decode(errors='ignore').strip()
        except Exception:
            banner = "Banner grab failed"

        sock.close()
    except Exception:
        banner = "Banner grab failed"

    return banner if banner else "Banner grab failed"
