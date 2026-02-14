import socket
from datetime import datetime

def check_port(host, port):
    """Check if a specific port is open on a host."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((host, port))
        s.close()

        if result == 0:
            return "OPEN"
        else:
            return "CLOSED"

    except Exception as e:
        return f"ERROR: {e}"


def main():
    print("\n=== Basic Security Port Scanner ===\n")

    target = input("Enter target IP (default 127.0.0.1): ") or "127.0.0.1"
    ports = [22, 80, 443, 5000, 5432]

    print(f"\nScanning {target}...\n")

    results = []
    for port in ports:
        status = check_port(target, port)
        output = f"Port {port}: {status}"
        print(output)
        results.append(output)

    # Save results to file
    filename = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(filename, "w") as f:
        f.write(f"Scan Report for {target}\n")
        f.write("=" * 40 + "\n")
        for line in results:
            f.write(line + "\n")

    print(f"\nScan complete. Report saved as {filename}\n")


if __name__ == "__main__":
    main()
