# 📌 Security Audit Automation Tool

A multithreaded Python-based network security audit tool designed to
detect open ports, perform service fingerprinting, classify severity
levels, and generate actionable security recommendations.

This project is part of my **AI-Enabled Cloud Network Security
Automation Roadmap (Phase-1)**.

---

## 🚀 Features

- Multithreaded TCP port scanning
- Service identification (HTTP, SSH, MySQL, etc.)
- Banner grabbing for open services
- Severity classification (INFO / LOW / MEDIUM / HIGH / CRITICAL)
- Actionable security recommendations
- Structured logging
- Report generation in:
  - TXT
  - JSON
  - CSV
  - Log file

---

## 🧠 Security Intelligence Model

Each detected service is analyzed and enriched with:

- Service name
- Severity level
- Banner (if available)
- Security recommendation

Example:

    Port 8080: OPEN
     → Service: HTTP [LOW]
     → Server: SimpleHTTP/0.6 Python/3.14.2
     → Recommendation: Check for outdated web server versions and enforce HTTPS.

---

## 🏗 Project Structure

    security_audit_tool/
    │
    ├── main.py
    ├── scanner/
    │   └── port_scanner.py
    ├── reports/
    ├── utils/
    │   └── report_generator.py
    └── README.md

---

## ⚙️ Installation

    git clone https://github.com/yourusername/security_audit_tool.git
    cd security_audit_tool

No external dependencies required (uses Python standard library).

Python 3.9+ recommended.

---

## ▶️ Usage

Basic scan:

    python3 main.py --target 127.0.0.1 --ports 22 80 443 --output-dir reports

Example with local test server:

    python3 -m http.server 8080
    python3 main.py --target 127.0.0.1 --ports 8080 --output-dir reports

---

## 📊 Output Example (JSON)

```json
{
  "port": 8080,
  "status": "OPEN",
  "service": "HTTP",
  "severity": "LOW",
  "banner": "SimpleHTTP/0.6 Python/3.14.2",
  "recommendation": "Check for outdated web server versions and enforce HTTPS."
}
```

---

## 🎯 Learning Objectives (Phase-1)

This project demonstrates:

- Linux CLI proficiency
- Threaded network programming
- Python modular architecture
- Structured logging
- Security assessment logic
- Professional report generation

---

## 📌 Roadmap

Future enhancements:

- Nmap-style OS detection
- CVE API integration
- Dockerized deployment
- Cloud scanning mode
- AI-based anomaly scoring

---

## 👤 Author

Yousuf Khan\
AI-Enabled Cloud Network Security Automation Journey
