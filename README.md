
**Author:** Ashley Okoro 
**Student ID:** sba25350   

## Project Overview

This repository contains three defensive security tools developed for system administration, security auditing, and vulnerability assessment:

1. **Error Log Manager** (`error_manager.sh`) - Bash-based automated log analysis and error detection
2. **Web Vulnerability Scanner** (`web_vulnerability_scanner.py`) - Python tool for web application security testing
3. **Network Scanner** (`network_scanner.py`) - Multi-threaded network port and service discovery utility

These tools demonstrate secure programming practices, including input validation, error handling, data encryption, and ethical security testing principles.


---

## Installation

### Prerequisites

- Linux/Unix-based operating system (Ubuntu, Debian, CentOS, macOS)
- Bash 4.0+ (for Error Log Manager)
- Python 3.7+ (for vulnerability and network scanners)

### Setup

```bash
# Clone the repository
git clone https://github.com/chief-okoro/Secure-Programming-and-Scripting_CA1.git
cd security-tools-suite

# Install Python dependencies
pip3 install requests beautifulsoup4 cryptography python-nmap

# Set executable permissions
chmod +x error_manager.sh network_scanner.py web_vulnerability_scanner.py
```

---

## Dependencies

### Error Log Manager (Bash)
- bash (4.0+), grep, date
- No external dependencies required

### Web Vulnerability Scanner (Python)
- `requests` (required)
- `beautifulsoup4` (optional - for form testing)
- `cryptography` (optional - for encryption)

### Network Scanner (Python)
- `python-nmap` (optional - socket-based scanning works without it)

---

## Usage Guide

### Tool 1: Error Log Manager

Automated detection and reporting of errors in system log files.

```bash
# Basic usage
./error_manager.sh [log_file]

# Examples
./error_manager.sh                           # Analyze default logs.txt
./error_manager.sh /var/log/application.log  # Analyze specific file
```

**Output:** Generates timestamped report `error_report_YYYYMMDD_HHMMSS.txt`

---

### Tool 2: Web Vulnerability Scanner

Automated detection of common web application vulnerabilities (SQL injection, XSS, security headers).

```bash
# Basic usage
python3 web_vulnerability_scanner.py --url <target_url> [options]

# Options
--url <url>      # Target URL (required, must include http:// or https://)
--deep           # Enable deep scan mode
--output <file>  # Specify output filename for JSON report

# Example
python3 web_vulnerability_scanner.py --url https://testsite.com --deep
```

**Output:** JSON report with encrypted evidence and vulnerability details

---

### Tool 3: Network Scanner

Network port scanning and service identification.

```bash
# Basic usage
python3 network_scanner.py --target <ip_or_range> [options]

# Options
--target, -t <ip>   # Target IP/range (required)
--ports, -p <spec>  # Port specification (e.g., 22,80,443 or 1-1024)
--common            # Scan common ports
--all               # Scan all well-known ports (1-1024)
--udp               # Enable UDP scanning
--services          # Enable service identification
--threads <n>       # Number of concurrent threads (default: 100)
--output, -o <file> # Save results to file

# Target formats
--target 192.168.1.100          # Single IP
--target 192.168.1.0/24         # CIDR notation
--target 192.168.1.1-50         # IP range

# Example
python3 network_scanner.py --target 192.168.1.100 --common --services
```

**Output:** Text report with discovered open ports and services

