# NetRecon


## ⚠️ Disclaimer

NetRecon is provided for **educational purposes and authorized security testing only**.

- Only use this tool on networks and devices you own or have explicit permission to assess.
- You are solely responsible for how you use this software and for obtaining the necessary authorization before conducting any scans.
- The author is not responsible for any damage, data loss, service disruption, legal consequences, or other issues arising from the use or misuse of this tool.
- The author makes no guarantees that the software will be error-free, accurate, or suitable for any particular purpose.

**By using NetRecon, you acknowledge that you are responsible for your actions and for complying with all applicable laws and regulations.**







**A Python-based network asset profiling and reconnaissance tool for authorized security assessments.**

NetRecon combines local network discovery, selected TCP port checks, service information gathering, and heuristic device profiling into one workflow. It displays findings in the terminal and can export reports in JSON and HTML formats.

This project was built to develop practical Python skills and explore how network reconnaissance data can be collected, analyzed, and organized.

## Features

- **ARP discovery:** Discover responding devices on a local network segment.
- **Host identification:** Collect IP addresses, MAC addresses, resolved hostnames, and basic vendor information.
- **TCP port scanning:** Check a predefined or user-specified list of ports using concurrent connections.
- **Service enumeration:** Identify common services by port and collect banners from selected services.
- **Web inspection:** Retrieve HTTP/HTTPS status codes, page titles, server headers, and final URLs.
- **RTSP probing:** Send OPTIONS requests to detected RTSP services.
- **Device profiling:** Estimate likely device types using observed ports, hostnames, and vendor information.
- **JSON reporting:** Export structured results for further processing.
- **HTML reporting:** Generate a readable report containing discovered devices and web interfaces.
- **Input validation:** Validate target networks using CIDR notation.
- **Authorization confirmation:** Prompt for confirmation before scanning unless explicitly skipped.

## Requirements

- Python 3
- Linux environment recommended
- Root privileges for ARP discovery on Linux
- Network access to the authorized target environment

### Dependencies

- Scapy
- Requests
- Beautiful Soup 4
- urllib3

## Installation

Clone the repository:

```bash
git clone https://github.com/assassin222/netrecon.git
cd netrecon
```

Install the dependencies:

```bash
python3 -m pip install scapy requests beautifulsoup4 urllib3
```

If your Python environment is externally managed, consider using a virtual environment instead of installing packages system-wide.

## Usage

### 1. View the available options

```bash
python3 netrecon.py --help
```

### 2. Scan a local network

```bash
sudo python3 netrecon.py 192.168.1.0/24
```

Replace the example subnet with a network you own or have explicit permission to assess.

The tool asks you to confirm authorization before proceeding.

### 3. Specify TCP ports

```bash
sudo python3 netrecon.py 192.168.1.0/24 --ports 22,80,443,445
```

The `--ports` argument accepts a comma-separated list. Providing it **replaces the default port list** rather than adding ports to it.

### 4. Adjust concurrent port checks

```bash
sudo python3 netrecon.py 192.168.1.0/24 --port-workers 100
```

The `--port-workers` option sets the maximum number of concurrent port-checking workers per host. The default is `50`.

Higher values can increase network load and resource usage.

### 5. Export a JSON report

```bash
sudo python3 netrecon.py 192.168.1.0/24 --json scan_report.json
```

### 6. Export an HTML report

```bash
sudo python3 netrecon.py 192.168.1.0/24 --html scan_report.html
```

### 7. Export both report formats

```bash
sudo python3 netrecon.py 192.168.1.0/24 --json scan_report.json --html scan_report.html
```

### 8. Skip the interactive confirmation

```bash
sudo python3 netrecon.py 192.168.1.0/24 --yes
```

The `--yes` flag skips the authorization confirmation prompt. It does not grant permission to scan a network.

## How it works

1. Validates the supplied network in CIDR notation.
2. Uses ARP to discover responding devices on the local network segment.
3. Collects available IP, MAC, hostname, and basic vendor information.
4. Checks the selected TCP ports on discovered devices.
5. Gathers service banners and inspects supported web and RTSP services.
6. Estimates device types using basic heuristics.
7. Displays findings and writes optional JSON and HTML reports.

## Limitations

NetRecon is a learning and reconnaissance project, not a full vulnerability scanner.

- It does not identify or exploit vulnerabilities.
- ARP discovery is limited to the local network segment and may miss devices that do not respond.
- Port checks are limited to the configured list; they do not cover every TCP port by default.
- Service names are based primarily on port mappings, and banners may be unavailable or misleading.
- MAC vendor identification uses a small built-in table and may return `Unknown`.
- Device type and confidence values are heuristic estimates, not verified classifications or calibrated probabilities.
- HTTPS certificate verification is disabled in the current implementation, so HTTPS inspection does not validate the server certificate.
- Results depend on network topology, host availability, firewall rules, and service responses.

## Responsible use

Use NetRecon only on networks and devices you own or are explicitly authorized to assess. You are responsible for complying with applicable laws, organizational policies, and testing permissions.

## Project status

NetRecon is a work in progress. Future improvements may include more comprehensive asset identification, better vendor data, improved error handling, and more detailed reporting.
