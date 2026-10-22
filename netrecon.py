#!/usr/bin/env python3

import argparse
import concurrent.futures
import html
import ipaddress
import json
import os
import platform
import socket
import sys
import time
import urllib3

import requests
import scapy.all as scapy
from bs4 import BeautifulSoup


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_PORTS = [
    21,      # FTP
    22,      # SSH
    23,      # Telnet
    25,      # SMTP
    53,      # DNS
    80,      # HTTP
    110,     # POP3
    143,     # IMAP
    443,     # HTTPS
    445,     # SMB
    554,     # RTSP
    3306,    # MySQL
    3389,    # RDP
    8080,    # HTTP alternate
    8443,    # HTTPS alternate
    8554     # RTSP alternate
]


PORT_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8554: "RTSP-Alt"
}


WEB_PORTS = {
    80: "http",
    443: "https",
    8080: "http",
    8443: "https"
}


RTSP_PORTS = {554, 8554}


BANNER_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL"
}


# ============================================================
# PRIVILEGE CHECK
# ============================================================

def check_privileges():

    system = platform.system()

    if system in ("Linux", "Darwin"):

        if os.geteuid() != 0:

            print(
                "[!] ARP scanning requires root privileges."
            )

            print(
                "[!] Run with sudo."
            )

            sys.exit(1)


# ============================================================
# INPUT VALIDATION
# ============================================================

def validate_network(network):

    try:

        return str(
            ipaddress.ip_network(
                network,
                strict=False
            )
        )

    except ValueError:

        raise ValueError(
            f"Invalid network: {network}"
        )


# ============================================================
# HOSTNAME
# ============================================================

def get_hostname(ip):

    try:

        return socket.gethostbyaddr(ip)[0]

    except (
        socket.herror,
        socket.gaierror,
        socket.timeout
    ):

        return "Unknown"


# ============================================================
# MAC VENDOR
# ============================================================

def get_mac_vendor(mac):

    """
    Basic vendor identification.

    This uses a small built-in OUI table.
    You can expand this later with a complete local
    IEEE OUI database.
    """

    oui = (
        mac.upper()
        .replace(":", "")
        .replace("-", "")
    )[:6]

    vendors = {

        # Common examples
        "001A2B": "Example Vendor",
        "B827EB": "Raspberry Pi",
        "DC41A9": "Raspberry Pi",
        "3C5A37": "Google",
        "F4F5D8": "Apple",
        "001C42": "Parallels",
        "080027": "VirtualBox",
        "525400": "QEMU",
        "000C29": "VMware",
        "00155D": "Microsoft",
    }

    return vendors.get(
        oui,
        "Unknown"
    )


# ============================================================
# ARP DISCOVERY
# ============================================================

def scan_network(network, timeout=3):

    print(
        f"[*] ARP sweeping {network} ..."
    )

    arp_request = scapy.ARP(
        pdst=network
    )

    broadcast = scapy.Ether(
        dst="ff:ff:ff:ff:ff:ff"
    )

    packet = broadcast / arp_request

    answered = scapy.srp(
        packet,
        timeout=timeout,
        verbose=0
    )[0]

    devices = []

    for _, received in answered:

        ip = received.psrc

        mac = received.hwsrc

        hostname = get_hostname(ip)

        vendor = get_mac_vendor(mac)

        devices.append({

            "ip": ip,

            "mac": mac,

            "vendor": vendor,

            "hostname": hostname,

            "open_ports": [],

            "services": [],

            "web": [],

            "rtsp": [],

            "device_type": "Unknown",

            "confidence": 0

        })

    return devices


# ============================================================
# TCP PORT TEST
# ============================================================

def check_port(ip, port, timeout):

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            return (
                sock.connect_ex(
                    (ip, port)
                ) == 0
            )

    except OSError:

        return False


# ============================================================
# PORT SCANNING
# ============================================================

def scan_ports(
    ip,
    ports,
    timeout=0.8,
    workers=50
):

    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=workers
    ) as pool:

        jobs = {

            pool.submit(
                check_port,
                ip,
                port,
                timeout
            ): port

            for port in ports
        }

        for future in concurrent.futures.as_completed(
            jobs
        ):

            port = jobs[future]

            try:

                if future.result():

                    open_ports.append(port)

            except Exception:

                pass

    return sorted(open_ports)


# ============================================================
# HTML TITLE
# ============================================================

def extract_title(content):

    try:

        soup = BeautifulSoup(
            content,
            "html.parser"
        )

        if soup.title:

            title = soup.title.string

            if title:

                return title.strip()

    except Exception:

        pass

    return "Unknown"


# ============================================================
# WEB DETECTION
# ============================================================

def detect_web(ip, port, timeout=2):

    scheme = WEB_PORTS.get(port)

    if not scheme:

        return None

    if (
        (scheme == "http" and port == 80)
        or
        (scheme == "https" and port == 443)
    ):

        url = f"{scheme}://{ip}"

    else:

        url = f"{scheme}://{ip}:{port}"

    try:

        response = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True
        )

        return {

            "port": port,

            "url": response.url,

            "status": response.status_code,

            "server": response.headers.get(
                "Server",
                "Unknown"
            ),

            "title": extract_title(
                response.text
            )

        }

    except requests.RequestException:

        return None


# ============================================================
# BANNER GRABBING
# ============================================================

def grab_banner(
    ip,
    port,
    timeout=2
):

    try:

        with socket.create_connection(
            (ip, port),
            timeout=timeout
        ) as sock:

            sock.settimeout(timeout)

            data = sock.recv(1024)

        if not data:

            return None

        if port == 3306:

            try:

                text = (
                    data[5:]
                    .split(b"\x00")[0]
                    .decode(
                        errors="ignore"
                    )
                )

            except Exception:

                text = data.decode(
                    errors="ignore"
                )

        else:

            text = data.decode(
                errors="ignore"
            ).strip()

        return text if text else None

    except (
        socket.timeout,
        ConnectionRefusedError,
        OSError
    ):

        return None


# ============================================================
# RTSP
# ============================================================

def detect_rtsp(
    ip,
    port,
    timeout=2
):

    request = (

        f"OPTIONS "
        f"rtsp://{ip}:{port} "
        f"RTSP/1.0\r\n"

        f"CSeq: 1\r\n"

        f"User-Agent: NetRecon\r\n"

        f"\r\n"
    )

    try:

        with socket.create_connection(
            (ip, port),
            timeout=timeout
        ) as sock:

            sock.sendall(
                request.encode()
            )

            sock.settimeout(timeout)

            response = sock.recv(
                2048
            ).decode(
                errors="ignore"
            )

        if not response:

            return None

        lines = response.split(
            "\r\n"
        )

        status_line = lines[0]

        headers = {}

        for line in lines[1:]:

            if ":" in line:

                key, value = line.split(
                    ":",
                    1
                )

                headers[
                    key.strip().lower()
                ] = value.strip()

        return {

            "port": port,

            "status": status_line,

            "server": headers.get(
                "server",
                "Unknown"
            ),

            "methods": headers.get(
                "public",
                "Unknown"
            )

        }

    except (
        socket.timeout,
        ConnectionRefusedError,
        OSError
    ):

        return None


# ============================================================
# DEVICE FINGERPRINTING
# ============================================================

def fingerprint_device(device):

    ports = set(
        device["open_ports"]
    )

    hostname = device[
        "hostname"
    ].lower()

    vendor = device[
        "vendor"
    ].lower()

    score = {}

    def add(name, points):

        score[name] = (
            score.get(name, 0)
            + points
        )

    # Printer
    if 9100 in ports:

        add(
            "Network Printer",
            70
        )

    # Camera / NVR
    if 554 in ports or 8554 in ports:

        add(
            "IP Camera / NVR",
            70
        )

    # Router
    if (
        "router" in hostname
        or "gateway" in hostname
    ):

        add(
            "Router / Gateway",
            60
        )

    if 53 in ports:

        add(
            "Router / DNS Server",
            25
        )

    # Windows
    if 445 in ports:

        add(
            "Windows / SMB Device",
            60
        )

    if 3389 in ports:

        add(
            "Windows Device",
            40
        )

    # Linux / Unix
    if 22 in ports:

        add(
            "Linux / Unix Device",
            30
        )

    # Vendor hints
    if "raspberry" in vendor:

        add(
            "Raspberry Pi",
            80
        )

    if "vmware" in vendor:

        add(
            "VMware Virtual Machine",
            80
        )

    if "virtualbox" in vendor:

        add(
            "VirtualBox Virtual Machine",
            80
        )

    if not score:

        return (
            "Unknown",
            0
        )

    device_type = max(
        score,
        key=score.get
    )

    confidence = min(
        score[device_type],
        100
    )

    return (
        device_type,
        confidence
    )


# ============================================================
# ANALYZE DEVICE
# ============================================================

def analyze_device(
    device,
    ports,
    port_workers
):

    ip = device["ip"]

    open_ports = scan_ports(
        ip,
        ports,
        workers=port_workers
    )

    device["open_ports"] = open_ports

    # Services
    for port in open_ports:

        service = {

            "port": port,

            "name": PORT_NAMES.get(
                port,
                "Unknown"
            )

        }

        if port in BANNER_PORTS:

            banner = grab_banner(
                ip,
                port
            )

            if banner:

                service[
                    "banner"
                ] = banner

        device[
            "services"
        ].append(service)

    # Web
    for port in open_ports:

        if port in WEB_PORTS:

            info = detect_web(
                ip,
                port
            )

            if info:

                device[
                    "web"
                ].append(info)

    # RTSP
    for port in open_ports:

        if port in RTSP_PORTS:

            info = detect_rtsp(
                ip,
                port
            )

            if info:

                device[
                    "rtsp"
                ].append(info)

    # Fingerprint
    device_type, confidence = (
        fingerprint_device(
            device
        )
    )

    device[
        "device_type"
    ] = device_type

    device[
        "confidence"
    ] = confidence

    return device


# ============================================================
# JSON REPORT
# ============================================================

def save_json(
    filename,
    network,
    devices,
    duration
):

    report = {

        "tool": "NetRecon",

        "network": network,

        "duration_seconds": round(
            duration,
            2
        ),

        "devices": devices

    }

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    print(
        f"[+] JSON report saved: {filename}"
    )


# ============================================================
# HTML REPORT
# ============================================================

def save_html(
    filename,
    network,
    devices,
    duration
):

    page = []

    page.append(
        "<html><head>"
        "<meta charset='utf-8'>"
        "<title>NetRecon Report</title>"
        "<style>"
        "body{font-family:Arial;margin:40px}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ccc;padding:8px}"
        "th{background:#eee}"
        "</style>"
        "</head><body>"
    )

    page.append(
        f"<h1>NetRecon Report</h1>"
    )

    page.append(
        f"<p>Network: "
        f"{html.escape(network)}</p>"
    )

    page.append(
        f"<p>Duration: "
        f"{duration:.2f} seconds</p>"
    )

    page.append(
        "<table>"
        "<tr>"
        "<th>IP</th>"
        "<th>MAC</th>"
        "<th>Vendor</th>"
        "<th>Hostname</th>"
        "<th>Device Type</th>"
        "<th>Ports</th>"
        "</tr>"
    )

    for device in devices:

        ports = ", ".join(
            str(p)
            for p in device[
                "open_ports"
            ]
        )

        page.append(
            "<tr>"
            f"<td>{html.escape(device['ip'])}</td>"
            f"<td>{html.escape(device['mac'])}</td>"
            f"<td>{html.escape(device['vendor'])}</td>"
            f"<td>{html.escape(device['hostname'])}</td>"
            f"<td>{html.escape(device['device_type'])} "
            f"({device['confidence']}%)</td>"
            f"<td>{html.escape(ports)}</td>"
            "</tr>"
        )

    page.append(
        "</table>"
    )

    page.append(
        "<h2>Web Interfaces</h2>"
    )

    for device in devices:

        for web_info in device["web"]:

            page.append(
                f"<p>"
                f"<b>{html.escape(device['ip'])}</b> "
                f"<a href='{html.escape(web_info['url'])}'>"
                f"{html.escape(web_info['url'])}"
                f"</a><br>"
                f"Title: "
                f"{html.escape(web_info['title'])}"
                f"<br>"
                f"Server: "
                f"{html.escape(web_info['server'])}"
                f"</p>"
            )

    page.append(
        "</body></html>"
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "\n".join(page)
        )

    print(
        f"[+] HTML report saved: {filename}"
    )


# ============================================================
# ARGUMENTS
# ============================================================

def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "NetRecon - authorized "
            "network reconnaissance tool"
        )
    )

    parser.add_argument(
        "network",
        nargs="?",
        help="CIDR network, e.g. 192.168.1.0/24"
    )

    parser.add_argument(
        "--ports",
        help=(
            "Comma-separated ports"
        )
    )

    parser.add_argument(
        "--port-workers",
        type=int,
        default=50
    )

    parser.add_argument(
        "--json",
        metavar="FILE"
    )

    parser.add_argument(
        "--html",
        metavar="FILE"
    )

    parser.add_argument(
        "-y",
        "--yes",
        action="store_true"
    )

    return parser.parse_args()


# ============================================================
# MAIN
# ============================================================

def main():

    args = parse_args()

    if args.network:

        network = args.network

    else:

        network = input(
            "Enter network to scan "
            "(example: 192.168.1.0/24): "
        ).strip()

    try:

        network = validate_network(
            network
        )

    except ValueError as error:

        print(
            f"[!] {error}"
        )

        sys.exit(1)

    if args.ports:

        try:

            ports = [
                int(p.strip())
                for p in args.ports.split(",")
            ]

        except ValueError:

            print(
                "[!] Invalid port list."
            )

            sys.exit(1)

    else:

        ports = DEFAULT_PORTS

    if not args.yes:

        answer = input(
            f"\nConfirm you are authorized "
            f"to scan {network} (y/N): "
        ).strip().lower()

        if answer != "y":

            print(
                "Aborted."
            )

            return

    check_privileges()

    print("\n" + "=" * 70)

    print(
        "                    NETRECON"
    )

    print(
        "          Network Asset & Service Scanner"
    )

    print("=" * 70)

    start = time.time()

    devices = scan_network(
        network
    )

    if not devices:

        print(
            "[!] No devices discovered."
        )

        return

    print(
        f"\n[+] Discovered "
        f"{len(devices)} device(s)"
    )

    for device in devices:

        print(
            f"    {device['ip']:<15} "
            f"{device['mac']:<18} "
            f"{device['vendor']:<20} "
            f"{device['hostname']}"
        )

    print(
        "\n[*] Performing service discovery..."
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=10
    ) as pool:

        futures = [

            pool.submit(
                analyze_device,
                device,
                ports,
                args.port_workers
            )

            for device in devices
        ]

        for future in concurrent.futures.as_completed(
            futures
        ):

            try:

                future.result()

            except Exception as error:

                print(
                    f"[!] Host analysis error: "
                    f"{error}"
                )

    # ========================================================
    # DISPLAY RESULTS
    # ========================================================

    for device in devices:

        print(
            "\n" + "-" * 70
        )

        print(
            f"HOST: "
            f"{device['ip']}"
        )

        print(
            f"MAC: "
            f"{device['mac']}"
        )

        print(
            f"Vendor: "
            f"{device['vendor']}"
        )

        print(
            f"Hostname: "
            f"{device['hostname']}"
        )

        print(
            f"Likely Type: "
            f"{device['device_type']} "
            f"({device['confidence']}%)"
        )

        if device["open_ports"]:

            print(
                "\nOpen Ports:"
            )

            for service in device[
                "services"
            ]:

                line = (
                    f"  "
                    f"{service['port']:<5}"
                    f"{service['name']}"
                )

                if "banner" in service:

                    line += (
                        f" | "
                        f"{service['banner'][:100]}"
                    )

                print(line)

        else:

            print(
                "\nOpen Ports: None"
            )

        if device["web"]:

            print(
                "\nWeb Interfaces:"
            )

            for web_info in device[
                "web"
            ]:

                print(
                    f"  {web_info['url']}"
                )

                print(
                    f"    Status : "
                    f"{web_info['status']}"
                )

                print(
                    f"    Title  : "
                    f"{web_info['title']}"
                )

                print(
                    f"    Server : "
                    f"{web_info['server']}"
                )

        if device["rtsp"]:

            print(
                "\nRTSP:"
            )

            for rtsp in device[
                "rtsp"
            ]:

                print(
                    f"  Port: "
                    f"{rtsp['port']}"
                )

                print(
                    f"  Status: "
                    f"{rtsp['status']}"
                )

                print(
                    f"  Server: "
                    f"{rtsp['server']}"
                )

                print(
                    f"  Methods: "
                    f"{rtsp['methods']}"
                )

    duration = (
        time.time() - start
    )

    print(
        "\n" + "=" * 70
    )

    print(
        f"Scan complete in "
        f"{duration:.2f} seconds"
    )

    print("=" * 70)

    if args.json:

        save_json(
            args.json,
            network,
            devices,
            duration
        )

    if args.html:

        save_html(
            args.html,
            network,
            devices,
            duration
        )


if __name__ == "__main__":

    main()
