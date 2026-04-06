from flask import Flask, render_template, jsonify
from scanner import scan_network
from port_scanner import scan_ports
from utils import (
    get_mac_vendor,
    detect_device_type,
    get_hostname,
    get_service,
    check_vulnerability,
    get_risk_level
)
import time
import socket

app = Flask(__name__)

# 🔥 AUTO-DETECT LOCAL NETWORK
def get_network_range():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # fallback fix (Windows issue sometimes returns 127.0.0.1)
        if local_ip.startswith("127."):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()

        network = local_ip.rsplit('.', 1)[0] + ".0/24"
        return network, local_ip

    except:
        return "192.168.0.0/24", "Unknown"


IP_RANGE, LOCAL_IP = get_network_range()

device_last_seen = {}

COMMON_PORTS = [22, 23, 80, 139, 443, 445, 3306, 3389]

@app.route("/")
def index():
    return render_template("index.html", local_ip=LOCAL_IP, network=IP_RANGE)

@app.route("/scan")
def scan():
    global device_last_seen

    devices = scan_network(IP_RANGE)
    current_time = time.time()

    result = []

    for d in devices:
        ip = d['ip']
        mac = d.get('mac', 'N/A')

        device_last_seen[ip] = {
            "last_seen": current_time,
            "mac": mac
        }

    for ip, data in device_last_seen.items():
        last_seen = data["last_seen"]
        mac = data["mac"]

        hostname = get_hostname(ip)
        vendor = get_mac_vendor(mac)
        device_type = detect_device_type(vendor, ip, hostname)

        # Status
        status = "Online" if current_time - last_seen <= 10 else "Idle"

        # 🔍 Port Scan
        open_ports = scan_ports(ip, COMMON_PORTS)

        port_info = []

        for port, banner in open_ports:
            service = get_service(port)
            vuln = check_vulnerability(port, service)
            risk = get_risk_level(port, service)

            port_info.append({
                "port": port,
                "service": service,
                "vuln": vuln,
                "risk": risk
            })

        result.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "type": device_type,
            "status": status,
            "ports": port_info
        })

    return jsonify(result)


if __name__ == "__main__":
    print(f"🌐 Your IP: {LOCAL_IP}")
    print(f"📡 Scanning Network: {IP_RANGE}")
    app.run(debug=True)