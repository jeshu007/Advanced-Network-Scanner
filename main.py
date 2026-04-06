from scanner import scan_network
from port_scanner import scan_ports
from utils import (
    get_hostname,
    get_service,
    check_vulnerability,
    get_mac_vendor,
    detect_device_type,
    get_risk_level,
    detect_os,
    detect_suspicious
)
import csv
import time
from colorama import Fore, init

init(autoreset=True)

print(Fore.GREEN + "🚀 Scan Started...\n")

start_time = time.time()

ip_range = input("Enter network (e.g. 192.168.1.0/24): ")

devices = scan_network(ip_range)

print(Fore.CYAN + "\n🔎 Active Devices:")

# Counters
routers = mobiles = pcs = unknown = 0

results = []

for device in devices:
    ip = device['ip']
    mac = device.get('mac', 'N/A')

    hostname = get_hostname(ip)
    vendor = get_mac_vendor(mac)
    device_type = detect_device_type(vendor, ip, hostname)

    print(Fore.YELLOW + f"\n==============================")
    print(Fore.YELLOW + f"📡 Device: {ip}")
    print(f"  🧾 MAC: {mac}")
    print(f"  🏢 Vendor: {vendor}")
    print(f"  💻 Type: {device_type}")

    # Count devices
    if "Router" in device_type:
        routers += 1
    elif "Mobile" in device_type:
        mobiles += 1
    elif "Laptop" in device_type or "PC" in device_type:
        pcs += 1
    else:
        unknown += 1

    print(Fore.MAGENTA + f"\n🔍 Scanning Ports on {ip}...")

    common_ports = [
        20,21,22,23,25,53,67,68,69,80,110,119,123,137,138,139,
        143,161,179,389,443,445,465,500,587,636,989,990,993,995,
        1433,1521,2049,2082,2083,2086,2087,2095,2096,2181,2483,
        2484,3000,3306,3389,3690,4444,4664,4672,5000,5432,5601,
        5900,5985,6379,6667,7001,8000,8008,8080,8081,8443,8888,
        9000,9042,9090,9200,9418,27017
    ]

    ports = scan_ports(ip, common_ports)

    # ✅ OS Detection
    os_type = detect_os(ports)
    print(Fore.BLUE + f"  🖥️ OS: {os_type}")

    for port, banner in ports:
        service = get_service(port)
        vuln = check_vulnerability(port, service)
        risk = get_risk_level(port, service)
        suspicious = detect_suspicious(port)

        # Port Output
        if banner:
            print(Fore.GREEN + f"{ip}:{port} OPEN ({service}) | {banner}")
        else:
            print(Fore.GREEN + f"{ip}:{port} OPEN ({service})")

        # Risk Level
        print(f"  📊 Risk: {risk}")

        # Vulnerability
        if vuln:
            print(Fore.RED + f"  ⚠️ Vulnerability: {vuln}")

        # Suspicious Activity
        if suspicious:
            print(Fore.RED + f"  🚨 Suspicious: {suspicious}")

        results.append([
            ip, hostname, mac, vendor, device_type, os_type,
            port, service, banner, risk, vuln, suspicious
        ])

# ✅ Network Summary
print(Fore.CYAN + "\n📊 --- Network Summary ---")
print(f"🛜 Routers: {routers}")
print(f"📱 Mobiles: {mobiles}")
print(f"💻 PCs: {pcs}")
print(f"❓ Unknown: {unknown}")
print(f"📡 Total Devices: {len(devices)}")

# ✅ Scan Time
end_time = time.time()
print(Fore.YELLOW + f"\n⏱️ Scan Time: {round(end_time - start_time, 2)} seconds")

# ✅ Save results
with open("results.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow([
        "IP", "Hostname", "MAC", "Vendor", "Device Type", "OS",
        "Port", "Service", "Banner", "Risk", "Vulnerability", "Suspicious"
    ])
    writer.writerows(results)

print(Fore.GREEN + "\n✅ Scan completed. Results saved to results.csv")
