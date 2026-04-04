from scanner import scan_network
from port_scanner import scan_ports
from utils import get_hostname, get_service, check_vulnerability
import csv

ip_range = input("Enter network (e.g. 192.168.1.0/24): ")

devices = scan_network(ip_range)

print("\nActive Devices:")
for device in devices:
    print(device['ip'], device['mac'])

results = []

for device in devices:
    ip = device['ip']
    print(f"\nScanning {ip}...")

    common_ports = [20,21,22,23,25,53,67,68,69,80,110,119,123,137,138,139,143,161,179,389,443,445,465,500,587,636,989,990,993,995,1433,1521,2049,2082,2083,2086,2087,2095,2096,2181,2483,2484,3000,3306,3389,3690,4444,4664,4672,5000,5432,5601,5900,5985,6379,6667,7001,8000,8008,8080,8081,8443,8888,9000,9042,9090,9200,9418,27017]
    ports = scan_ports(ip, common_ports)
    hostname = get_hostname(ip)

    for port, banner in ports:
        service = get_service(port)
        vuln = check_vulnerability(port, service)

        if banner:
            print(f"{ip}:{port} OPEN ({service}) | Banner: {banner}")
        else:
            print(f"{ip}:{port} OPEN ({service})")

        if vuln:
            print(f"  ⚠️ Vulnerability: {vuln}")

        results.append([ip, hostname, port, service, banner, vuln])

# Save results
with open("results.csv", "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["IP", "Hostname", "Port", "Service", "Banner", "Vulnerability"])
    writer.writerows(results)

print("\nScan completed. Results saved to results.csv")
from colorama import Fore, init
init()

print(Fore.GREEN + "Scan Started...")