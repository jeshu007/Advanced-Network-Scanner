import socket
import requests

# 🔹 Get Hostname
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"


# 🔹 Get Service Name from Port
def get_service(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"


# 🔹 Basic Vulnerability Check
def check_vulnerability(port, service):
    vulnerabilities = {
        21: "FTP may allow anonymous login",
        23: "Telnet is insecure (no encryption)",
        80: "HTTP is not secure (use HTTPS)",
        139: "NetBIOS exposure (internal network risk)",
        445: "SMB vulnerable to attacks (e.g. WannaCry)",
        3389: "RDP exposed (brute-force risk)"
    }
    return vulnerabilities.get(port, "")


# 🔥 NEW PART STARTS HERE

# 🔹 Get Vendor from MAC Address (API)
def get_mac_vendor(mac):
    try:
        url = f"https://api.macvendors.com/{mac}"
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            return response.text
    except:
        pass
    return "Unknown"


# 🔹 Detect Device Type
def detect_device_type(vendor, ip, hostname):
    vendor = vendor.lower()
    hostname = hostname.lower()

    # Router
    if ip.endswith(".1") or any(x in vendor for x in ["tenda", "tp-link", "d-link", "netgear", "huawei"]):
        return "📡 Router"

    # Mobile
    elif any(x in vendor for x in ["apple", "samsung", "xiaomi", "oppo", "vivo", "oneplus"]):
        return "📱 Mobile"

    # PC / Laptop
    elif any(x in vendor for x in ["intel", "realtek", "dell", "hp", "lenovo", "asus", "acer"]) \
         or "pc" in hostname or "desktop" in hostname:
        return "💻 Laptop/PC"

    else:
        return "🖥️ Unknown Device"
    
def get_risk_level(port, service):
    high_risk = [21, 23, 445, 3389]
    medium_risk = [80, 139, 137]
    low_risk = [22, 443]

    if port in high_risk:
        return "🔴 HIGH RISK"
    elif port in medium_risk:
        return "🟠 MEDIUM RISK"
    elif port in low_risk:
        return "🟢 LOW RISK"
    else:
        return "⚪ UNKNOWN"
    
def detect_os(open_ports):
    ports = [p for p, _ in open_ports]

    if 3389 in ports or 445 in ports:
        return "🪟 Windows"
    elif 22 in ports:
        return "🐧 Linux"
    elif 5555 in ports:
        return "📱 Android"
    else:
        return "❓ Unknown OS"
    
def detect_suspicious(port):
    suspicious_ports = {
        4444: "Metasploit backdoor",
        5555: "ADB (Android Debugging)",
        6667: "IRC (possible botnet)",
        31337: "Back Orifice trojan"
    }
    return suspicious_ports.get(port, "")
