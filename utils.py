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
def detect_device_type(vendor):
    vendor = vendor.lower()

    if any(x in vendor for x in ["apple", "samsung", "xiaomi", "oppo", "vivo", "oneplus"]):
        return "📱 Mobile"
    elif any(x in vendor for x in ["dell", "hp", "lenovo", "asus", "acer", "microsoft"]):
        return "💻 Laptop/PC"
    elif any(x in vendor for x in ["cisco", "tp-link", "d-link", "netgear", "huawei"]):
        return "📡 Router/Network Device"
    else:
        return "🖥️ Unknown Device"
