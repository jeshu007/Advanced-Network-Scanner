import socket

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def get_service(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown"
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