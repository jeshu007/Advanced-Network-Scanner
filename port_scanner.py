import socket
import threading

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(1)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        return banner
    except:
        return ""

def scan_ports(ip, ports):
    open_ports = []

    def scan_port(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)

        if s.connect_ex((ip, port)) == 0:
            banner = grab_banner(ip, port)
            open_ports.append((port, banner))

        s.close()

    threads = []

    for port in ports:
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return open_ports