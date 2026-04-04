import tkinter as tk
from tkinter import scrolledtext
from scanner import scan_network
from port_scanner import scan_ports
from utils import (
    get_hostname,
    get_service,
    check_vulnerability,
    get_mac_vendor,
    detect_device_type
)

def start_scan():
    status.config(text="Status: Scanning...")
    root.update()
    output.delete(1.0, tk.END)

    ip_range = entry.get()
    output.insert(tk.END, f"Scanning {ip_range}...\n\n")

    devices = scan_network(ip_range)

    for device in devices:
        ip = device['ip']
        mac = device.get('mac', 'N/A')

        hostname = get_hostname(ip)
        vendor = get_mac_vendor(mac)
        device_type = detect_device_type(vendor)

        output.insert(
            tk.END,
            f"\nDevice: {ip} ({hostname})\n"
            f"  MAC: {mac}\n"
            f"  Vendor: {vendor}\n"
            f"  Type: {device_type}\n",
            "info"
        )

        common_ports = [
            20,21,22,23,25,53,67,68,69,80,110,119,123,137,138,139,
            143,161,179,389,443,445,465,500,587,636,989,990,993,995,
            1433,1521,2049,2082,2083,2086,2087,2095,2096,2181,2483,
            2484,3000,3306,3389,3690,4444,4664,4672,5000,5432,5601,
            5900,5985,6379,6667,7001,8000,8008,8080,8081,8443,8888,
            9000,9042,9090,9200,9418,27017
        ]

        ports = scan_ports(ip, common_ports)

        for port, banner in ports:
            service = get_service(port)
            vuln = check_vulnerability(port, service)

            line = f"  Port {port} OPEN ({service})"
            if banner:
                line += f" | {banner}"

            output.insert(tk.END, line + "\n", "open")

            if vuln:
                output.insert(tk.END, f"    ⚠️ {vuln}\n", "vuln")

    # ✅ Total Devices Count
    output.insert(tk.END, f"\nTotal Devices: {len(devices)}\n", "summary")

    status.config(text="Status: Completed")


# GUI Window
root = tk.Tk()
root.configure(bg="#1e1e1e")
root.title("⚡ Advanced Network Security Scanner")
root.geometry("700x500")

# Input Field
label = tk.Label(
    root,
    text="Enter Network (e.g. 192.168.1.0/24):",
    bg="#1e1e1e",
    fg="white"
)
label.pack()

entry = tk.Entry(
    root,
    width=40,
    bg="#2d2d2d",
    fg="white",
    insertbackground="white"
)
entry.pack()

# Scan Button
scan_button = tk.Button(
    root,
    text="Start Scan",
    command=start_scan,
    bg="#3c3f41",
    fg="white",
    activebackground="#5a5a5a"
)
scan_button.pack()

# Status Label
status = tk.Label(
    root,
    text="Status: Idle",
    bg="#1e1e1e",
    fg="lightgreen"
)
status.pack()

# Clear Button
clear_btn = tk.Button(
    root,
    text="Clear Output",
    command=lambda: output.delete(1.0, tk.END),
    bg="#3c3f41",
    fg="white",
    activebackground="#5a5a5a"
)
clear_btn.pack()

# Output Box
output = scrolledtext.ScrolledText(
    root,
    width=80,
    height=25,
    bg="#1e1e1e",
    fg="white",
    insertbackground="white"
)
output.pack()

# Styling
output.tag_config("open", foreground="#00ff00")
output.tag_config("vuln", foreground="#ff4d4d")
output.tag_config("info", foreground="#4da6ff")
output.tag_config("summary", foreground="#ffff00")

# Run App
root.mainloop()
