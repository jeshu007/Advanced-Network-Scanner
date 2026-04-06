from scanner import scan_network
import time
from datetime import datetime

device_last_seen = {}

TIMEOUT = 30   # remove device after 30 sec

def monitor_network(ip_range):
    print("\n📡 Stable Network Monitoring Started...\n")

    while True:
        try:
            devices = scan_network(ip_range)
            current_time = time.time()

            # Update last seen time
            for d in devices:
                ip = d['ip']
                device_last_seen[ip] = current_time

            timestamp = datetime.now().strftime("%H:%M:%S")

            active_count = 0

            print(f"\n[{timestamp}] 📊 Device Status:")

            for ip, last_seen in list(device_last_seen.items()):

                # ❌ Remove if timeout exceeded
                if current_time - last_seen > TIMEOUT:
                    print(f"   ❌ Removed: {ip}")
                    del device_last_seen[ip]
                    continue

                # 🟢 / 🟡 Status logic
                if current_time - last_seen <= 10:
                    status = "🟢 Online"
                else:
                    status = "🟡 Idle"

                print(f"   {ip} → {status}")
                active_count += 1

            print(f"\n🔄 Stable Devices: {active_count}")

            time.sleep(10)

        except KeyboardInterrupt:
            print("\n🛑 Monitoring Stopped")
            break


if __name__ == "__main__":
    ip_range = input("Network IP Range: ") or "192.168.0.0/24"
    monitor_network(ip_range)