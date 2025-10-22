import os
import time
import datetime
import platform
import requests
import smtplib
import json
import subprocess
import socket
import netifaces
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from colorama import init, Fore
from tabulate import tabulate

init(autoreset=True)

class MITMDefense:
    def __init__(self):
        self.previous_table = {}
        self.mac_vendors = {}
        self.whitelist_macs = set()
        self.known_devices = {}
        self.alert_cooldown = {}
        
        self.WEBHOOK_URL = "https://your-webhook-url-here"
        self.EMAIL_ENABLED = False
        self.SMTP_SERVER = "smtp.gmail.com"
        self.SMTP_PORT = 587
        self.SENDER_EMAIL = "youremail@gmail.com"
        self.SENDER_PASSWORD = "yourpassword"
        self.RECEIVER_EMAIL = "targetemail@gmail.com"
        
        self.gateway_ip = self.get_gateway_ip()
        self.gateway_mac = self.get_gateway_mac()
        self.interface = self.get_default_interface()
        
        print(Fore.GREEN + f"Gateway IP: {self.gateway_ip}")
        print(Fore.GREEN + f"Gateway MAC: {self.gateway_mac}")
        print(Fore.GREEN + f"Interface: {self.interface}")

    def get_default_interface(self):
        try:
            gateway = netifaces.gateways()['default']
            return list(gateway.values())[0][1]
        except:
            return "eth0"

    def get_gateway_ip(self):
        try:
            gateway = netifaces.gateways()['default'][netifaces.AF_INET]
            return gateway[0]
        except:
            return "192.168.1.1"

    def get_gateway_mac(self):
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output(f"arp -a {self.gateway_ip}", shell=True).decode()
                for line in result.splitlines():
                    if self.gateway_ip in line:
                        parts = line.split()
                        return parts[1].replace('-', ':')
            else:
                result = subprocess.check_output(f"arp -n {self.gateway_ip}", shell=True).decode()
                for line in result.splitlines():
                    if self.gateway_ip in line:
                        parts = line.split()
                        return parts[2]
        except:
            pass
        return None

    def send_webhook_alert(self, title, description):
        try:
            data = {
                "embeds": [
                    {
                        "title": title,
                        "description": description,
                        "color": 16711680,
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                ]
            }
            headers = {"Content-Type": "application/json"}
            requests.post(self.WEBHOOK_URL, headers=headers, data=json.dumps(data), timeout=5)
        except Exception as e:
            print(Fore.YELLOW + f"[Webhook] Error: {e}")

    def send_email_alert(self, subject, content):
        if not self.EMAIL_ENABLED:
            return
        try:
            msg = MIMEMultipart()
            msg['From'] = formataddr(("MITM Alarm", self.SENDER_EMAIL))
            msg['To'] = self.RECEIVER_EMAIL
            msg['Subject'] = subject
            msg.attach(MIMEText(content, 'plain'))

            server = smtplib.SMTP(self.SMTP_SERVER, self.SMTP_PORT)
            server.starttls()
            server.login(self.SENDER_EMAIL, self.SENDER_PASSWORD)
            server.sendmail(self.SENDER_EMAIL, self.RECEIVER_EMAIL, msg.as_string())
            server.quit()
            print(Fore.GREEN + "[Email] Alert sent.")
        except Exception as e:
            print(Fore.YELLOW + f"[Email] Error: {e}")

    def get_mac_vendor(self, mac):
        if mac in self.mac_vendors:
            return self.mac_vendors[mac]
        
        if mac.startswith(('00:50:56', '00:0C:29', '00:05:69')):
            self.mac_vendors[mac] = "VMware"
            return "VMware"
        elif mac.startswith(('00:1C:42', '00:03:FF')):
            self.mac_vendors[mac] = "Parallels"
            return "Parallels"
        elif mac.startswith('00:15:5D'):
            self.mac_vendors[mac] = "Hyper-V"
            return "Hyper-V"
        
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
            if response.status_code == 200:
                vendor = response.text.strip()
                self.mac_vendors[mac] = vendor
                return vendor
            else:
                return "Unknown"
        except:
            local_vendors = {
                'aa:bb:cc': 'Example Vendor',
                '11:22:33': 'Test Manufacturer'
            }
            return local_vendors.get(mac[:8], "Unknown")

    def get_arp_table(self):
        arp_table = {}
        try:
            if platform.system() == "Windows":
                result = subprocess.check_output("arp -a", shell=True).decode('utf-8', errors='ignore')
                for line in result.splitlines():
                    if 'dynamic' in line.lower() or 'static' in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[0]
                            mac = parts[1].replace('-', ':')
                            if ip and mac and mac != 'ff:ff:ff:ff:ff:ff':
                                arp_table[ip] = mac
            else:
                result = subprocess.check_output("arp -n", shell=True).decode('utf-8', errors='ignore')
                for line in result.splitlines():
                    if 'ether' in line or 'lladdr' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            ip = parts[0]
                            mac = parts[2]
                            if ip and mac and mac != 'ff:ff:ff:ff:ff:ff':
                                arp_table[ip] = mac
        except Exception as e:
            print(Fore.RED + f"[ARP Error] {e}")
        
        return arp_table

    def is_cooldown_active(self, key):
        if key in self.alert_cooldown:
            if time.time() - self.alert_cooldown[key] < 300:
                return True
        return False

    def update_cooldown(self, key):
        self.alert_cooldown[key] = time.time()

    def detect_arp_spoofing(self):
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        current_table = self.get_arp_table()

        if not current_table:
            print(Fore.RED + "[Error] ARP table could not be read")
            return

        table_data = []
        for ip, mac in current_table.items():
            vendor = self.get_mac_vendor(mac)
            table_data.append([ip, mac, vendor])
        
        print(Fore.CYAN + f"\n🕒 {current_time} - ARP Table:")
        headers = ["IP Address", "MAC Address", "Vendor"]
        print(Fore.CYAN + tabulate(table_data, headers, tablefmt="grid"))

        for ip, mac in current_table.items():
            alert_key = f"{ip}_{mac}"
            
            if ip in self.previous_table and self.previous_table[ip] != mac:
                if not self.is_cooldown_active(alert_key):
                    title = "🚨 ARP Spoofing Detected!"
                    content = f"""Time: {current_time}
IP: {ip}
Old MAC: {self.previous_table[ip]}
New MAC: {mac}
Vendor: {self.get_mac_vendor(mac)}
Risk: HIGH - Possible MITM Attack!"""
                    
                    print(Fore.RED + f"\n[!] {title}")
                    print(Fore.RED + content)
                    print(Fore.RED + "-" * 50)
                    
                    self.send_webhook_alert(title, content)
                    self.send_email_alert(title, content)
                    self.update_cooldown(alert_key)

            elif ip == self.gateway_ip and mac != self.gateway_mac:
                if not self.is_cooldown_active("gateway_spoof"):
                    title = "🚨 Gateway Spoofing Detected!"
                    content = f"""Time: {current_time}
Gateway IP: {ip}
Expected MAC: {self.gateway_mac}
Current MAC: {mac}
Vendor: {self.get_mac_vendor(mac)}
Risk: CRITICAL - Gateway compromised!"""
                    
                    print(Fore.RED + f"\n[!] {title}")
                    print(Fore.RED + content)
                    print(Fore.RED + "-" * 50)
                    
                    self.send_webhook_alert(title, content)
                    self.send_email_alert(title, content)
                    self.update_cooldown("gateway_spoof")

            vendor = self.get_mac_vendor(mac)
            if vendor == "Unknown" and mac not in self.whitelist_macs:
                if not self.is_cooldown_active(f"unknown_{mac}"):
                    title = "⚠️ Unknown Device Detected"
                    content = f"""Time: {current_time}
IP: {ip}
MAC: {mac}
Vendor: Unknown
Note: This might be a new device or suspicious activity"""
                    
                    print(Fore.YELLOW + f"\n[!] {title}")
                    print(Fore.YELLOW + content)
                    print(Fore.YELLOW + "-" * 50)
                    
                    self.send_webhook_alert(title, content)
                    self.update_cooldown(f"unknown_{mac}")

        duplicate_macs = {}
        for ip, mac in current_table.items():
            if mac in duplicate_macs:
                duplicate_macs[mac].append(ip)
            else:
                duplicate_macs[mac] = [ip]

        for mac, ips in duplicate_macs.items():
            if len(ips) > 1 and not self.is_cooldown_active(f"duplicate_{mac}"):
                title = "🚨 Duplicate MAC Detected!"
                content = f"""Time: {current_time}
MAC: {mac}
IPs: {', '.join(ips)}
Vendor: {self.get_mac_vendor(mac)}
Risk: Possible ARP Spoofing!"""
                
                print(Fore.RED + f"\n[!] {title}")
                print(Fore.RED + content)
                print(Fore.RED + "-" * 50)
                
                self.send_webhook_alert(title, content)
                self.send_email_alert(title, content)
                self.update_cooldown(f"duplicate_{mac}")

        self.previous_table = current_table.copy()

    def add_to_whitelist(self, mac):
        self.whitelist_macs.add(mac)
        print(Fore.GREEN + f"[Whitelist] MAC {mac} added to whitelist")

    def start_monitoring(self):
        print(Fore.CYAN + "🚨 MITM Defense System Started...")
        print(Fore.CYAN + "Monitoring network for ARP spoofing attacks...")
        print(Fore.CYAN + "Press Ctrl+C to stop\n")
        
        try:
            while True:
                self.detect_arp_spoofing()
                time.sleep(10)
        except KeyboardInterrupt:
            print(Fore.CYAN + "\n🛑 MITM Defense System Stopped")

if __name__ == "__main__":
    defense = MITMDefense()
    defense.start_monitoring()
