import os
import time
import datetime
import platform
import requests
import smtplib
import json
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from colorama import init, Fore
from tabulate import tabulate

init(autoreset=True)

previous_table = {}
mac_vendors = {}

# Webhook URL (Discord veya başka sistem)
WEBHOOK_URL = "https://your-webhook-url-here"

# E-posta alarm ayarları
EMAIL_ENABLED = False
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "youremail@gmail.com"
SENDER_PASSWORD = "yourpassword"
RECEIVER_EMAIL = "targetemail@gmail.com"

# Gateway MAC adresi başlangıçta alınır
def get_gateway_mac():
    try:
        result = subprocess.check_output("arp -a", shell=True).decode()
        for line in result.splitlines():
            if "gateway" in line.lower() or "192.168.1.1" in line:
                return line.split()[1]
    except:
        return None

KNOWN_GATEWAY_MAC = get_gateway_mac()

def send_webhook_alert(title, description):
    try:
        data = {
            "embeds": [
                {
                    "title": title,
                    "description": description,
                    "color": 16711680
                }
            ]
        }
        headers = {"Content-Type": "application/json"}
        requests.post(WEBHOOK_URL, headers=headers, data=json.dumps(data))
    except Exception as e:
        print(Fore.YELLOW + f"[Webhook] Gönderilemedi: {e}")

def send_email_alert(subject, content):
    if not EMAIL_ENABLED:
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = formataddr(("MITM Alarm", SENDER_EMAIL))
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = subject
        msg.attach(MIMEText(content, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print(Fore.GREEN + "[Email] Alarm e-posta ile gönderildi.")
    except Exception as e:
        print(Fore.YELLOW + f"[Email] Gönderilemedi: {e}")

def get_mac_vendor(mac):
    if mac in mac_vendors:
        return mac_vendors[mac]
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if response.status_code == 200:
            vendor = response.text.strip()
            mac_vendors[mac] = vendor
            return vendor
        else:
            return "Bilinmiyor"
    except:
        return "Bilinmiyor"

def get_arp_table():
    system = platform.system()
    if system == "Windows":
        arp_output = os.popen("arp -a").read().splitlines()
    else:
        arp_output = os.popen("arp -n").read().splitlines()
    return arp_output

def parse_arp_table(arp_output):
    arp_table = {}
    for line in arp_output:
        if "dynamic" in line or ("ether" in line and ("eth" in line or "wlan" in line)):
            try:
                parts = line.split()
                ip = parts[0]
                mac = parts[1]
                arp_table[ip] = mac
            except IndexError:
                continue
    return arp_table

def display_table(arp_data):
    table = [(ip, mac, get_mac_vendor(mac)) for ip, mac in arp_data.items()]
    headers = ["IP Adresi", "MAC Adresi", "Üretici"]
    print(Fore.CYAN + tabulate(table, headers, tablefmt="fancy_grid"))

def detect_arp_spoofing():
    global previous_table
    current_time = datetime.datetime.now().strftime("%H:%M:%S")
    arp_output = get_arp_table()
    current_table = parse_arp_table(arp_output)

    display_table(current_table)

    for ip, mac in current_table.items():
        vendor = get_mac_vendor(mac)
        if ip in previous_table and previous_table[ip] != mac:
            title = "🚨 ARP Spoofing Tespit Edildi!"
            content = f"Saat: {current_time}\nIP: {ip}\nEski MAC: {previous_table[ip]}\nYeni MAC: {mac}\nÜretici: {vendor}"
            print(Fore.RED + f"\n[!] {title}\n{content}\n" + "-" * 50)
            send_webhook_alert(title, content)
            send_email_alert(title, content)

        elif vendor.lower() in ["unknown", "private", ""]:
            title = "⚠️ Şüpheli Cihaz Tespit Edildi"
            content = f"Saat: {current_time}\nIP: {ip}\nMAC: {mac}\nÜretici Bilinmiyor veya Gizli"
            print(Fore.MAGENTA + f"\n[!] {title}\n{content}\n" + "-" * 50)
            send_webhook_alert(title, content)
            send_email_alert(title, content)

    if KNOWN_GATEWAY_MAC:
        gateway_mac_now = get_gateway_mac()
        if gateway_mac_now and gateway_mac_now != KNOWN_GATEWAY_MAC:
            title = "🚨 Gateway MAC Adresi Değişti!"
            content = f"Saat: {current_time}\nBeklenen MAC: {KNOWN_GATEWAY_MAC}\nŞu Anki MAC: {gateway_mac_now}"
            print(Fore.YELLOW + f"\n[!] {title}\n{content}\n" + "-" * 50)
            send_webhook_alert(title, content)
            send_email_alert(title, content)

    previous_table = current_table

print(Fore.CYAN + "🚨 MITM Defense Sistemi Başladı. Takip ediliyor...")
while True:
    detect_arp_spoofing()
    time.sleep(10)
