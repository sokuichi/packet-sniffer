import argparse
import datetime
import logging
import threading
import signal
import sys
import os
import time
import random
import hashlib
import base64
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, simpledialog
from collections import defaultdict
import queue
import getpass

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, conf, wrpcap, ARP
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    print("error: missing dependencies. run: pip3 install scapy cryptography")
    sys.exit(1)

logging.basicConfig(filename='netlog.db', level=logging.INFO, format='%(message)s')

# ====================== CONFIG ======================
MAX_PACKETS_IN_MEMORY = 1000
PACKET_SAVE_THRESHOLD = 600
ALERT_COOLDOWN = 5
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 12
MAX_TRACKED_IPS = 300
LIVE_TRAFFIC_THROTTLE = 12
CLEANUP_INTERVAL = 50


class NetworkSniffer:
    def __init__(self):
        self.stats = defaultdict(int)
        self.lock = threading.Lock()
        self.running = True
        self.packets = []
        self.alerts = []
        self.alert_queue = queue.Queue()

        self.keywords = {'password', 'passwd', 'login', 'token', 'auth', 'api_key', 'secret', 'private',
                        'bearer', 'session', 'key', 'credential', 'credit', 'card', 'ssn', 'pin', 'bank',
                        'admin', 'root', 'vpn', 'oauth', '2fa', 'mfa', 'jwt', 'refresh_token', 'apikey',
                        'privatekey', 'secretkey'}

        self.capture_file = 'capture.pcap'
        self.encrypted_log = 'secure_netlog.enc'
        self.key_file = '.key_secure'
        self.salt_file = '.salt_secure'

        self.cipher = None
        self.gui = None
        self.suspicious_ips = defaultdict(int)
        self.port_scan_tracker = defaultdict(list)
        self.last_alert_time = defaultdict(float)
        self.bpf_filter = "tcp or udp"
        self.live_counter = 0
        self.packet_counter = 0
        self.max_retries = 12
        self.version = "2.1"

        self.load_or_create_key()

    # ==================== KEY MANAGEMENT ====================
    def generate_secure_salt(self):
        if os.path.exists(self.salt_file):
            try:
                with open(self.salt_file, 'rb') as f:
                    return f.read()
            except Exception:
                pass
        salt = os.urandom(32)
        try:
            with open(self.salt_file, 'wb') as f:
                f.write(salt)
        except Exception:
            pass
        return salt

    def load_or_create_key(self):
        salt = self.generate_secure_salt()
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    self.key = f.read()
                self.cipher = Fernet(self.key)
            else:
                password = getpass.getpass("Enter master password for encryption: ")
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=650000)
                derived = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                self.key = derived
                self.cipher = Fernet(derived)
                with open(self.key_file, 'wb') as f:
                    f.write(derived)
        except Exception as e:
            print(f"[!] Key setup warning: {e}. Using fallback.")
            fallback = hashlib.sha256(salt + os.urandom(48)).digest()
            self.key = base64.urlsafe_b64encode(fallback)
            self.cipher = Fernet(self.key)

    def change_key(self):
        try:
            new_pass = simpledialog.askstring("Key Management", "New master password (min 8 chars):", show='*')
            if not new_pass or len(new_pass) < 8:
                messagebox.showwarning("Invalid", "Password must be at least 8 characters.")
                return
            salt = self.generate_secure_salt()
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=650000)
            new_key = base64.urlsafe_b64encode(kdf.derive(new_pass.encode()))
            self.key = new_key
            self.cipher = Fernet(new_key)
            with open(self.key_file, 'wb') as f:
                f.write(new_key)
            messagebox.showinfo("Success", "Encryption key updated.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change key: {e}")

    def encrypt_data(self, data):
        try:
            return self.cipher.encrypt(data.encode('utf-8'))
        except Exception:
            return base64.b64encode(data.encode('utf-8'))

    def secure_log(self, message):
        try:
            enc = self.encrypt_data(message)
            with open(self.encrypted_log, 'ab') as f:
                f.write(enc + b'\n')
        except Exception:
            pass

    # ==================== UTILITIES ====================
    def get_interfaces(self):
        try:
            return list(conf.ifaces.keys())
        except Exception:
            return ['eth0', 'wlan0', 'en0', 'Wi-Fi', 'Ethernet']

    def interface_exists(self, iface):
        return iface in self.get_interfaces()

    def auto_select_interface(self):
        for iface in self.get_interfaces():
            try:
                sniff(iface=iface, count=1, timeout=1, store=False)
                return iface
            except Exception:
                continue
        return self.get_interfaces()[0] if self.get_interfaces() else None

    def should_rate_limit_alert(self, alert_type):
        now = time.time()
        if now - self.last_alert_time[alert_type] < ALERT_COOLDOWN:
            return True
        self.last_alert_time[alert_type] = now
        return False

    def clean_old_tracking_data(self):
        now = time.time()
        for ip in list(self.port_scan_tracker.keys()):
            self.port_scan_tracker[ip] = [p for p in self.port_scan_tracker[ip] if now - p[1] < PORT_SCAN_WINDOW]
            if not self.port_scan_tracker[ip]:
                self.port_scan_tracker.pop(ip, None)
        if len(self.suspicious_ips) > MAX_TRACKED_IPS:
            self.suspicious_ips = defaultdict(int, dict(sorted(self.suspicious_ips.items(), key=lambda x: x[1], reverse=True)[:MAX_TRACKED_IPS]))

    def process_payload(self, raw_load):
        try:
            return raw_load.decode('utf-8', errors='ignore').lower()
        except Exception:
            return str(raw_load)[:400].lower()

    # ==================== CORE LOGIC ====================
    def detect_intrusion(self, packet, src, dst):
        sensitive_found = False
        if Raw in packet:
            try:
                payload_lower = self.process_payload(packet[Raw].load)
                for kw in self.keywords:
                    if kw in payload_lower:
                        ts = datetime.datetime.now().strftime('%H:%M:%S')
                        msg = f"SENSITIVE|{ts}|{src}->{dst}|{kw}"
                        logging.info(msg)
                        self.secure_log(msg)
                        sensitive_found = True
                        break
            except Exception:
                pass

        if TCP in packet:
            dport = packet[TCP].dport
            self.port_scan_tracker[src].append((dport, time.time()))
            recent = [p for p in self.port_scan_tracker[src] if time.time() - p[1] < PORT_SCAN_WINDOW]
            if len(recent) > PORT_SCAN_THRESHOLD:
                if not self.should_rate_limit_alert("portscan"):
                    self.alert_queue.put(("HIGH", f"PORT SCAN from {src}"))

        if ARP in packet and packet[ARP].op == 1:
            if not self.should_rate_limit_alert("arp"):
                self.alert_queue.put(("LOW", f"ARP Request from {src}"))

        if sensitive_found and not self.should_rate_limit_alert("sensitive"):
            self.alert_queue.put(("CRITICAL", f"SENSITIVE DATA | {src} → {dst}"))

    def packet_handler(self, packet):
        if not self.running or IP not in packet:
            return

        src = packet[IP].src
        dst = packet[IP].dst
        self.packet_counter += 1

        with self.lock:
            self.stats['total'] += 1
            self.packets.append(packet)

            if len(self.packets) > MAX_PACKETS_IN_MEMORY:
                try:
                    wrpcap(self.capture_file, self.packets[-PACKET_SAVE_THRESHOLD:], append=True)
                    self.packets = self.packets[-500:]
                except Exception:
                    pass

            if TCP in packet:
                self.stats['tcp'] += 1
            elif UDP in packet:
                self.stats['udp'] += 1

        self.detect_intrusion(packet, src, dst)

        # Periodic cleanup
        if self.packet_counter % CLEANUP_INTERVAL == 0:
            self.clean_old_tracking_data()

        # Live Traffic (throttled + no redundant keyword check)
        if self.gui and self.packet_counter % LIVE_TRAFFIC_THROTTLE == 0:
            try:
                payload_preview = ""
                if Raw in packet:
                    payload_preview = self.process_payload(packet[Raw].load)[:100]
                entry = f"{datetime.datetime.now().strftime('%H:%M:%S')} | {src:15} → {dst:15} | {payload_preview}\n"
                self.gui.update_live_traffic(entry)
            except Exception:
                pass

    def stats_reporter(self):
        while self.running:
            time.sleep(7)
            with self.lock:
                if self.gui and self.stats['total'] > 0:
                    stats_str = (f"Total Packets     : {self.stats['total']:,}\n"
                                f"TCP Packets       : {self.stats['tcp']:,}\n"
                                f"UDP Packets       : {self.stats['udp']:,}\n"
                                f"Alerts Generated  : {len(self.alerts)}\n"
                                f"Tracked IPs       : {len(self.suspicious_ips)}")
                    self.gui.update_stats(stats_str)

    def gui_updater(self):
        while self.running:
            try:
                while not self.alert_queue.empty():
                    level, alert = self.alert_queue.get_nowait()
                    self.alerts.append(alert)
                    if self.gui:
                        self.gui.log_alert(level, alert)
                time.sleep(0.1)
            except Exception:
                time.sleep(0.5)

    def retry_sniff(self, iface, filter_str, timeout):
        for attempt in range(self.max_retries):
            if not self.running:
                return
            try:
                if not self.interface_exists(iface):
                    print(f"[!] Interface {iface} not found.")
                    return
                print(f"[*] Starting capture on {iface} | Filter: {filter_str}")
                sniff(iface=iface, filter=filter_str, prn=self.packet_handler, store=False,
                      timeout=timeout if timeout > 0 else None,
                      stop_filter=lambda x: not self.running)
                return
            except Exception as e:
                print(f"[!] Sniff attempt {attempt+1} failed: {e}")
                time.sleep(random.uniform(2.5, 6.5))
        print("[!] Max retries reached.")
        self.running = False

    def stop(self, sig=None, frame=None):
        self.running = False
        try:
            if self.packets:
                wrpcap(self.capture_file, self.packets, append=True)
        except Exception:
            pass
        sys.exit(0)

    def run(self):
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("-i", "--iface", default=None)
        parser.add_argument("-l", "--list", action="store_true")
        parser.add_argument("-f", "--filter", default="")
        parser.add_argument("-t", "--time", type=int, default=0)
        parser.add_argument("--daemon", action="store_true")
        parser.add_argument("-o", "--output", default="capture.pcap")
        args = parser.parse_args()

        self.capture_file = args.output
        if args.filter:
            self.bpf_filter = args.filter

        if args.list:
            for iface in self.get_interfaces():
                print(iface)
            return

        if args.daemon:
            logging.getLogger().setLevel(logging.WARNING)
            signal.signal(signal.SIGINT, self.stop)
            signal.signal(signal.SIGTERM, self.stop)
            threading.Thread(target=self.stats_reporter, daemon=True).start()
            iface = args.iface or self.auto_select_interface() or self.get_interfaces()[0]
            self.retry_sniff(iface, self.bpf_filter, args.time)
            return

        self.gui = SnifferGUI(self, self.version)
        threading.Thread(target=self.stats_reporter, daemon=True).start()
        threading.Thread(target=self.gui_updater, daemon=True).start()

        iface = args.iface or self.auto_select_interface() or self.get_interfaces()[0]
        sniff_thread = threading.Thread(target=self.retry_sniff,
                                        args=(iface, self.bpf_filter, args.time),
                                        daemon=True)
        sniff_thread.start()
        self.gui.root.mainloop()


class SnifferGUI:
    def __init__(self, sniffer, version):
        self.sniffer = sniffer
        self.root = tk.Tk()
        self.root.title(f"Advanced Network Sniffer + IDS v{version}")
        self.root.geometry("1350x900")
        self.create_widgets()

    def create_widgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True)

        tab1 = ttk.Frame(notebook)
        tab2 = ttk.Frame(notebook)
        tab3 = ttk.Frame(notebook)

        notebook.add(tab1, text="Live Traffic")
        notebook.add(tab2, text="Alerts & IDS")
        notebook.add(tab3, text="Statistics")

        self.live_text = scrolledtext.ScrolledText(tab1, height=42, font=("Consolas", 10))
        self.live_text.pack(fill='both', expand=True)

        self.alert_text = scrolledtext.ScrolledText(tab2, height=42, fg="#ff4444", font=("Consolas", 10))
        self.alert_text.pack(fill='both', expand=True)

        self.stats_text = scrolledtext.ScrolledText(tab3, height=38, font=("Consolas", 11))
        self.stats_text.pack(fill='both', expand=True)

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill='x', pady=10)
        ttk.Button(btn_frame, text="Stop", command=self.stop_sniff).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Clear", command=self.clear_logs).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Save PCAP", command=self.save_pcap).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Export Alerts", command=self.export_alerts).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Change Key", command=self.sniffer.change_key).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Exit", command=self.root.quit).pack(side='right', padx=5)

    def update_live_traffic(self, text):
        self.live_text.insert(tk.END, text)
        self.live_text.see(tk.END)
        if int(self.live_text.index('end-1c').split('.')[0]) > 700:
            self.live_text.delete(1.0, 150.0)

    def log_alert(self, level, message):
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        entry = f"[{level}] {ts} | {message}\n"
        self.alert_text.insert(tk.END, entry)
        self.alert_text.see(tk.END)

    def update_stats(self, stats_str):
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_str)

    def stop_sniff(self):
        self.sniffer.running = False
        self.root.quit()

    def clear_logs(self):
        self.live_text.delete(1.0, tk.END)
        self.alert_text.delete(1.0, tk.END)

    def save_pcap(self):
        try:
            if self.sniffer.packets:
                wrpcap("final_capture.pcap", self.sniffer.packets)
                messagebox.showinfo("Success", "PCAP saved as final_capture.pcap")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save PCAP: {e}")

    def export_alerts(self):
        try:
            with open("alerts_export.txt", "w") as f:
                f.write(self.alert_text.get(1.0, tk.END))
            messagebox.showinfo("Exported", "Alerts exported to alerts_export.txt")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")


if os.geteuid() != 0 and sys.platform != "win32":
    try:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    except Exception:
        pass

sniffer = NetworkSniffer()
sniffer.run()