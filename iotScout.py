#!/usr/bin/env python3

import csv
import ipaddress
import os
import queue
import re
import socket
import struct
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from urllib.request import Request, urlopen
import ssl

DEFAULT_PORTS = "80,443,554,8000,8080,8443,1883,8883"
SERVICE_MAP = {
    80: "HTTP", 443: "HTTPS", 554: "RTSP",
    8000: "HTTP/IoT", 8080: "HTTP", 8443: "HTTPS",
    1883: "MQTT", 8883: "MQTT-TLS"
}

SSDP_MX = 2
SSDP_ST = "ssdp:all"
MDNS_ADDR = ("224.0.0.251", 5353)

def normalize_mac(mac):
    if not mac:
        return ""
    h = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(h) != 12:
        return mac.upper()
    return ":".join(h[i:i+2] for i in range(0, 12, 2)).upper()

def local_oui_db():
    db = {}
    candidates = [
        os.path.join(os.path.dirname(__file__), "oui.txt"),
        os.path.join(os.getcwd(), "oui.txt"),
    ]
    for filename in candidates:
        if not os.path.isfile(filename):
            continue
        try:
            with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Accept CSV, tab, or whitespace-separated forms.
                    m = re.match(r"^\s*([0-9A-Fa-f]{2}[-: ]?[0-9A-Fa-f]{2}[-: ]?[0-9A-Fa-f]{2})\s*[,;\t ]+\s*(.+?)\s*$", line)
                    if m:
                        oui = re.sub(r"[^0-9A-Fa-f]", "", m.group(1)).upper()
                        db[oui] = m.group(2).strip()
            break
        except OSError:
            pass
    return db

def oui_vendor(mac, db):
    h = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    return db.get(h[:6], "Unknown")

def arp_table():

    found = {}
    try:
        if os.name == "nt":
            out = subprocess.check_output(["arp", "-a"], text=True,
                                          errors="ignore", timeout=5)
            for line in out.splitlines():
                m = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\w+)",
                    line
                )
                if m:
                    found[m.group(1)] = normalize_mac(m.group(2))
        else:
            out = subprocess.check_output(["ip", "neigh"], text=True,
                                          errors="ignore", timeout=5)
            for line in out.splitlines():
                m = re.search(
                    r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]{17})",
                    line
                )
                if m:
                    found[m.group(1)] = normalize_mac(m.group(2))
    except Exception:
        pass
    return found

def hostname_for(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def parse_ssdp_headers(raw):
    text = raw.decode("utf-8", "ignore")
    lines = text.split("\r\n")
    data = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip().upper()] = v.strip()
    return data

def ssdp_discover(timeout=2.5):

    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode()

    results = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(0.4)
    try:
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(8192)
                headers = parse_ssdp_headers(data)
                results.append({
                    "ip": addr[0],
                    "port": 1900,
                    "service": "SSDP/UPnP",
                    "title": headers.get("SERVER", ""),
                    "server": headers.get("SERVER", ""),
                    "detail": headers.get("ST", "") or headers.get("USN", ""),
                })
            except socket.timeout:
                continue
    except OSError:
        pass
    finally:
        s.close()

    unique = {}
    for r in results:
        unique[(r["ip"], r["detail"], r["server"])] = r
    return list(unique.values())

def decode_dns_name(packet, offset):
    labels = []
    jumped = False
    original = offset
    seen = set()
    while offset < len(packet):
        if offset in seen:
            break
        seen.add(offset)
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(packet):
                break
            ptr = ((length & 0x3F) << 8) | packet[offset + 1]
            part, _ = decode_dns_name(packet, ptr)
            labels.append(part)
            offset += 2
            jumped = True
            break
        offset += 1
        if offset + length > len(packet):
            break
        labels.append(packet[offset:offset+length].decode("utf-8", "ignore"))
        offset += length
    return ".".join(x for x in labels if x), offset if not jumped else original + 2

def mdns_query(timeout=2.0):

    services = [
        "_services._dns-sd._udp.local",
        "_http._tcp.local",
        "_ipp._tcp.local",
        "_printer._tcp.local",
        "_googlecast._tcp.local",
        "_airplay._tcp.local",
        "_rtsp._tcp.local",
    ]

    def encode_name(name):
        return b"".join(bytes([len(x)]) + x.encode() for x in name.split(".")) + b"\x00"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    except OSError:
        pass
    sock.settimeout(0.25)

    results = []
    try:
        for service in services:
            # ID=0, flags=0, QDCOUNT=1, no answers/authority/additional.
            header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
            question = encode_name(service) + struct.pack("!HH", 12, 1)  # PTR/IN
            sock.sendto(header + question, MDNS_ADDR)

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                packet, addr = sock.recvfrom(9000)
            except socket.timeout:
                continue
            if len(packet) < 12:
                continue

            qd, an, ns, ar = struct.unpack("!HHHH", packet[4:12])
            offset = 12
            try:
                for _ in range(qd):
                    _, offset = decode_dns_name(packet, offset)
                    offset += 4

                # Parse answer records enough to extract names and PTR targets.
                for _ in range(an + ns + ar):
                    name, offset = decode_dns_name(packet, offset)
                    if offset + 10 > len(packet):
                        break
                    rtype, rclass, ttl, rdlen = struct.unpack(
                        "!HHIH", packet[offset:offset+10]
                    )
                    offset += 10
                    rdata_start = offset
                    if offset + rdlen > len(packet):
                        break

                    target = ""
                    if rtype == 12:  # PTR
                        target, _ = decode_dns_name(packet, offset)

                    if name or target:
                        results.append({
                            "ip": addr[0],
                            "port": 5353,
                            "service": "mDNS",
                            "title": target or name,
                            "server": "",
                            "detail": name
                        })
                    offset = rdata_start + rdlen
            except Exception:
                continue
    except OSError:
        pass
    finally:
        sock.close()

    unique = {}
    for r in results:
        unique[(r["ip"], r["title"], r["detail"])] = r
    return list(unique.values())

def classify_device(rows, vendor="", hostname=""):
    text = " ".join(
        str(x).lower() for r in rows for x in
        (r.get("title", ""), r.get("server", ""), r.get("service", ""),
         r.get("detail", ""))
    )
    text += " " + vendor.lower() + " " + hostname.lower()

    rules = [
        ("Camera", ["rtsp", "hikvision", "dahua", "onvif", "ipcam", "camera", "axis"]),
        ("Smart TV", ["googlecast", "chromecast", "airplay", "smart-tv", "roku", "samsung tv", "lg tv"]),
        ("Printer", ["ipp", "printer", "jetdirect", "print", "epson", "brother", "canon"]),
        ("Router / AP", ["router", "gateway", "access point", "mikrotik", "openwrt", "dd-wrt", "tp-link"]),
        ("NAS", ["nas", "synology", "qnap", "storage"]),
        ("IoT / Smart Home", ["mqtt", "homeassistant", "home-assistant", "tuya", "espressif", "shelly", "tasmota"]),
        ("Media Device", ["dlna", "upnp", "mediaserver", "media server"]),
    ]
    for device, needles in rules:
        if any(n in text for n in needles):
            return device
    if any(r.get("service") in ("SSDP/UPnP", "mDNS") for r in rows):
        return "Smart / Network Device"
    return "Unknown"

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Scout | CyberX")
        self.root.geometry("1320x790")
        self.root.minsize(1050, 650)
        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.results = []
        self.worker = None
        self.started = 0
        self.done = 0
        self.total = 0
        self.oui = local_oui_db()
        self.build_style()
        self.build_ui()
        self.root.after(100, self.poll)

    def build_style(self):
        s = ttk.Style()
        try: s.theme_use("clam")
        except tk.TclError: pass
        s.configure("TFrame", background="#f4f7fb")
        s.configure("TLabel", background="#f4f7fb", foreground="#263449",
                    font=("Segoe UI", 10))
        s.configure("Title.TLabel", font=("Segoe UI Semibold", 22), foreground="#14213d")
        s.configure("Sub.TLabel", font=("Segoe UI", 10), foreground="#64748b")
        s.configure("TButton", font=("Segoe UI Semibold", 10), padding=(12, 8))
        s.configure("Accent.TButton", foreground="white", background="#2563eb")
        s.map("Accent.TButton", background=[("active", "#1d4ed8")])
        s.configure("Treeview", rowheight=29, font=("Segoe UI", 9))
        s.configure("Treeview.Heading", font=("Segoe UI Semibold", 9))
        s.configure("TEntry", padding=7)

    def build_ui(self):
        outer = ttk.Frame(self.root, padding=22)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text="IoT Scout", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            outer,
            text="IoT Discovery and Service Enumeration Tool | CyberX",
            style="Sub.TLabel"
        ).pack(anchor="w", pady=(2, 15))

        card = ttk.Frame(outer, padding=14)
        card.pack(fill="x", pady=(0, 12))

        ttk.Label(card, text="Target").grid(row=0, column=0, sticky="w")
        self.target = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(card, textvariable=self.target, width=25).grid(
            row=1, column=0, padx=(0, 10), pady=(4, 0), sticky="ew")

        ttk.Label(card, text="TCP ports").grid(row=0, column=1, sticky="w")
        self.ports = tk.StringVar(value=DEFAULT_PORTS)
        ttk.Entry(card, textvariable=self.ports, width=40).grid(
            row=1, column=1, padx=(0, 10), pady=(4, 0), sticky="ew")

        ttk.Label(card, text="Threads").grid(row=0, column=2, sticky="w")
        self.threads = tk.IntVar(value=64)
        ttk.Spinbox(card, from_=1, to=256, textvariable=self.threads, width=7).grid(
            row=1, column=2, padx=(0, 10), pady=(4, 0))

        ttk.Label(card, text="Timeout").grid(row=0, column=3, sticky="w")
        self.timeout = tk.DoubleVar(value=0.8)
        ttk.Spinbox(card, from_=0.1, to=10, increment=0.1,
                    textvariable=self.timeout, width=7).grid(
            row=1, column=3, padx=(0, 10), pady=(4, 0))

        self.arp_var = tk.BooleanVar(value=True)
        self.ssdp_var = tk.BooleanVar(value=True)
        self.mdns_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(card, text="ARP/MAC", variable=self.arp_var).grid(row=1, column=4, padx=5)
        ttk.Checkbutton(card, text="SSDP/UPnP", variable=self.ssdp_var).grid(row=1, column=5, padx=5)
        ttk.Checkbutton(card, text="mDNS", variable=self.mdns_var).grid(row=1, column=6, padx=5)

        self.start_btn = ttk.Button(card, text="▶  Start", style="Accent.TButton",
                                    command=self.start)
        self.start_btn.grid(row=1, column=7, padx=(12, 4))
        self.stop_btn = ttk.Button(card, text="■  Stop", command=self.stop,
                                   state="disabled")
        self.stop_btn.grid(row=1, column=8, padx=4)
        self.export_btn = ttk.Button(card, text="⇩  CSV", command=self.export,
                                     state="disabled")
        self.export_btn.grid(row=1, column=9, padx=4)

        card.columnconfigure(0, weight=1)
        card.columnconfigure(1, weight=2)

        stats = ttk.Frame(outer)
        stats.pack(fill="x", pady=(0, 10))
        self.stats = {}
        for i, (key, name) in enumerate([
            ("status", "STATUS"), ("devices", "DEVICES"),
            ("services", "SERVICES"), ("macs", "MACS"),
            ("elapsed", "ELAPSED")
        ]):
            b = ttk.Frame(stats, padding=10)
            b.grid(row=0, column=i, padx=(0, 7), sticky="ew")
            ttk.Label(b, text=name, style="Sub.TLabel").pack(anchor="w")
            v = ttk.Label(b, text="—", font=("Segoe UI Semibold", 14),
                          foreground="#14213d")
            v.pack(anchor="w")
            self.stats[key] = v
            stats.columnconfigure(i, weight=1)

        self.progress = ttk.Progressbar(outer, mode="determinate")
        self.progress.pack(fill="x", pady=(0, 10))

        frame = ttk.Frame(outer)
        frame.pack(fill="both", expand=True)

        cols = ("ip", "mac", "vendor", "hostname", "device", "port", "service", "title", "server")
        heads = {
            "ip":"IP ADDRESS", "mac":"MAC", "vendor":"VENDOR", "hostname":"HOSTNAME",
            "device":"DEVICE TYPE", "port":"PORT", "service":"SERVICE",
            "title":"TITLE / PTR", "server":"SERVER"
        }
        widths = {"ip":125, "mac":145, "vendor":155, "hostname":180, "device":150,
                  "port":60, "service":105, "title":260, "server":190}
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=heads[c])
            self.tree.column(c, width=widths[c], anchor="w")
        ys = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        xs = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self.log = tk.Text(outer, height=5, relief="flat", bg="#111827",
                           fg="#dbeafe", font=("Consolas", 9),
                           padx=10, pady=7)
        self.log.pack(fill="x", pady=(10, 0))
        self.logmsg("Ready. Scan only networks you own or are authorized to assess.")

    def logmsg(self, msg):
        self.log.insert("end", f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self.log.see("end")

    def targets(self, text):
        text = text.strip()
        if "-" in text and "/" not in text:
            a, b = map(lambda x: ipaddress.ip_address(x.strip()), text.split("-", 1))
            if a.version != 4 or b.version != 4 or int(b) < int(a):
                raise ValueError("Invalid IPv4 range")
            if int(b) - int(a) + 1 > 65536:
                raise ValueError("Maximum target size is 65,536 addresses")
            return [str(ipaddress.ip_address(i)) for i in range(int(a), int(b)+1)]
        net = ipaddress.ip_network(text, strict=False)
        if net.version != 4:
            raise ValueError("Only IPv4 targets are supported")
        if net.num_addresses > 65536:
            raise ValueError("Maximum target size is 65,536 addresses")
        return [str(x) for x in net.hosts()]

    def start(self):
        if self.worker and self.worker.is_alive():
            return
        try:
            ips = self.targets(self.target.get())
            ports = sorted(set(int(x.strip()) for x in self.ports.get().split(",") if x.strip()))
            if not ports or any(p < 1 or p > 65535 for p in ports):
                raise ValueError("Invalid TCP port list")
            threads = max(1, min(256, int(self.threads.get())))
            timeout = max(0.1, min(10, float(self.timeout.get())))
        except Exception as e:
            messagebox.showerror("Invalid input", str(e))
            return

        self.results = []
        for x in self.tree.get_children(): self.tree.delete(x)
        self.done = 0
        self.started = time.time()
        self.stop_event.clear()
        self.total = len(ips) * len(ports)
        self.progress["maximum"] = max(1, self.total)
        self.progress["value"] = 0
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.export_btn.configure(state="disabled")
        self.stats["status"].configure(text="SCANNING")
        self.logmsg(f"TCP scan: {len(ips)} hosts × {len(ports)} ports")

        self.worker = threading.Thread(
            target=self.run_scan,
            args=(ips, ports, threads, timeout),
            daemon=True
        )
        self.worker.start()

    def stop(self):
        self.stop_event.set()
        self.stop_btn.configure(state="disabled")
        self.logmsg("Stop requested...")

    def tcp_probe(self, ip, port, timeout):
        start = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) != 0:
                return None
        except OSError:
            return None
        finally:
            try: s.close()
            except OSError: pass

        latency = (time.perf_counter() - start) * 1000
        service = SERVICE_MAP.get(port, "TCP")
        title, server = "", ""
        if port in (80, 443, 8000, 8080, 8443):
            scheme = "https" if port in (443, 8443) else "http"
            try:
                ctx = ssl._create_unverified_context()
                req = Request(f"{scheme}://{ip}:{port}/",
                              headers={"User-Agent": "IoT-Scout/1.0"})
                with urlopen(req, timeout=timeout, context=ctx) as r:
                    body = r.read(65536).decode("utf-8", "ignore")
                    server = r.headers.get("Server", "")
                    m = re.search(r"<title[^>]*>(.*?)</title>", body,
                                  re.I | re.S)
                    if m:
                        title = re.sub(r"\s+", " ", m.group(1)).strip()
            except Exception:
                pass

        return {"ip": ip, "port": port, "service": service,
                "title": title, "server": server,
                "latency": latency}

    def run_scan(self, ips, ports, workers, timeout):
        # ARP/MAC inventory from the local OS cache.
        macs = arp_table() if self.arp_var.get() else {}
        if macs:
            self.q.put(("log", f"ARP cache: {len(macs)} MAC addresses found"))
        elif self.arp_var.get():
            self.q.put(("log", "ARP cache returned no entries; MAC visibility depends on local LAN/OS."))

        # Multicast discovery runs independently of TCP scan.
        if self.ssdp_var.get():
            for r in ssdp_discover():
                r["mac"] = macs.get(r["ip"], "")
                r["vendor"] = oui_vendor(r["mac"], self.oui)
                r["hostname"] = hostname_for(r["ip"])
                r["device"] = classify_device([r], r["vendor"], r["hostname"])
                self.q.put(("result", r))

        if self.mdns_var.get():
            for r in mdns_query():
                r["mac"] = macs.get(r["ip"], "")
                r["vendor"] = oui_vendor(r["mac"], self.oui)
                r["hostname"] = hostname_for(r["ip"])
                r["device"] = classify_device([r], r["vendor"], r["hostname"])
                self.q.put(("result", r))

        jobs = queue.Queue()
        for ip in ips:
            for port in ports:
                jobs.put((ip, port))

        def worker():
            while not self.stop_event.is_set():
                try: ip, port = jobs.get_nowait()
                except queue.Empty: return
                try:
                    r = self.tcp_probe(ip, port, timeout)
                    if r:
                        r["mac"] = macs.get(ip, "")
                        r["vendor"] = oui_vendor(r["mac"], self.oui)
                        r["hostname"] = hostname_for(ip)
                        r["device"] = classify_device([r], r["vendor"], r["hostname"])
                        self.q.put(("result", r))
                finally:
                    self.q.put(("progress", 1))
                    jobs.task_done()

        ts = [threading.Thread(target=worker, daemon=True)
              for _ in range(min(workers, max(1, self.total)))]
        for t in ts: t.start()
        for t in ts: t.join()

        self.q.put(("finished", self.stop_event.is_set()))

    def merge_display(self, r):
        self.results.append(r)
        self.tree.insert("", "end", values=(
            r.get("ip",""), r.get("mac",""), r.get("vendor",""),
            r.get("hostname",""), r.get("device",""), r.get("port",""),
            r.get("service",""), r.get("title","") or r.get("detail",""),
            r.get("server","")
        ))

    def poll(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                if kind == "result":
                    self.merge_display(data)
                elif kind == "progress":
                    self.done += 1
                    self.progress["value"] = self.done
                elif kind == "log":
                    self.logmsg(data)
                elif kind == "finished":
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self.export_btn.configure(
                        state="normal" if self.results else "disabled")
                    self.stats["status"].configure(text="STOPPED" if data else "COMPLETE")
                    self.logmsg(
                        f"Finished: {len(self.results)} observations across "
                        f"{len(set(r.get('ip') for r in self.results))} hosts."
                    )
        except queue.Empty:
            pass

        ips = set(r.get("ip") for r in self.results)
        macs = set(r.get("mac") for r in self.results if r.get("mac"))
        self.stats["devices"].configure(text=str(len(ips)))
        self.stats["services"].configure(text=str(len(self.results)))
        self.stats["macs"].configure(text=str(len(macs)))
        if self.started:
            self.stats["elapsed"].configure(text=f"{time.time()-self.started:.1f}s")
        self.root.after(100, self.poll)

    def export(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            title="Export IoT inventory", defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")])
        if not path: return

        fields = ["ip", "mac", "vendor", "hostname", "device",
                  "port", "service", "title", "server", "detail", "latency"]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in self.results:
                w.writerow({k: r.get(k, "") for k in fields})
        self.logmsg(f"Exported {len(self.results)} observations → {path}")
        messagebox.showinfo("Export complete", f"Saved {len(self.results)} observations.")

if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
