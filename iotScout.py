#!/usr/bin/env python3

import csv
import ipaddress
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl

DEFAULT_PORTS = "80,443,554,8000,8080,8443,1883,8883"
SERVICE_MAP = {
    80: "HTTP", 443: "HTTPS", 554: "RTSP",
    8000: "HTTP/IoT", 8080: "HTTP", 8443: "HTTPS",
    1883: "MQTT", 8883: "MQTT-TLS"
}

class IoTScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ioT Scout | CyberX")
        self.root.geometry("1180x720")
        self.root.minsize(980, 620)

        self.q = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.results = []
        self.total = 0
        self.done = 0
        self.started = 0

        self._style()
        self._build()
        self.root.after(100, self._poll)

    def _style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TFrame", background="#f4f7fb")
        s.configure("TLabel", background="#f4f7fb", foreground="#263449",
                    font=("Segoe UI", 10))
        s.configure("Title.TLabel", font=("Segoe UI Semibold", 22),
                    foreground="#14213d")
        s.configure("Sub.TLabel", font=("Segoe UI", 10),
                    foreground="#65748b")
        s.configure("TButton", font=("Segoe UI Semibold", 10), padding=(14, 8))
        s.configure("Accent.TButton", foreground="white", background="#2563eb")
        s.map("Accent.TButton", background=[("active", "#1d4ed8")])
        s.configure("Treeview", rowheight=30, font=("Segoe UI", 9))
        s.configure("Treeview.Heading", font=("Segoe UI Semibold", 9))
        s.configure("TEntry", padding=7)
        s.configure("TCombobox", padding=6)

    def _build(self):
        outer = ttk.Frame(self.root, padding=22)
        outer.pack(fill="both", expand=True)

        head = ttk.Frame(outer)
        head.pack(fill="x")
        ttk.Label(head, text="ioT Scout", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            head,
            text="IoT Discovery and Service Enumeration Tool | CyberX",
            style="Sub.TLabel"
        ).pack(anchor="w", pady=(2, 16))

        controls = ttk.Frame(outer)
        controls.pack(fill="x", pady=(0, 12))

        card = ttk.Frame(controls, padding=14)
        card.pack(fill="x")

        ttk.Label(card, text="Target").grid(row=0, column=0, sticky="w")
        self.target = tk.StringVar(value="192.168.1.0/24")
        ttk.Entry(card, textvariable=self.target, width=28).grid(
            row=1, column=0, padx=(0, 12), pady=(5, 0), sticky="ew")

        ttk.Label(card, text="Ports").grid(row=0, column=1, sticky="w")
        self.ports = tk.StringVar(value=DEFAULT_PORTS)
        ttk.Entry(card, textvariable=self.ports, width=38).grid(
            row=1, column=1, padx=(0, 12), pady=(5, 0), sticky="ew")

        ttk.Label(card, text="Threads").grid(row=0, column=2, sticky="w")
        self.threads = tk.IntVar(value=64)
        ttk.Spinbox(card, from_=1, to=256, textvariable=self.threads, width=8).grid(
            row=1, column=2, padx=(0, 12), pady=(5, 0))

        ttk.Label(card, text="Timeout (sec)").grid(row=0, column=3, sticky="w")
        self.timeout = tk.DoubleVar(value=0.8)
        ttk.Spinbox(card, from_=0.1, to=10.0, increment=0.1,
                    textvariable=self.timeout, width=8).grid(
            row=1, column=3, padx=(0, 12), pady=(5, 0))

        self.start_btn = ttk.Button(card, text="▶  Start Scan",
                                    style="Accent.TButton", command=self.start_scan)
        self.start_btn.grid(row=1, column=4, padx=(8, 4))

        self.stop_btn = ttk.Button(card, text="■  Stop", command=self.stop_scan,
                                   state="disabled")
        self.stop_btn.grid(row=1, column=5, padx=4)

        self.export_btn = ttk.Button(card, text="⇩  Export CSV",
                                     command=self.export_csv, state="disabled")
        self.export_btn.grid(row=1, column=6, padx=(4, 0))

        card.columnconfigure(0, weight=1)
        card.columnconfigure(1, weight=2)

        stats = ttk.Frame(outer)
        stats.pack(fill="x", pady=(0, 12))
        self.stat_labels = {}
        for i, (key, label) in enumerate([
            ("status", "STATUS"), ("hosts", "HOSTS"), ("services", "SERVICES"),
            ("http", "WEB"), ("elapsed", "ELAPSED")
        ]):
            box = ttk.Frame(stats, padding=12)
            box.grid(row=0, column=i, padx=(0, 8), sticky="ew")
            ttk.Label(box, text=label, style="Sub.TLabel").pack(anchor="w")
            v = ttk.Label(box, text="—", font=("Segoe UI Semibold", 14),
                          foreground="#14213d")
            v.pack(anchor="w", pady=(2, 0))
            self.stat_labels[key] = v
            stats.columnconfigure(i, weight=1)

        self.progress = ttk.Progressbar(outer, mode="determinate")
        self.progress.pack(fill="x", pady=(0, 12))

        table_frame = ttk.Frame(outer)
        table_frame.pack(fill="both", expand=True)

        columns = ("ip", "port", "service", "title", "server", "latency")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        widths = {"ip": 145, "port": 70, "service": 105,
                  "title": 300, "server": 210, "latency": 90}
        headings = {"ip": "IP ADDRESS", "port": "PORT", "service": "SERVICE",
                    "title": "HTTP TITLE", "server": "SERVER", "latency": "LATENCY"}
        for c in columns:
            self.tree.heading(c, text=headings[c])
            self.tree.column(c, width=widths[c], anchor="w")

        yscroll = ttk.Scrollbar(table_frame, orient="vertical",
                                command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient="horizontal",
                                command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.log = tk.Text(outer, height=5, relief="flat", bg="#111827",
                           fg="#dbeafe", insertbackground="white",
                           font=("Consolas", 9), padx=10, pady=8)
        self.log.pack(fill="x", pady=(12, 0))
        self._log("Ready. Enter an authorized LAN target and start a scan.")

    def _log(self, text):
        self.log.insert("end", f"[{time.strftime('%H:%M:%S')}] {text}\n")
        self.log.see("end")

    def parse_targets(self, text):
        text = text.strip()
        if "-" in text and "/" not in text:
            a, b = [x.strip() for x in text.split("-", 1)]
            ia, ib = ipaddress.ip_address(a), ipaddress.ip_address(b)
            if ia.version != 4 or ib.version != 4 or int(ib) < int(ia):
                raise ValueError("Invalid IPv4 range.")
            count = int(ib) - int(ia) + 1
            if count > 65536:
                raise ValueError("Range is too large (maximum 65,536 addresses).")
            return [str(ipaddress.ip_address(i)) for i in range(int(ia), int(ib)+1)]

        net = ipaddress.ip_network(text, strict=False)
        if net.version != 4:
            raise ValueError("Only IPv4 targets are supported.")
        if net.num_addresses > 65536:
            raise ValueError("Target is too large (maximum 65,536 addresses).")
        return [str(x) for x in net.hosts()]

    def start_scan(self):
        if self.worker and self.worker.is_alive():
            return
        try:
            targets = self.parse_targets(self.target.get())
            ports = sorted(set(int(x.strip()) for x in self.ports.get().split(",")
                               if x.strip()))
            if not ports or any(p < 1 or p > 65535 for p in ports):
                raise ValueError("Ports must be between 1 and 65535.")
            threads = max(1, min(256, int(self.threads.get())))
            timeout = max(0.1, min(10.0, float(self.timeout.get())))
        except Exception as e:
            messagebox.showerror("Invalid input", str(e))
            return

        self.results.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.stop_event.clear()
        self.total = len(targets) * len(ports)
        self.done = 0
        self.started = time.time()
        self.progress["maximum"] = self.total
        self.progress["value"] = 0
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.export_btn.configure(state="disabled")
        self.stat_labels["status"].configure(text="SCANNING")
        self._log(f"Scanning {len(targets)} hosts × {len(ports)} ports...")
        self.worker = threading.Thread(
            target=self._scan, args=(targets, ports, threads, timeout), daemon=True)
        self.worker.start()

    def stop_scan(self):
        self.stop_event.set()
        self._log("Stopping scan...")
        self.stop_btn.configure(state="disabled")

    def _scan(self, targets, ports, workers, timeout):
        jobs = queue.Queue()
        for ip in targets:
            for port in ports:
                jobs.put((ip, port))

        def worker():
            while not self.stop_event.is_set():
                try:
                    ip, port = jobs.get_nowait()
                except queue.Empty:
                    return
                try:
                    result = self.probe(ip, port, timeout)
                    if result:
                        self.q.put(("result", result))
                finally:
                    self.q.put(("progress", 1))
                    jobs.task_done()

        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(min(workers, max(1, self.total)))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.q.put(("finished", self.stop_event.is_set()))

    def probe(self, ip, port, timeout):
        start = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip, port)) != 0:
                return None
        except OSError:
            return None
        finally:
            try:
                sock.close()
            except OSError:
                pass

        latency = (time.perf_counter() - start) * 1000
        service = SERVICE_MAP.get(port, "TCP")
        title, server = "", ""

        if port in (80, 443, 8000, 8080, 8443):
            scheme = "https" if port in (443, 8443) else "http"
            try:
                ctx = ssl._create_unverified_context()
                req = Request(f"{scheme}://{ip}:{port}/",
                              headers={"User-Agent": "IoT-LAN-Inventory/1.0"})
                with urlopen(req, timeout=timeout, context=ctx) as r:
                    data = r.read(65536).decode("utf-8", "ignore")
                    server = r.headers.get("Server", "")
                    import re
                    m = re.search(r"<title[^>]*>(.*?)</title>", data,
                                  re.I | re.S)
                    if m:
                        title = re.sub(r"\s+", " ", m.group(1)).strip()
                    if not title:
                        title = "[blank]"
            except Exception:
                pass

        return {
            "ip": ip, "port": port, "service": service,
            "title": title, "server": server,
            "latency": f"{latency:.0f} ms"
        }

    def _poll(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "result":
                    self.results.append(payload)
                    self.tree.insert("", "end", values=(
                        payload["ip"], payload["port"], payload["service"],
                        payload["title"], payload["server"], payload["latency"]))
                elif kind == "progress":
                    self.done += payload
                    self.progress["value"] = self.done
                    self.stat_labels["hosts"].configure(
                        text=str(len(set(r["ip"] for r in self.results))))
                    self.stat_labels["services"].configure(text=str(len(self.results)))
                    self.stat_labels["http"].configure(
                        text=str(sum(1 for r in self.results
                                     if r["port"] in (80, 443, 8000, 8080, 8443))))
                    if self.started:
                        self.stat_labels["elapsed"].configure(
                            text=f"{time.time()-self.started:.1f}s")
                elif kind == "finished":
                    self.start_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    self.export_btn.configure(
                        state="normal" if self.results else "disabled")
                    self.stat_labels["status"].configure(
                        text="STOPPED" if payload else "COMPLETE")
                    self._log(
                        f"Finished: {len(self.results)} open services on "
                        f"{len(set(r['ip'] for r in self.results))} hosts."
                    )
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def export_csv(self):
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            title="Export IoT inventory",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "ip", "port", "service", "title", "server", "latency"])
            writer.writeheader()
            writer.writerows(self.results)
        self._log(f"Exported {len(self.results)} records → {path}")
        messagebox.showinfo("Export complete", f"Saved {len(self.results)} records.")

if __name__ == "__main__":
    root = tk.Tk()
    app = IoTScannerGUI(root)
    root.mainloop()
