import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import queue
import socket
import ipaddress
import subprocess
import re
import csv
import time
import os
import ssl
import struct
from urllib.request import Request, urlopen


# ============================================================
# CONFIG
# ============================================================

APP_NAME = "IoT Scout"
VERSION = "2.0"

DEFAULT_PORTS = (
    "21,22,23,53,80,443,554,"
    "1883,5353,8000,8080,8443"
)

SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    1883: "MQTT",
    5353: "mDNS",
    8000: "HTTP / IoT",
    8080: "HTTP",
    8443: "HTTPS",
}


DEVICE_RULES = [
    (
        "Camera",
        [
            "rtsp",
            "onvif",
            "hikvision",
            "dahua",
            "axis",
            "ipcam",
            "camera",
        ],
    ),
    (
        "Router / AP",
        [
            "router",
            "gateway",
            "access point",
            "mikrotik",
            "openwrt",
            "dd-wrt",
            "tp-link",
        ],
    ),
    (
        "Smart TV",
        [
            "googlecast",
            "chromecast",
            "airplay",
            "roku",
            "smart-tv",
            "samsung tv",
            "lg tv",
        ],
    ),
    (
        "Printer",
        [
            "ipp",
            "printer",
            "jetdirect",
            "epson",
            "brother",
            "canon",
            "hp printer",
        ],
    ),
    (
        "NAS",
        [
            "nas",
            "synology",
            "qnap",
            "storage",
        ],
    ),
    (
        "IoT / Smart Home",
        [
            "mqtt",
            "homeassistant",
            "home-assistant",
            "tuya",
            "espressif",
            "shelly",
            "tasmota",
        ],
    ),
    (
        "Media Device",
        [
            "dlna",
            "upnp",
            "mediaserver",
            "media server",
        ],
    ),
]


# ============================================================
# HELPERS
# ============================================================

def normalize_mac(mac):
    if not mac:
        return ""

    h = re.sub(r"[^0-9A-Fa-f]", "", mac)

    if len(h) != 12:
        return mac.upper()

    return ":".join(
        h[i:i + 2]
        for i in range(0, 12, 2)
    ).upper()


def load_oui_database():
    """
    Optional local OUI database.

    Place oui.txt beside this script.

    Examples:

    AA-BB-CC,Example Vendor
    AABBCC Example Vendor
    """

    database = {}

    possible_files = [
        os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "oui.txt",
        ),
        os.path.join(
            os.getcwd(),
            "oui.txt",
        ),
    ]

    for filename in possible_files:

        if not os.path.isfile(filename):
            continue

        try:

            with open(
                filename,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as f:

                for line in f:

                    line = line.strip()

                    if not line:
                        continue

                    if line.startswith("#"):
                        continue

                    match = re.match(
                        r"^\s*"
                        r"([0-9A-Fa-f]{2}"
                        r"[-: ]?"
                        r"[0-9A-Fa-f]{2}"
                        r"[-: ]?"
                        r"[0-9A-Fa-f]{2})"
                        r"\s*[,;\t ]+\s*"
                        r"(.+?)"
                        r"\s*$",
                        line,
                    )

                    if match:

                        oui = re.sub(
                            r"[^0-9A-Fa-f]",
                            "",
                            match.group(1),
                        ).upper()

                        vendor = match.group(2).strip()

                        database[oui] = vendor

            break

        except OSError:
            pass

    return database


def get_vendor(mac, database):

    cleaned = re.sub(
        r"[^0-9A-Fa-f]",
        "",
        mac or "",
    ).upper()

    return database.get(
        cleaned[:6],
        "Unknown",
    )


def get_arp_cache():

    devices = {}

    try:

        if os.name == "nt":

            output = subprocess.check_output(
                ["arp", "-a"],
                text=True,
                errors="ignore",
                timeout=5,
            )

            for line in output.splitlines():

                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)"
                    r"\s+"
                    r"([0-9a-fA-F]{2}"
                    r"(?:-[0-9a-fA-F]{2}){5})"
                    r"\s+\w+",
                    line,
                )

                if match:

                    ip = match.group(1)
                    mac = normalize_mac(
                        match.group(2)
                    )

                    devices[ip] = mac

        else:

            output = subprocess.check_output(
                ["ip", "neigh"],
                text=True,
                errors="ignore",
                timeout=5,
            )

            for line in output.splitlines():

                match = re.search(
                    r"(\d+\.\d+\.\d+\.\d+)"
                    r".*lladdr\s+"
                    r"([0-9a-fA-F:]{17})",
                    line,
                )

                if match:

                    devices[
                        match.group(1)
                    ] = normalize_mac(
                        match.group(2)
                    )

    except Exception:
        pass

    return devices


def reverse_dns(ip):

    try:
        return socket.gethostbyaddr(ip)[0]

    except Exception:
        return ""


def parse_targets(value):

    value = value.strip()

    # Range:
    # 192.168.1.1-192.168.1.100

    if "-" in value and "/" not in value:

        start, end = [
            x.strip()
            for x in value.split("-", 1)
        ]

        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)

        if start_ip.version != 4:
            raise ValueError(
                "Only IPv4 targets are supported."
            )

        if int(end_ip) < int(start_ip):
            raise ValueError(
                "Invalid IP range."
            )

        count = (
            int(end_ip)
            - int(start_ip)
            + 1
        )

        if count > 65536:
            raise ValueError(
                "Maximum 65,536 addresses."
            )

        return [
            str(ipaddress.ip_address(i))
            for i in range(
                int(start_ip),
                int(end_ip) + 1,
            )
        ]

    # CIDR

    network = ipaddress.ip_network(
        value,
        strict=False,
    )

    if network.version != 4:
        raise ValueError(
            "Only IPv4 is supported."
        )

    if network.num_addresses > 65536:
        raise ValueError(
            "Maximum 65,536 addresses."
        )

    return [
        str(ip)
        for ip in network.hosts()
    ]


# ============================================================
# SSDP
# ============================================================

def ssdp_discover(timeout=3):

    packet = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    results = []

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        socket.IPPROTO_UDP,
    )

    sock.settimeout(0.4)

    try:

        for _ in range(2):

            sock.sendto(
                packet,
                (
                    "239.255.255.250",
                    1900,
                ),
            )

        deadline = time.time() + timeout

        while time.time() < deadline:

            try:

                data, address = sock.recvfrom(
                    8192
                )

            except socket.timeout:
                continue

            text = data.decode(
                "utf-8",
                errors="ignore",
            )

            headers = {}

            for line in text.split("\r\n")[1:]:

                if ":" in line:

                    key, value = line.split(
                        ":",
                        1,
                    )

                    headers[
                        key.strip().upper()
                    ] = value.strip()

            results.append(
                {
                    "ip": address[0],
                    "port": 1900,
                    "service": "SSDP / UPnP",
                    "title": headers.get(
                        "SERVER",
                        "",
                    ),
                    "server": headers.get(
                        "SERVER",
                        "",
                    ),
                    "detail": headers.get(
                        "ST",
                        "",
                    ),
                }
            )

    except OSError:
        pass

    finally:
        sock.close()

    unique = {}

    for result in results:

        key = (
            result["ip"],
            result["detail"],
            result["server"],
        )

        unique[key] = result

    return list(unique.values())


# ============================================================
# mDNS
# ============================================================

def encode_dns_name(name):

    result = b""

    for part in name.split("."):

        result += bytes(
            [len(part)]
        )

        result += part.encode()

    return result + b"\x00"


def decode_dns_name(packet, offset):

    labels = []

    original = offset
    jumped = False
    visited = set()

    while offset < len(packet):

        if offset in visited:
            break

        visited.add(offset)

        length = packet[offset]

        if length == 0:

            offset += 1
            break

        if length & 0xC0 == 0xC0:

            if offset + 1 >= len(packet):
                break

            pointer = (
                ((length & 0x3F) << 8)
                | packet[offset + 1]
            )

            part, _ = decode_dns_name(
                packet,
                pointer,
            )

            if part:
                labels.append(part)

            offset += 2
            jumped = True
            break

        offset += 1

        if offset + length > len(packet):
            break

        labels.append(
            packet[
                offset:
                offset + length
            ].decode(
                "utf-8",
                errors="ignore",
            )
        )

        offset += length

    name = ".".join(
        x for x in labels if x
    )

    if jumped:
        return name, original + 2

    return name, offset


def mdns_discover(timeout=2):

    services = [
        "_services._dns-sd._udp.local",
        "_http._tcp.local",
        "_ipp._tcp.local",
        "_printer._tcp.local",
        "_googlecast._tcp.local",
        "_airplay._tcp.local",
        "_rtsp._tcp.local",
    ]

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        socket.IPPROTO_UDP,
    )

    sock.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1,
    )

    sock.settimeout(0.3)

    results = []

    try:

        for service in services:

            header = struct.pack(
                "!HHHHHH",
                0,
                0,
                1,
                0,
                0,
                0,
            )

            question = (
                encode_dns_name(service)
                + struct.pack(
                    "!HH",
                    12,
                    1,
                )
            )

            sock.sendto(
                header + question,
                (
                    "224.0.0.251",
                    5353,
                ),
            )

        deadline = time.time() + timeout

        while time.time() < deadline:

            try:

                packet, address = sock.recvfrom(
                    9000
                )

            except socket.timeout:
                continue

            if len(packet) < 12:
                continue

            qd, an, ns, ar = struct.unpack(
                "!HHHH",
                packet[4:12],
            )

            offset = 12

            try:

                for _ in range(qd):

                    _, offset = decode_dns_name(
                        packet,
                        offset,
                    )

                    offset += 4

                for _ in range(
                    an + ns + ar
                ):

                    name, offset = decode_dns_name(
                        packet,
                        offset,
                    )

                    if offset + 10 > len(packet):
                        break

                    rtype, _, _, rdlength = struct.unpack(
                        "!HHIH",
                        packet[offset:offset + 10],
                    )

                    offset += 10

                    if offset + rdlength > len(packet):
                        break

                    target = ""

                    if rtype == 12:

                        target, _ = decode_dns_name(
                            packet,
                            offset,
                        )

                    if name or target:

                        results.append(
                            {
                                "ip": address[0],
                                "port": 5353,
                                "service": "mDNS",
                                "title": target or name,
                                "server": "",
                                "detail": name,
                            }
                        )

                    offset += rdlength

            except Exception:
                continue

    except OSError:
        pass

    finally:
        sock.close()

    unique = {}

    for result in results:

        key = (
            result["ip"],
            result["title"],
            result["detail"],
        )

        unique[key] = result

    return list(unique.values())


# ============================================================
# DEVICE FINGERPRINT
# ============================================================

def classify_device(
    results,
    vendor="",
    hostname="",
):

    text = ""

    for result in results:

        text += " ".join(
            [
                str(result.get("title", "")),
                str(result.get("server", "")),
                str(result.get("service", "")),
                str(result.get("detail", "")),
            ]
        ).lower()

    text += " "
    text += vendor.lower()
    text += " "
    text += hostname.lower()

    for device, keywords in DEVICE_RULES:

        for keyword in keywords:

            if keyword in text:
                return device

    if any(
        result.get("service")
        in ("SSDP / UPnP", "mDNS")
        for result in results
    ):
        return "Smart / Network Device"

    return "Unknown"


# ============================================================
# MAIN GUI
# ============================================================

class IotScout:

    def __init__(self, root):

        self.root = root

        self.root.title(
            f"{APP_NAME} {VERSION} | CyberX"
        )

        self.root.geometry(
            "1450x860"
        )

        self.root.minsize(
            1150,
            700,
        )

        self.root.configure(
            bg="#edf2f7"
        )

        self.queue = queue.Queue()

        self.stop_event = threading.Event()

        self.worker = None

        self.results = []

        self.host_items = {}

        self.started = 0

        self.total = 0

        self.completed = 0

        self.oui = load_oui_database()

        self.build_styles()

        self.build_interface()

        self.root.after(
            100,
            self.process_queue,
        )

    # ========================================================
    # STYLES
    # ========================================================

    def build_styles(self):

        style = ttk.Style()

        style.theme_use(
            "clam"
        )

        style.configure(
            "TFrame",
            background="#edf2f7",
        )

        style.configure(
            "Card.TFrame",
            background="#ffffff",
        )

        style.configure(
            "TLabel",
            background="#edf2f7",
            foreground="#26364a",
            font=(
                "Segoe UI",
                10,
            ),
        )

        style.configure(
            "Card.TLabel",
            background="#ffffff",
            foreground="#26364a",
            font=(
                "Segoe UI",
                10,
            ),
        )

        style.configure(
            "Title.TLabel",
            background="#edf2f7",
            foreground="#14213d",
            font=(
                "Segoe UI Semibold",
                23,
            ),
        )

        style.configure(
            "Subtitle.TLabel",
            background="#edf2f7",
            foreground="#64748b",
            font=(
                "Segoe UI",
                9,
            ),
        )

        style.configure(
            "Section.TLabel",
            background="#ffffff",
            foreground="#14213d",
            font=(
                "Segoe UI Semibold",
                9,
            ),
        )

        style.configure(
            "TButton",
            font=(
                "Segoe UI Semibold",
                9,
            ),
            padding=(
                13,
                8,
            ),
        )

        style.configure(
            "Accent.TButton",
            background="#2563eb",
            foreground="white",
            padding=(
                16,
                9,
            ),
        )

        style.map(
            "Accent.TButton",
            background=[
                (
                    "active",
                    "#1d4ed8",
                )
            ],
        )

        style.configure(
            "Danger.TButton",
            foreground="#b42318",
            padding=(
                13,
                8,
            ),
        )

        style.configure(
            "Treeview",
            background="#ffffff",
            fieldbackground="#ffffff",
            foreground="#26364a",
            rowheight=31,
            font=(
                "Segoe UI",
                9,
            ),
        )

        style.configure(
            "Treeview.Heading",
            background="#e8eef5",
            foreground="#344054",
            font=(
                "Segoe UI Semibold",
                9,
            ),
        )

        style.map(
            "Treeview",
            background=[
                (
                    "selected",
                    "#dbeafe",
                )
            ],
            foreground=[
                (
                    "selected",
                    "#0f2747",
                )
            ],
        )

        style.configure(
            "TNotebook",
            background="#edf2f7",
            borderwidth=0,
        )

        style.configure(
            "TNotebook.Tab",
            padding=(
                19,
                10,
            ),
            font=(
                "Segoe UI Semibold",
                9,
            ),
        )

        style.map(
            "TNotebook.Tab",
            foreground=[
                (
                    "selected",
                    "#2563eb",
                )
            ],
            background=[
                (
                    "selected",
                    "#ffffff",
                )
            ],
        )

        style.configure(
            "Horizontal.TProgressbar",
            troughcolor="#dce5ef",
            background="#2563eb",
            thickness=7,
        )

    # ========================================================
    # HEADER
    # ========================================================

    def build_interface(self):

        header = ttk.Frame(
            self.root,
            padding=(
                25,
                19,
                25,
                8,
            ),
        )

        header.pack(
            fill="x"
        )

        ttk.Label(
            header,
            text="IoT Scout",
            style="Title.TLabel",
        ).pack(
            side="left"
        )

        ttk.Label(
            header,
            text="   IoT Devices Discovery & Service Enumeration Tool | CyberX",
            style="Subtitle.TLabel",
        ).pack(
            side="left",
            pady=(7, 0),
        )

        ttk.Label(
            header,
            text=f"v{VERSION}",
            style="Subtitle.TLabel",
        ).pack(
            side="right",
            pady=(7, 0),
        )

        self.notebook = ttk.Notebook(
            self.root
        )

        self.notebook.pack(
            fill="both",
            expand=True,
            padx=18,
            pady=(0, 18),
        )

        self.discovery_tab = ttk.Frame(
            self.notebook
        )

        self.hosts_tab = ttk.Frame(
            self.notebook
        )

        self.services_tab = ttk.Frame(
            self.notebook
        )

        self.fingerprint_tab = ttk.Frame(
            self.notebook
        )

        self.topology_tab = ttk.Frame(
            self.notebook
        )

        self.logs_tab = ttk.Frame(
            self.notebook
        )

        self.notebook.add(
            self.discovery_tab,
            text="  Discovery  ",
        )

        self.notebook.add(
            self.hosts_tab,
            text="  Hosts  ",
        )

        self.notebook.add(
            self.services_tab,
            text="  Services  ",
        )

        self.notebook.add(
            self.fingerprint_tab,
            text="  Fingerprint  ",
        )

        self.notebook.add(
            self.topology_tab,
            text="  Topology  ",
        )

        self.notebook.add(
            self.logs_tab,
            text="  Logs  ",
        )

        self.build_discovery()

        self.build_hosts()

        self.build_services()

        self.build_fingerprint()

        self.build_topology()

        self.build_logs()

    # ========================================================
    # DISCOVERY TAB
    # ========================================================

    def build_discovery(self):

        base = ttk.Frame(
            self.discovery_tab,
            padding=12,
        )

        base.pack(
            fill="both",
            expand=True,
        )

        controls = ttk.Frame(
            base,
            style="Card.TFrame",
            padding=15,
        )

        controls.pack(
            fill="x",
            pady=(0, 10),
        )

        ttk.Label(
            controls,
            text="TARGET",
            style="Section.TLabel",
        ).grid(
            row=0,
            column=0,
            sticky="w",
        )

        ttk.Label(
            controls,
            text="CIDR / range / single IP",
            style="Card.TLabel",
        ).grid(
            row=1,
            column=0,
            sticky="w",
        )

        self.target = tk.StringVar(
            value="192.168.1.0/24"
        )

        ttk.Entry(
            controls,
            textvariable=self.target,
            width=27,
        ).grid(
            row=2,
            column=0,
            padx=(0, 14),
            pady=(4, 0),
        )

        ttk.Label(
            controls,
            text="PORT PROFILE",
            style="Section.TLabel",
        ).grid(
            row=0,
            column=1,
            sticky="w",
        )

        ttk.Label(
            controls,
            text="TCP ports",
            style="Card.TLabel",
        ).grid(
            row=1,
            column=1,
            sticky="w",
        )

        self.ports = tk.StringVar(
            value=DEFAULT_PORTS
        )

        ttk.Entry(
            controls,
            textvariable=self.ports,
            width=47,
        ).grid(
            row=2,
            column=1,
            padx=(0, 14),
            pady=(4, 0),
        )

        ttk.Label(
            controls,
            text="THREADS",
            style="Section.TLabel",
        ).grid(
            row=0,
            column=2,
            sticky="w",
        )

        self.threads = tk.IntVar(
            value=64
        )

        ttk.Spinbox(
            controls,
            from_=1,
            to=256,
            textvariable=self.threads,
            width=8,
        ).grid(
            row=2,
            column=2,
            padx=(0, 14),
        )

        ttk.Label(
            controls,
            text="TIMEOUT",
            style="Section.TLabel",
        ).grid(
            row=0,
            column=3,
            sticky="w",
        )

        self.timeout = tk.DoubleVar(
            value=0.8
        )

        ttk.Spinbox(
            controls,
            from_=0.1,
            to=10,
            increment=0.1,
            textvariable=self.timeout,
            width=8,
        ).grid(
            row=2,
            column=3,
            padx=(0, 14),
        )

        self.arp_enabled = tk.BooleanVar(
            value=True
        )

        self.ssdp_enabled = tk.BooleanVar(
            value=True
        )

        self.mdns_enabled = tk.BooleanVar(
            value=True
        )

        ttk.Checkbutton(
            controls,
            text="ARP / MAC",
            variable=self.arp_enabled,
        ).grid(
            row=2,
            column=4,
            padx=4,
        )

        ttk.Checkbutton(
            controls,
            text="SSDP / UPnP",
            variable=self.ssdp_enabled,
        ).grid(
            row=2,
            column=5,
            padx=4,
        )

        ttk.Checkbutton(
            controls,
            text="mDNS",
            variable=self.mdns_enabled,
        ).grid(
            row=2,
            column=6,
            padx=4,
        )

        self.start_button = ttk.Button(
            controls,
            text="▶  START SCAN",
            style="Accent.TButton",
            command=self.start_scan,
        )

        self.start_button.grid(
            row=2,
            column=7,
            padx=(13, 4),
        )

        self.stop_button = ttk.Button(
            controls,
            text="■  STOP",
            style="Danger.TButton",
            command=self.stop_scan,
            state="disabled",
        )

        self.stop_button.grid(
            row=2,
            column=8,
            padx=4,
        )

        self.export_button = ttk.Button(
            controls,
            text="⇩  EXPORT",
            command=self.export_csv,
            state="disabled",
        )

        self.export_button.grid(
            row=2,
            column=9,
            padx=4,
        )

        # ----------------------------------------------------
        # Statistics
        # ----------------------------------------------------

        stats = ttk.Frame(
            base
        )

        stats.pack(
            fill="x",
            pady=(0, 10),
        )

        self.stat_labels = {}

        statistic_items = [
            ("status", "STATUS"),
            ("devices", "DEVICES"),
            ("services", "SERVICES"),
            ("macs", "MACs"),
            ("web", "WEB"),
            ("elapsed", "ELAPSED"),
        ]

        for index, (
            key,
            label,
        ) in enumerate(
            statistic_items
        ):

            card = ttk.Frame(
                stats,
                style="Card.TFrame",
                padding=10,
            )

            card.grid(
                row=0,
                column=index,
                padx=(0, 7),
                sticky="ew",
            )

            ttk.Label(
                card,
                text=label,
                style="Card.TLabel",
            ).pack(
                anchor="w"
            )

            value = ttk.Label(
                card,
                text="—",
                style="Card.TLabel",
                font=(
                    "Segoe UI Semibold",
                    14,
                ),
            )

            value.pack(
                anchor="w",
                pady=(2, 0),
            )

            self.stat_labels[
                key
            ] = value

            stats.columnconfigure(
                index,
                weight=1,
            )

        self.progress = ttk.Progressbar(
            base,
            style="Horizontal.TProgressbar",
            mode="determinate",
        )

        self.progress.pack(
            fill="x",
            pady=(0, 10),
        )

        # ----------------------------------------------------
        # Main inventory
        # ----------------------------------------------------

        table_box = ttk.Frame(
            base,
            style="Card.TFrame",
            padding=8,
        )

        table_box.pack(
            fill="both",
            expand=True,
        )

        columns = (
            "ip",
            "device",
            "mac",
            "vendor",
            "hostname",
            "ports",
            "services",
            "fingerprint",
        )

        headings = {
            "ip": "IP ADDRESS",
            "device": "DEVICE TYPE",
            "mac": "MAC ADDRESS",
            "vendor": "VENDOR",
            "hostname": "HOSTNAME",
            "ports": "OPEN PORTS",
            "services": "SERVICES",
            "fingerprint": "FINGERPRINT",
        }

        widths = {
            "ip": 125,
            "device": 150,
            "mac": 145,
            "vendor": 155,
            "hostname": 190,
            "ports": 120,
            "services": 190,
            "fingerprint": 280,
        }

        self.inventory = ttk.Treeview(
            table_box,
            columns=columns,
            show="headings",
        )

        for column in columns:

            self.inventory.heading(
                column,
                text=headings[column],
            )

            self.inventory.column(
                column,
                width=widths[column],
                anchor="w",
            )

        vertical = ttk.Scrollbar(
            table_box,
            orient="vertical",
            command=self.inventory.yview,
        )

        horizontal = ttk.Scrollbar(
            table_box,
            orient="horizontal",
            command=self.inventory.xview,
        )

        self.inventory.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )

        self.inventory.grid(
            row=0,
            column=0,
            sticky="nsew",
        )

        vertical.grid(
            row=0,
            column=1,
            sticky="ns",
        )

        horizontal.grid(
            row=1,
            column=0,
            sticky="ew",
        )

        table_box.rowconfigure(
            0,
            weight=1,
        )

        table_box.columnconfigure(
            0,
            weight=1,
        )

        self.inventory.bind(
            "<<TreeviewSelect>>",
            self.on_device_selected,
        )

    # ========================================================
    # HOSTS TAB
    # ========================================================

    def build_hosts(self):

        container = ttk.Frame(
            self.hosts_tab,
            padding=18,
        )

        container.pack(
            fill="both",
            expand=True,
        )

        card = ttk.Frame(
            container,
            style="Card.TFrame",
            padding=15,
        )

        card.pack(
            fill="both",
            expand=True,
        )

        ttk.Label(
            card,
            text="Discovered Hosts",
            style="Section.TLabel",
        ).pack(
            anchor="w",
            pady=(0, 10),
        )

        columns = (
            "ip",
            "mac",
            "vendor",
            "hostname",
            "device",
            "ports",
        )

        self.host_tree = ttk.Treeview(
            card,
            columns=columns,
            show="headings",
        )

        headings = [
            "IP ADDRESS",
            "MAC",
            "VENDOR",
            "HOSTNAME",
            "DEVICE TYPE",
            "OPEN PORTS",
        ]

        for column, heading in zip(
            columns,
            headings,
        ):

            self.host_tree.heading(
                column,
                text=heading,
            )

        self.host_tree.column(
            "ip",
            width=140,
        )

        self.host_tree.column(
            "mac",
            width=160,
        )

        self.host_tree.column(
            "vendor",
            width=190,
        )

        self.host_tree.column(
            "hostname",
            width=230,
        )

        self.host_tree.column(
            "device",
            width=170,
        )

        self.host_tree.column(
            "ports",
            width=180,
        )

        self.host_tree.pack(
            fill="both",
            expand=True,
        )

    # ========================================================
    # SERVICES TAB
    # ========================================================

    def build_services(self):

        container = ttk.Frame(
            self.services_tab,
            padding=18,
        )

        container.pack(
            fill="both",
            expand=True,
        )

        card = ttk.Frame(
            container,
            style="Card.TFrame",
            padding=15,
        )

        card.pack(
            fill="both",
            expand=True,
        )

        ttk.Label(
            card,
            text="Observed Services",
            style="Section.TLabel",
        ).pack(
            anchor="w",
            pady=(0, 10),
        )

        columns = (
            "ip",
            "port",
            "service",
            "title",
            "server",
            "latency",
        )

        self.service_tree = ttk.Treeview(
            card,
            columns=columns,
            show="headings",
        )

        headings = {
            "ip": "IP ADDRESS",
            "port": "PORT",
            "service": "SERVICE",
            "title": "TITLE / PTR",
            "server": "SERVER",
            "latency": "LATENCY",
        }

        for column in columns:

            self.service_tree.heading(
                column,
                text=headings[column],
            )

        self.service_tree.column(
            "ip",
            width=140,
        )

        self.service_tree.column(
            "port",
            width=80,
        )

        self.service_tree.column(
            "service",
            width=140,
        )

        self.service_tree.column(
            "title",
            width=340,
        )

        self.service_tree.column(
            "server",
            width=260,
        )

        self.service_tree.column(
            "latency",
            width=100,
        )

        self.service_tree.pack(
            fill="both",
            expand=True,
        )

    # ========================================================
    # FINGERPRINT TAB
    # ========================================================

    def build_fingerprint(self):

        container = ttk.Frame(
            self.fingerprint_tab,
            padding=18,
        )

        container.pack(
            fill="both",
            expand=True,
        )

        self.fingerprint_text = tk.Text(
            container,
            bg="#ffffff",
            fg="#26364a",
            relief="flat",
            font=(
                "Consolas",
                10,
            ),
            padx=18,
            pady=18,
        )

        self.fingerprint_text.pack(
            fill="both",
            expand=True,
        )

        self.fingerprint_text.insert(
            "1.0",
            "Select a discovered device to inspect its fingerprint.",
        )

        self.fingerprint_text.configure(
            state="disabled"
        )

    # ========================================================
    # TOPOLOGY TAB
    # ========================================================

    def build_topology(self):

        container = ttk.Frame(
            self.topology_tab,
            padding=18,
        )

        container.pack(
            fill="both",
            expand=True,
        )

        self.topology_canvas = tk.Canvas(
            container,
            bg="#f8fafc",
            highlightthickness=0,
        )

        self.topology_canvas.pack(
            fill="both",
            expand=True,
        )

        self.topology_canvas.create_text(
            40,
            40,
            anchor="nw",
            text=(
                "LAN Topology\n\n"
                "Run a discovery scan to populate "
                "the host topology."
            ),
            fill="#64748b",
            font=(
                "Segoe UI",
                12,
            ),
        )

    # ========================================================
    # LOGS TAB
    # ========================================================

    def build_logs(self):

        container = ttk.Frame(
            self.logs_tab,
            padding=18,
        )

        container.pack(
            fill="both",
            expand=True,
        )

        self.log_console = tk.Text(
            container,
            bg="#172033",
            fg="#d7e3f4",
            insertbackground="#ffffff",
            relief="flat",
            font=(
                "Consolas",
                9,
            ),
            padx=14,
            pady=12,
        )

        self.log_console.pack(
            fill="both",
            expand=True,
        )

        self.log(
            "IoT Scout initialized."
        )

    # ========================================================
    # LOG
    # ========================================================

    def log(self, message):

        self.log_console.insert(
            "end",
            (
                f"[{time.strftime('%H:%M:%S')}] "
                f"{message}\n"
            ),
        )

        self.log_console.see(
            "end"
        )

    # ========================================================
    # START SCAN
    # ========================================================

    def start_scan(self):

        if (
            self.worker
            and self.worker.is_alive()
        ):
            return

        try:

            targets = parse_targets(
                self.target.get()
            )

            ports = sorted(
                set(
                    int(x.strip())
                    for x in self.ports.get().split(",")
                    if x.strip()
                )
            )

            if not ports:
                raise ValueError(
                    "No ports specified."
                )

            if any(
                p < 1 or p > 65535
                for p in ports
            ):
                raise ValueError(
                    "Ports must be 1-65535."
                )

            threads = max(
                1,
                min(
                    256,
                    int(
                        self.threads.get()
                    ),
                ),
            )

            timeout = max(
                0.1,
                min(
                    10,
                    float(
                        self.timeout.get()
                    ),
                ),
            )

        except Exception as error:

            messagebox.showerror(
                "Invalid Scan Profile",
                str(error),
            )

            return

        self.results = []

        self.host_items = {}

        self.completed = 0

        self.started = time.time()

        self.total = (
            len(targets)
            * len(ports)
        )

        self.stop_event.clear()

        for item in self.inventory.get_children():
            self.inventory.delete(
                item
            )

        for item in self.host_tree.get_children():
            self.host_tree.delete(
                item
            )

        for item in self.service_tree.get_children():
            self.service_tree.delete(
                item
            )

        self.progress["maximum"] = max(
            1,
            self.total,
        )

        self.progress["value"] = 0

        self.start_button.configure(
            state="disabled"
        )

        self.stop_button.configure(
            state="normal"
        )

        self.export_button.configure(
            state="disabled"
        )

        self.stat_labels[
            "status"
        ].configure(
            text="SCANNING"
        )

        self.log(
            f"Target: {self.target.get()}"
        )

        self.log(
            f"Hosts: {len(targets)}"
        )

        self.log(
            f"TCP ports: {len(ports)}"
        )

        self.worker = threading.Thread(
            target=self.run_scan,
            args=(
                targets,
                ports,
                threads,
                timeout,
            ),
            daemon=True,
        )

        self.worker.start()

    # ========================================================
    # STOP
    # ========================================================

    def stop_scan(self):

        self.stop_event.set()

        self.stop_button.configure(
            state="disabled"
        )

        self.log(
            "Stop requested..."
        )

    # ========================================================
    # TCP PROBE
    # ========================================================

    def tcp_probe(
        self,
        ip,
        port,
        timeout,
    ):

        started = time.perf_counter()

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        sock.settimeout(
            timeout
        )

        try:

            if sock.connect_ex(
                (
                    ip,
                    port,
                )
            ) != 0:

                return None

        except OSError:

            return None

        finally:

            try:
                sock.close()
            except OSError:
                pass

        latency = (
            time.perf_counter()
            - started
        ) * 1000

        result = {
            "ip": ip,
            "port": port,
            "service": SERVICE_MAP.get(
                port,
                "TCP",
            ),
            "title": "",
            "server": "",
            "detail": "",
            "latency": latency,
        }

        # HTTP fingerprint
        if port in (
            80,
            443,
            8000,
            8080,
            8443,
        ):

            scheme = (
                "https"
                if port in (
                    443,
                    8443,
                )
                else "http"
            )

            try:

                context = (
                    ssl._create_unverified_context()
                )

                request = Request(
                    f"{scheme}://{ip}:{port}/",
                    headers={
                        "User-Agent":
                        "IoT-Scout/2.0"
                    },
                )

                with urlopen(
                    request,
                    timeout=timeout,
                    context=context,
                ) as response:

                    body = response.read(
                        65536
                    ).decode(
                        "utf-8",
                        errors="ignore",
                    )

                    result[
                        "server"
                    ] = response.headers.get(
                        "Server",
                        "",
                    )

                    title_match = re.search(
                        r"<title[^>]*>"
                        r"(.*?)"
                        r"</title>",
                        body,
                        re.I | re.S,
                    )

                    if title_match:

                        result[
                            "title"
                        ] = re.sub(
                            r"\s+",
                            " ",
                            title_match.group(1),
                        ).strip()

            except Exception:
                pass

        return result

    # ========================================================
    # RUN SCAN
    # ========================================================

    def run_scan(
        self,
        targets,
        ports,
        worker_count,
        timeout,
    ):

        macs = {}

        if self.arp_enabled.get():

            macs = get_arp_cache()

            self.queue.put(
                (
                    "log",
                    f"ARP cache: {len(macs)} entries",
                )
            )

        def enrich(result):

            ip = result["ip"]

            result["mac"] = macs.get(
                ip,
                "",
            )

            result["vendor"] = get_vendor(
                result["mac"],
                self.oui,
            )

            result["hostname"] = reverse_dns(
                ip
            )

            result["device"] = classify_device(
                [result],
                result["vendor"],
                result["hostname"],
            )

            return result

        # ----------------------------------------------------
        # SSDP
        # ----------------------------------------------------

        if self.ssdp_enabled.get():

            found = ssdp_discover()

            for result in found:

                self.queue.put(
                    (
                        "result",
                        enrich(result),
                    )
                )

            self.queue.put(
                (
                    "log",
                    f"SSDP/UPnP: {len(found)} responses",
                )
            )

        # ----------------------------------------------------
        # mDNS
        # ----------------------------------------------------

        if self.mdns_enabled.get():

            found = mdns_discover()

            for result in found:

                self.queue.put(
                    (
                        "result",
                        enrich(result),
                    )
                )

            self.queue.put(
                (
                    "log",
                    f"mDNS: {len(found)} observations",
                )
            )

        # ----------------------------------------------------
        # TCP queue
        # ----------------------------------------------------

        jobs = queue.Queue()

        for ip in targets:

            for port in ports:

                jobs.put(
                    (
                        ip,
                        port,
                    )
                )

        def worker():

            while not self.stop_event.is_set():

                try:

                    ip, port = jobs.get_nowait()

                except queue.Empty:

                    return

                try:

                    result = self.tcp_probe(
                        ip,
                        port,
                        timeout,
                    )

                    if result:

                        self.queue.put(
                            (
                                "result",
                                enrich(result),
                            )
                        )

                finally:

                    self.queue.put(
                        (
                            "progress",
                            1,
                        )
                    )

                    jobs.task_done()

        threads = []

        for _ in range(
            min(
                worker_count,
                max(
                    1,
                    self.total,
                ),
            )
        ):

            thread = threading.Thread(
                target=worker,
                daemon=True,
            )

            thread.start()

            threads.append(
                thread
            )

        for thread in threads:

            thread.join()

        self.queue.put(
            (
                "finished",
                self.stop_event.is_set(),
            )
        )

    # ========================================================
    # ADD RESULT
    # ========================================================

    def add_result(self, result):

        self.results.append(
            result
        )

        ip = result["ip"]

        if ip not in self.host_items:

            item = self.inventory.insert(
                "",
                "end",
                values=(
                    ip,
                    result.get(
                        "device",
                        "Unknown",
                    ),
                    result.get(
                        "mac",
                        "",
                    ),
                    result.get(
                        "vendor",
                        "Unknown",
                    ),
                    result.get(
                        "hostname",
                        "",
                    ),
                    str(
                        result.get(
                            "port",
                            "",
                        )
                    ),
                    result.get(
                        "service",
                        "",
                    ),
                    result.get(
                        "title",
                        "",
                    )
                    or result.get(
                        "detail",
                        "",
                    ),
                ),
            )

            self.host_items[
                ip
            ] = item

        else:

            item = self.host_items[
                ip
            ]

            values = list(
                self.inventory.item(
                    item,
                    "values",
                )
            )

            # device
            if (
                values[1] == "Unknown"
                and result.get("device")
            ):
                values[1] = result[
                    "device"
                ]

            # MAC
            if (
                not values[2]
                and result.get("mac")
            ):
                values[2] = result[
                    "mac"
                ]

            # Vendor
            if (
                values[3] == "Unknown"
                and result.get("vendor")
            ):
                values[3] = result[
                    "vendor"
                ]

            # Hostname
            if (
                not values[4]
                and result.get("hostname")
            ):
                values[4] = result[
                    "hostname"
                ]

            # Ports
            port = str(
                result.get(
                    "port",
                    "",
                )
            )

            existing_ports = (
                values[5].split(",")
                if values[5]
                else []
            )

            if port not in existing_ports:

                existing_ports.append(
                    port
                )

            values[5] = ",".join(
                existing_ports
            )

            # Services
            service = result.get(
                "service",
                "",
            )

            existing_services = (
                [
                    x.strip()
                    for x in values[6].split(",")
                ]
                if values[6]
                else []
            )

            if (
                service
                and service not in existing_services
            ):

                existing_services.append(
                    service
                )

            values[6] = ", ".join(
                existing_services
            )

            # Fingerprint
            fingerprint = (
                result.get("title")
                or result.get("detail")
                or result.get("server")
            )

            if (
                fingerprint
                and not values[7]
            ):

                values[7] = fingerprint

            self.inventory.item(
                item,
                values=values,
            )

        # Services tab

        self.service_tree.insert(
            "",
            "end",
            values=(
                result.get("ip", ""),
                result.get("port", ""),
                result.get("service", ""),
                result.get("title", "")
                or result.get("detail", ""),
                result.get("server", ""),
                (
                    f"{result.get('latency', 0):.0f} ms"
                    if result.get("latency")
                    else ""
                ),
            ),
        )

        self.refresh_host_tab()

    # ========================================================
    # HOST TAB
    # ========================================================

    def refresh_host_tab(self):

        for item in self.host_tree.get_children():

            self.host_tree.delete(
                item
            )

        hosts = {}

        for result in self.results:

            ip = result["ip"]

            if ip not in hosts:

                hosts[ip] = {
                    "ip": ip,
                    "mac": result.get(
                        "mac",
                        "",
                    ),
                    "vendor": result.get(
                        "vendor",
                        "Unknown",
                    ),
                    "hostname": result.get(
                        "hostname",
                        "",
                    ),
                    "device": result.get(
                        "device",
                        "Unknown",
                    ),
                    "ports": [],
                }

            if result.get("port"):

                port = str(
                    result["port"]
                )

                if port not in hosts[ip]["ports"]:

                    hosts[ip]["ports"].append(
                        port
                    )

        for host in hosts.values():

            self.host_tree.insert(
                "",
                "end",
                values=(
                    host["ip"],
                    host["mac"],
                    host["vendor"],
                    host["hostname"],
                    host["device"],
                    ",".join(
                        host["ports"]
                    ),
                ),
            )

    # ========================================================
    # DEVICE SELECTED
    # ========================================================

    def on_device_selected(
        self,
        event=None,
    ):

        selection = self.inventory.selection()

        if not selection:
            return

        values = self.inventory.item(
            selection[0],
            "values",
        )

        if not values:
            return

        ip = values[0]

        device_results = [
            result
            for result in self.results
            if result["ip"] == ip
        ]

        text = []

        text.append(
            "DEVICE FINGERPRINT"
        )

        text.append(
            "=" * 65
        )

        text.append(
            f"IP Address : {ip}"
        )

        text.append(
            f"Device Type: {values[1]}"
        )

        text.append(
            f"MAC Address: {values[2]}"
        )

        text.append(
            f"Vendor     : {values[3]}"
        )

        text.append(
            f"Hostname   : {values[4]}"
        )

        text.append(
            ""
        )

        text.append(
            "OBSERVED SERVICES"
        )

        text.append(
            "-" * 65
        )

        for result in device_results:

            text.append(
                f"{result.get('port',''):<6} "
                f"{result.get('service',''):<18} "
                f"{result.get('title','') or result.get('detail','')}"
            )

            if result.get("server"):

                text.append(
                    f"       Server: {result['server']}"
                )

        self.fingerprint_text.configure(
            state="normal"
        )

        self.fingerprint_text.delete(
            "1.0",
            "end",
        )

        self.fingerprint_text.insert(
            "1.0",
            "\n".join(text),
        )

        self.fingerprint_text.configure(
            state="disabled"
        )

        self.notebook.select(
            self.fingerprint_tab
        )

    # ========================================================
    # QUEUE PROCESSOR
    # ========================================================

    def process_queue(self):

        try:

            while True:

                kind, data = (
                    self.queue.get_nowait()
                )

                if kind == "result":

                    self.add_result(
                        data
                    )

                elif kind == "progress":

                    self.completed += data

                    self.progress[
                        "value"
                    ] = self.completed

                elif kind == "log":

                    self.log(
                        data
                    )

                elif kind == "finished":

                    self.start_button.configure(
                        state="normal"
                    )

                    self.stop_button.configure(
                        state="disabled"
                    )

                    self.export_button.configure(
                        state=(
                            "normal"
                            if self.results
                            else "disabled"
                        )
                    )

                    self.stat_labels[
                        "status"
                    ].configure(
                        text=(
                            "STOPPED"
                            if data
                            else "COMPLETE"
                        )
                    )

                    device_count = len(
                        self.host_items
                    )

                    self.log(
                        f"Discovery complete: "
                        f"{device_count} hosts / "
                        f"{len(self.results)} observations."
                    )

        except queue.Empty:

            pass

        devices = len(
            self.host_items
        )

        macs = len(
            {
                r.get("mac")
                for r in self.results
                if r.get("mac")
            }
        )

        web = sum(
            1
            for r in self.results
            if r.get("port")
            in (
                80,
                443,
                8000,
                8080,
                8443,
            )
        )

        self.stat_labels[
            "devices"
        ].configure(
            text=str(devices)
        )

        self.stat_labels[
            "services"
        ].configure(
            text=str(
                len(self.results)
            )
        )

        self.stat_labels[
            "macs"
        ].configure(
            text=str(macs)
        )

        self.stat_labels[
            "web"
        ].configure(
            text=str(web)
        )

        if self.started:

            self.stat_labels[
                "elapsed"
            ].configure(
                text=f"{time.time() - self.started:.1f}s"
            )

        self.root.after(
            100,
            self.process_queue,
        )

    # ========================================================
    # EXPORT
    # ========================================================

    def export_csv(self):

        if not self.results:
            return

        filename = filedialog.asksaveasfilename(
            title="Export IoT Inventory",
            defaultextension=".csv",
            filetypes=[
                (
                    "CSV files",
                    "*.csv",
                )
            ],
        )

        if not filename:
            return

        fields = [
            "ip",
            "mac",
            "vendor",
            "hostname",
            "device",
            "port",
            "service",
            "title",
            "server",
            "detail",
            "latency",
        ]

        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8-sig",
        ) as file:

            writer = csv.DictWriter(
                file,
                fieldnames=fields,
            )

            writer.writeheader()

            for result in self.results:

                writer.writerow(
                    {
                        field: result.get(
                            field,
                            "",
                        )
                        for field in fields
                    }
                )

        self.log(
            f"Exported {len(self.results)} observations."
        )

        messagebox.showinfo(
            "Export Complete",
            f"Saved {len(self.results)} observations.",
        )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = IotScout(
        root
    )

    root.mainloop()