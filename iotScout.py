import os
import re
import csv
import json
import time
import queue
import hashlib
import threading
import ipaddress
from collections import Counter, defaultdict
from datetime import datetime

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from scapy.all import (
    PcapReader,
    Ether,
    ARP,
    IP,
    IPv6,
    TCP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    DHCP,
    Raw,
	ICMP,
)


# ============================================================
# IoT PCAP ANALYZER
# CyberX
# Full working PCAP/PCAPNG analyzer
# ============================================================


APP_NAME = "IoT ScouT"
APP_VERSION = "2.0.0"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SETTINGS_FILE = os.path.join(BASE_DIR, "iot_pcap_settings.json")


# ============================================================
# COLORS
# ============================================================

COLORS = {
    "bg": "#EEF3F8",
    "surface": "#FFFFFF",
    "surface2": "#F6F9FC",
    "border": "#D7E1EA",

    "sidebar": "#172A3A",
    "sidebar_hover": "#24465D",
    "sidebar_active": "#159A9C",

    "text": "#17212B",
    "muted": "#6C7D8D",

    "accent": "#159A9C",
    "accent_dark": "#117E80",
    "accent_light": "#DDF5F4",

    "blue": "#2878D4",
    "blue_light": "#E7F0FC",

    "green": "#2E9968",
    "green_light": "#E3F4EC",

    "orange": "#D9822B",
    "orange_light": "#FFF0DF",

    "red": "#D9534F",
    "red_light": "#FBE8E7",

    "purple": "#7657C5",
    "purple_light": "#EEE9FB",

    "cyan": "#208FA8",
    "cyan_light": "#E3F4F8",
}


# ============================================================
# DEFAULT SETTINGS
# ============================================================

DEFAULT_SETTINGS = {
    "analysis": {
        "oui_analysis": True,
        "arp_analysis": True,
        "dhcp_analysis": True,
        "dns_analysis": True,
        "mdns_analysis": True,
        "ssdp_analysis": True,
        "mqtt_detection": True,
        "rtsp_detection": True,
        "http_fingerprinting": True,
        "tls_analysis": True,
        "traffic_behaviour": True,
    },
    "detection": {
        "iot_threshold": 60,
        "high_confidence": 80,
    },
    "interface": {
        "remember_last_pcap": True,
    },
    "fingerprinting": {
        "use_protocol_fingerprints": True,
        "use_dns_vendor_hints": True,
        "use_randomized_mac_detection": True,
    },
    "paths": {
        "last_pcap": "",
        "oui_file": "",
        "device_csv": "",
    },
}


# ============================================================
# HELPERS
# ============================================================

def safe_text(value):
    if value is None:
        return ""

    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return value.decode("latin-1", errors="ignore")

    return str(value)


def normalize_mac(mac):
    if not mac:
        return ""

    value = safe_text(mac).lower().replace("-", ":")
    parts = value.split(":")

    if len(parts) == 6:
        return ":".join(part.zfill(2) for part in parts)

    return value


def get_oui(mac):
    mac = normalize_mac(mac)

    if len(mac) < 8:
        return ""

    return mac[:8].upper()


def is_private_or_local(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
        )
    except Exception:
        return False


def sha256_file(path, callback=None):
    digest = hashlib.sha256()

    size = os.path.getsize(path)
    processed = 0

    with open(path, "rb") as handle:

        while True:

            chunk = handle.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

            processed += len(chunk)

            if callback and size:
                callback(processed / size * 100)

    return digest.hexdigest()


def format_bytes(value):
    try:
        value = float(value)
    except Exception:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB"]

    for unit in units:

        if value < 1024:
            return f"{value:.1f} {unit}"

        value /= 1024

    return f"{value:.1f} PB"


def format_timestamp(ts):
    if ts is None:
        return ""

    try:
        return datetime.fromtimestamp(float(ts)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except Exception:
        return safe_text(ts)


def extract_ascii(payload):
    if not payload:
        return ""

    try:
        return bytes(payload).decode(
            "utf-8",
            errors="ignore"
        )
    except Exception:
        return ""


def parse_http_headers(payload):
    text = extract_ascii(payload)

    if not text:
        return {}

    lines = text.split("\r\n")

    headers = {}

    if lines:
        headers["_request_line"] = lines[0]

    for line in lines[1:]:

        if ":" not in line:
            continue

        key, value = line.split(":", 1)

        headers[key.strip().lower()] = value.strip()

    return headers


def looks_like_http(payload):
    if not payload:
        return False

    text = extract_ascii(payload[:2048])

    methods = (
        "GET ",
        "POST ",
        "PUT ",
        "DELETE ",
        "HEAD ",
        "OPTIONS ",
        "PATCH ",
        "HTTP/1.0",
        "HTTP/1.1",
        "HTTP/2",
    )

    return text.startswith(methods)


def extract_dns_names(packet):
    names = []

    if not packet.haslayer(DNS):
        return names

    dns = packet[DNS]

    try:

        if dns.qd:

            for i in range(int(dns.qdcount)):

                try:
                    item = dns.qd[i]

                    name = safe_text(
                        item.qname
                    ).rstrip(".")

                    if name:
                        names.append(name)

                except Exception:
                    break

    except Exception:
        pass

    try:

        if dns.an:

            for i in range(int(dns.ancount)):

                try:
                    item = dns.an[i]

                    name = safe_text(
                        item.rrname
                    ).rstrip(".")

                    if name:
                        names.append(name)

                except Exception:
                    break

    except Exception:
        pass

    return list(dict.fromkeys(names))


# ============================================================
# DEVICE FINGERPRINT HELPERS
# ============================================================

VENDOR_FINGERPRINTS = {
    "hikvision": "Hikvision", "hik-connect": "Hikvision", "ezviz": "Hikvision",
    "dahua": "Dahua", "dahuatech": "Dahua",
    "tuya": "Tuya", "smartlife": "Tuya", "smart life": "Tuya",
    "xiaomi": "Xiaomi", "mi.com": "Xiaomi", "miio": "Xiaomi", "mijia": "Xiaomi",
    "tplink": "TP-Link", "tp-link": "TP-Link", "kasa": "TP-Link", "tapo": "TP-Link",
    "ubnt": "Ubiquiti", "ubiquiti": "Ubiquiti", "unifi": "Ubiquiti",
    "espressif": "Espressif", "esp32": "Espressif", "esp8266": "Espressif",
    "amazon": "Amazon", "amazonaws": "Amazon", "alexa": "Amazon", "echo": "Amazon",
    "google": "Google", "chromecast": "Google", "nest": "Google/Nest", "googlecast": "Google",
    "apple": "Apple", "airplay": "Apple", "homekit": "Apple", "bonjour": "Apple",
    "samsung": "Samsung", "tizen": "Samsung",
    "sony": "Sony", "bravia": "Sony",
    "ring": "Ring", "arlo": "Arlo", "eufy": "Eufy", "wyze": "Wyze",
    "sonos": "Sonos", "roku": "Roku", "wemo": "Belkin/Wemo",
    "philips": "Philips", "hue": "Philips Hue",
    "raspberry": "Raspberry Pi", "raspberrypi": "Raspberry Pi",
    "netgear": "NETGEAR", "dlink": "D-Link", "linksys": "Linksys",
    "synology": "Synology", "qnap": "QNAP", "western digital": "Western Digital",
    "printer": "Printer", "epson": "Epson", "brother": "Brother", "canon": "Canon", "hp": "HP",
}

DEVICE_FINGERPRINTS = {
    "camera": "IP Camera", "hikvision": "IP Camera", "ezviz": "IP Camera", "dahua": "IP Camera",
    "rtsp": "IP Camera", "onvif": "IP Camera", "ipc": "IP Camera", "nvr": "NVR / Camera System",
    "dvr": "DVR / Camera System", "doorbell": "Smart Doorbell", "ring": "Smart Doorbell",
    "chromecast": "Smart TV / Media Device", "googlecast": "Smart TV / Media Device", "airplay": "Media Device",
    "sonos": "Smart Speaker", "roku": "Streaming Device", "echo": "Smart Speaker",
    "alexa": "Smart Speaker", "homekit": "Smart Home Device", "tuya": "Smart Home Device",
    "mijia": "Smart Home Device", "kasa": "Smart Plug / IoT", "tapo": "Smart Home Device",
    "mqtt": "IoT / MQTT Device", "coap": "IoT / CoAP Device", "printer": "Network Printer",
    "ipp": "Network Printer", "_printer": "Network Printer", "nas": "NAS / Storage",
    "synology": "NAS / Storage", "qnap": "NAS / Storage", "unifi": "Network Infrastructure",
    "ubiquiti": "Network Infrastructure", "router": "Router / Gateway", "gateway": "Router / Gateway",
    "esp32": "Embedded / IoT Device", "esp8266": "Embedded / IoT Device", "espressif": "Embedded / IoT Device",
}


def fingerprint_tokens(*values):
    text = " ".join(safe_text(v) for v in values if v)
    return text.lower()


def load_external_oui(path):
    """
    Load vendor/OUI mappings from an external CSV/TXT file.

    Supported formats:

        28:6F:B9    Nokia Shanghai Bell Co., Ltd.
        38:E2:CA    Katun Corporation
        E8:0A:B9    Cisco

    Also supports:

        28-6F-B9,Nokia Shanghai Bell Co., Ltd.
        286FB9,Nokia Shanghai Bell Co., Ltd.
        28:6F:B9,Nokia Shanghai Bell Co., Ltd.
        28:6F:B9;Nokia Shanghai Bell Co., Ltd.

    The first 6 hexadecimal characters are used as the OUI.
    """

    database = {}

    if not path:
        return database

    if not os.path.isfile(path):
        return database

    try:
        with open(path, "r", encoding="utf-8-sig", errors="ignore") as handle:

            for raw_line in handle:

                line = raw_line.strip()

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # ----------------------------------------------------
                # Remove BOM / surrounding whitespace
                # ----------------------------------------------------
                line = line.replace("\ufeff", "").strip()

                # ----------------------------------------------------
                # Try to identify OUI at the beginning of the line.
                #
                # Accepted:
                #   AA:BB:CC Vendor
                #   AA-BB-CC Vendor
                #   AABBCC Vendor
                #   AA:BB:CC,Vendor
                #   AA:BB:CC;Vendor
                # ----------------------------------------------------
                match = re.match(
                    r"""
                    ^\s*
                    (
                        [0-9A-Fa-f]{2}(?:[:\-][0-9A-Fa-f]{2}){2}
                        |
                        [0-9A-Fa-f]{6}
                    )
                    \s*
                    (?:
                        [,\t;]
                        |
                        \s{2,}
                        |
                        \s+
                    )
                    (.+?)
                    \s*$
                    """,
                    line,
                    re.VERBOSE,
                )

                if not match:
                    continue

                raw_oui = match.group(1)
                vendor = match.group(2).strip()

                # ----------------------------------------------------
                # Normalize OUI
                # 28:6F:B9 -> 286FB9
                # 28-6F-B9 -> 286FB9
                # 286FB9   -> 286FB9
                # ----------------------------------------------------
                oui = re.sub(
                    r"[^0-9A-Fa-f]",
                    "",
                    raw_oui
                ).upper()

                if len(oui) != 6:
                    continue

                if not vendor:
                    continue

                # ----------------------------------------------------
                # Store normalized OUI -> vendor
                # ----------------------------------------------------
                database[oui] = vendor

    except Exception as exc:

        print(
            f"[OUI] Failed to load external vendor file "
            f"'{path}': {exc}"
        )

    return database


def normalize_csv_header(value):
    """Normalize CSV column names for flexible header matching."""
    return re.sub(
        r"[^a-z0-9]+",
        "_",
        safe_text(value).strip().lower()
    ).strip("_")


def load_device_csv(path):
    """
    Load a simple device mapping CSV.

    Supported columns:
        MAC, Make, Model

    Also accepts common aliases such as:
        MAC Address / mac_address
        Manufacturer / Vendor
        Device Model / device_model

    MAC matching supports:
        - exact full MAC address
        - first 3 octets / OUI fallback
    """
    exact = {}
    oui = {}

    if not path or not os.path.isfile(path):
        return {
            "exact": exact,
            "oui": oui,
            "count": 0,
        }

    try:
        with open(
            path,
            "r",
            encoding="utf-8-sig",
            errors="ignore",
            newline=""
        ) as handle:

            sample = handle.read(4096)
            handle.seek(0)

            try:
                dialect = csv.Sniffer().sniff(
                    sample,
                    delimiters=",;\\t"
                )
            except Exception:
                dialect = csv.excel

            reader = csv.DictReader(
                handle,
                dialect=dialect
            )

            if not reader.fieldnames:
                return {
                    "exact": exact,
                    "oui": oui,
                    "count": 0,
                }

            field_map = {
                normalize_csv_header(name): name
                for name in reader.fieldnames
                if name
            }

            def find_field(*names):
                for name in names:
                    key = normalize_csv_header(name)
                    if key in field_map:
                        return field_map[key]
                return None

            mac_field = find_field(
                "mac",
                "mac_address",
                "mac address",
                "macaddress",
            )

            make_field = find_field(
                "make",
                "manufacturer",
                "vendor",
                "brand",
                "device_make",
            )

            model_field = find_field(
                "model",
                "device_model",
                "device model",
                "product",
                "product_model",
            )

            if not mac_field:
                return {
                    "exact": exact,
                    "oui": oui,
                    "count": 0,
                }

            count = 0

            for row in reader:
                raw_mac = row.get(mac_field, "")
                mac = normalize_mac(raw_mac)

                if not mac:
                    continue

                clean = re.sub(
                    r"[^0-9a-f]",
                    "",
                    mac.lower()
                )

                if len(clean) != 12:
                    continue

                normalized = ":".join(
                    clean[i:i + 2]
                    for i in range(0, 12, 2)
                )

                make = safe_text(
                    row.get(make_field, "")
                    if make_field else ""
                ).strip()

                model = safe_text(
                    row.get(model_field, "")
                    if model_field else ""
                ).strip()

                if not make and not model:
                    continue

                record = {
                    "make": make,
                    "model": model,
                    "mac": normalized,
                }

                exact[normalized] = record
                oui[clean[:6].upper()] = record
                count += 1

            return {
                "exact": exact,
                "oui": oui,
                "count": count,
            }

    except Exception:
        return {
            "exact": exact,
            "oui": oui,
            "count": 0,
        }


# ============================================================
# BUILT-IN OUI DATABASE
# ============================================================

# Common IoT / embedded vendors.
# The analyzer does not require internet access.
OUI_DATABASE = {
    "001C42": "Parallels",
    "001E06": "Toshiba",
    "00237F": "Hon Hai / Foxconn",
    "00250F": "Cisco",
    "0026BB": "Apple",
    "001A11": "Google",
    "001788": "Cisco-Linksys",
    "001B63": "Apple",
    "001C23": "Dell",
    "001D25": "Samsung",
    "001E58": "Samsung",
    "001FE2": "Samsung",
    "002339": "Samsung",
    "0023C2": "Samsung",
    "0024E9": "Samsung",
    "0026E2": "Samsung",
    "3C5A37": "Samsung",
    "5C0A5B": "Samsung",
    "D0DF9A": "Samsung",

    "001A7D": "Ubiquiti",
    "002722": "Ubiquiti",
    "04180F": "Ubiquiti",
    "18E829": "Ubiquiti",
    "24A43C": "Ubiquiti",
    "44D9E7": "Ubiquiti",
    "68D79A": "Ubiquiti",
    "74ACB9": "Ubiquiti",
    "788A20": "Ubiquiti",
    "802AA8": "Ubiquiti",
    "B4FB57": "Ubiquiti",
    "FC5B39": "Ubiquiti",

    "001132": "Cisco",
    "001A2B": "Cisco",
    "001A30": "Cisco",
    "0021A0": "Cisco",
    "0023EA": "Cisco",
    "0026CA": "Cisco",

    "001C10": "Hikvision",
    "28:57:BE": "Hikvision",
    "44:19:B6": "Hikvision",
    "54:8C:A0": "Hikvision",
    "BC:AD:28": "Hikvision",

    "001122": "Cisco",
    "B827EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E45F01": "Raspberry Pi",

    "B0B448": "Espressif",
    "24:0A:C4": "Espressif",
    "30:AE:A4": "Espressif",
    "3C:61:05": "Espressif",
    "7C:DF:A1": "Espressif",
    "84:F3:EB": "Espressif",
    "A4:CF:12": "Espressif",
    "AC:67:B2": "Espressif",
    "CC:50:E3": "Espressif",
    "EC:62:60": "Espressif",

    "10:CE:A9": "Tuya",
    "D8:1F:12": "Tuya",
    "50:02:91": "Tuya",
    "7C:F6:66": "Tuya",

    "0019A9": "TP-Link",
    "14CC20": "TP-Link",
    "30DE4B": "TP-Link",
    "50C7BF": "TP-Link",
    "54C80F": "TP-Link",
    "98DAc4".upper(): "TP-Link",

    "001E5A": "Amazon",
    "0C47C9": "Amazon",
    "18:74:2E": "Amazon",
    "34:D2:70": "Amazon",
    "40:B4:F0": "Amazon",
    "44:65:0D": "Amazon",
    "68:54:FD": "Amazon",
    "74:75:48": "Amazon",
    "A0:02:DC": "Amazon",
    "AC:63:BE": "Amazon",

    "001EC0": "Nest",
    "18:B4:30": "Nest",
    "64:16:66": "Nest",

    "0024E4": "Sony",
    "001A80": "Sony",
    "FC:F1:52": "Sony",

    "000C29": "VMware",
    "005056": "VMware",

    "080027": "VirtualBox",
}


# Normalize database keys to first six hexadecimal characters.
NORMALIZED_OUI = {}

for key, vendor in OUI_DATABASE.items():

    clean = re.sub(
        r"[^0-9A-Fa-f]",
        "",
        key
    ).upper()

    if len(clean) >= 6:
        NORMALIZED_OUI[clean[:6]] = vendor


# ============================================================
# ANALYSIS ENGINE
# ============================================================

class PCAPAnalyzer:

    def __init__(self, settings, event_queue):

        self.settings = settings
        self.events = event_queue

        self.cancel_requested = False
        self.external_oui = load_external_oui(
            self.settings.get("paths", {}).get("oui_file", "")
        )

        self.device_database = load_device_csv(
            self.settings.get("paths", {}).get("device_csv", "")
        )

        self.reset()

    # --------------------------------------------------------
    # Reset
    # --------------------------------------------------------

    def reset(self):

        self.result = {
            "metadata": {
                "file": "",
                "sha256": "",
                "started": "",
                "completed": "",
                "duration": 0,
            },

            "packets": 0,
            "bytes": 0,

            "hosts": {},

            "protocols": Counter(),

            "services": Counter(),

            "dns_names": Counter(),

            "timeline": [],

            "evidence": [],

            "iot_devices": {},

            "alerts": [],

            "conversations": Counter(),
        }

        self._last_timestamps = defaultdict(list)

    # --------------------------------------------------------
    # Cancel
    # --------------------------------------------------------

    def cancel(self):
        self.cancel_requested = True

    # --------------------------------------------------------
    # Emit
    # --------------------------------------------------------

    def emit(self, event, payload=None):

        self.events.put(
            (
                event,
                payload
            )
        )

    # --------------------------------------------------------
    # Host
    # --------------------------------------------------------

    def ensure_host(self, ip):

        if not ip:
            return None

        if ip not in self.result["hosts"]:

            self.result["hosts"][ip] = {
                "ip": ip,
                "mac": "",
                "macs": [],
                "vendor": "",
                "vendor_candidates": Counter(),
                "hostname": "",
                "device_make": "",
                "device_model": "",
                "device_db_source": "",
                "fingerprint": [],
                "dhcp": {},
                "packets": 0,
                "bytes": 0,
                "protocols": Counter(),
                "ports": Counter(),
                "dns": Counter(),
                "services": Counter(),
                "evidence": [],
                "timestamps": [],
                "classification": "Unknown",
                "score": 0,
                "confidence": "LOW",
            }

        return self.result["hosts"][ip]

    # --------------------------------------------------------
    # Add evidence
    # --------------------------------------------------------

    def add_evidence(
        self,
        ip,
        category,
        description,
        weight=0,
        severity="INFO"
    ):

        host = self.ensure_host(ip)

        if host is not None:

            item = {
                "ip": ip,
                "category": category,
                "description": description,
                "weight": weight,
                "severity": severity,
            }

            host["evidence"].append(item)

            self.result["evidence"].append(item)

    # --------------------------------------------------------
    # Packet IPs
    # --------------------------------------------------------

    def get_ips(self, packet):

        src = None
        dst = None

        if packet.haslayer(IP):

            src = packet[IP].src
            dst = packet[IP].dst

        elif packet.haslayer(IPv6):

            src = packet[IPv6].src
            dst = packet[IPv6].dst

        return src, dst

    # --------------------------------------------------------
    # Fingerprint helpers
    # --------------------------------------------------------

    def identify_vendor_from_text(self, *values):
        text = fingerprint_tokens(*values)
        if not text:
            return ""
        for token, vendor in VENDOR_FINGERPRINTS.items():
            if token in text:
                return vendor
        return ""

    def identify_device_from_text(self, *values):
        text = fingerprint_tokens(*values)
        if not text:
            return ""
        for token, device in DEVICE_FINGERPRINTS.items():
            if token in text:
                return device
        return ""

    def add_vendor_candidate(self, ip, vendor, weight=1, source="Fingerprint", detail=""):
        if not ip or not vendor:
            return
        host = self.ensure_host(ip)
        host["vendor_candidates"][vendor] += max(1, int(weight))
        current = host.get("vendor") or ""
        best = host["vendor_candidates"].most_common(1)
        if best and (not current or current == "Unknown"):
            host["vendor"] = best[0][0]
        if detail:
            host["fingerprint"].append(detail)

    def add_device_fingerprint(self, ip, device, detail, weight=8, category="Fingerprint"):
        if not ip or not device:
            return
        host = self.ensure_host(ip)
        host["fingerprint"].append(detail)
        self.add_evidence(ip, category, detail, weight, "MEDIUM")
        
    def lookup_vendor(self, mac):

        oui = get_oui(mac)

        if not oui:
            return ""

        # ------------------------------------------------------------
        # Normalize MAC/OUI
        # ------------------------------------------------------------
        normalized_oui = re.sub(
            r"[^0-9A-Fa-f]",
            "",
            oui
        ).upper()[:6]

        if len(normalized_oui) != 6:
            return ""

        # ------------------------------------------------------------
        # PRIORITY 1:
        # External vendor database
        # ------------------------------------------------------------
        external_vendor = self.external_oui.get(normalized_oui)

        if external_vendor:
            return external_vendor

        # ------------------------------------------------------------
        # PRIORITY 2:
        # Built-in vendor database
        # ------------------------------------------------------------
        builtin_vendor = NORMALIZED_OUI.get(normalized_oui)

        if builtin_vendor:
            return builtin_vendor

        return ""

    def lookup_device_from_csv(self, mac):
        """Return Make/Model from the configured MAC CSV."""
        normalized = normalize_mac(mac)

        if not normalized:
            return None

        exact = self.device_database.get("exact", {})
        oui_db = self.device_database.get("oui", {})

        record = exact.get(normalized)

        if record:
            return dict(
                record,
                source="MAC CSV (exact)"
            )

        clean = re.sub(
            r"[^0-9A-Fa-f]",
            "",
            normalized
        ).upper()

        if len(clean) >= 6:
            record = oui_db.get(clean[:6])
            if record:
                return dict(
                    record,
                    source="MAC CSV (OUI)"
                )

        return None

    def apply_device_csv(self, ip, mac):
        """
        Apply CSV Make/Model information to a host.
        CSV data is authoritative for Make/Model fields.
        """
        if not ip or not mac:
            return

        record = self.lookup_device_from_csv(mac)

        if not record:
            return

        host = self.ensure_host(ip)

        make = safe_text(
            record.get("make", "")
        ).strip()

        model = safe_text(
            record.get("model", "")
        ).strip()

        if make:
            host["device_make"] = make
            # Use CSV make as vendor only when protocol/OUI
            # fingerprinting has not already produced a stronger value.
            if not host.get("vendor"):
                host["vendor"] = make

        if model:
            host["device_model"] = model

        host["device_db_source"] = record.get(
            "source",
            "MAC CSV"
        )

        display_name = " ".join(
            part for part in (make, model)
            if part
        ) or "Device"

        self.add_evidence(
            ip,
            "MAC CSV",
            (
                f"MAC CSV match: {mac} → "
                f"{display_name} "
                f"({record.get('source', 'MAC CSV')})"
            ),
            30,
            "HIGH",
        )

    # --------------------------------------------------------
    # MAC analysis
    # --------------------------------------------------------

    def process_mac(self, packet, src_ip):

        if not packet.haslayer(Ether):
            return

        eth = packet[Ether]
        src_mac = normalize_mac(eth.src)
        dst_mac = normalize_mac(eth.dst)

        if src_ip and src_mac:
            host = self.ensure_host(src_ip)
            if src_mac not in host["macs"]:
                host["macs"].append(src_mac)
            if not host["mac"]:
                host["mac"] = src_mac

            self.apply_device_csv(
                src_ip,
                src_mac
            )

            vendor = self.lookup_vendor(src_mac)
            if vendor:
                host["vendor"] = vendor
                self.add_vendor_candidate(src_ip, vendor, 10, "MAC/OUI", f"MAC/OUI: {vendor} ({src_mac})")
                if self.settings["analysis"]["oui_analysis"]:
                    self.add_evidence(src_ip, "MAC/OUI", f"MAC vendor identified as {vendor} ({src_mac})", 25, "HIGH")

            if self.settings.get("fingerprinting", {}).get("use_randomized_mac_detection", True):
                try:
                    first = int(src_mac.split(":")[0], 16)
                    if first & 0x02:
                        self.add_evidence(src_ip, "MAC", "Locally administered/randomized MAC bit is set; OUI may not identify the physical vendor", 3, "INFO")
                except Exception:
                    pass

        # Destination MAC is useful in captures where the device's first
        # visible packet is a reply and therefore appears only as a destination.
        if dst_mac and src_ip and dst_mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            vendor = self.lookup_vendor(dst_mac)
            if vendor and src_ip not in self.result["hosts"]:
                self.add_vendor_candidate(src_ip, vendor, 1, "MAC/OUI", f"Destination MAC vendor hint: {vendor}")

    # --------------------------------------------------------
    # ARP
    # --------------------------------------------------------

    def process_arp(self, packet):

        if not self.settings["analysis"]["arp_analysis"]:
            return

        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]

        ip = safe_text(arp.psrc)
        mac = normalize_mac(arp.hwsrc)

        if not ip:
            return

        host = self.ensure_host(ip)

        if mac:
            host["mac"] = mac

            self.apply_device_csv(
                ip,
                mac
            )

            vendor = self.lookup_vendor(mac)

            if vendor:
                host["vendor"] = vendor
                self.add_vendor_candidate(ip, vendor, 12, "ARP/OUI", f"ARP MAC vendor: {vendor} ({mac})")

        host["services"]["ARP"] += 1

        self.add_evidence(
            ip,
            "ARP",
            "ARP activity observed",
            2,
            "INFO",
        )

    # --------------------------------------------------------
    # DHCP
    # --------------------------------------------------------

    def process_dhcp(self, packet, src_ip):

        if not self.settings["analysis"]["dhcp_analysis"]:
            return

        if not packet.haslayer(DHCP):
            return

        host = self.ensure_host(src_ip)

        options = packet[DHCP].options

        for option in options:

            if not isinstance(option, tuple):
                continue

            key = option[0]
            value = option[1]

            if key == "hostname":

                hostname = safe_text(value)

                host["hostname"] = hostname

                self.add_evidence(
                    src_ip,
                    "DHCP",
                    f"DHCP hostname: {hostname}",
                    8,
                    "MEDIUM",
                )

            elif key in ("vendor_class_id", "vendor_class_data"):

                value = safe_text(value)
                host["dhcp"][key] = value

                vendor = self.identify_vendor_from_text(value)
                device = self.identify_device_from_text(value)
                if vendor:
                    self.add_vendor_candidate(src_ip, vendor, 18, "DHCP", f"DHCP vendor fingerprint: {vendor} ({value})")
                if device:
                    host["device_model"] = device
                    self.add_device_fingerprint(src_ip, device, f"DHCP device fingerprint: {device} ({value})", 12, "DHCP")

                self.add_evidence(
                    src_ip,
                    "DHCP",
                    f"DHCP vendor class: {value}",
                    12,
                    "MEDIUM",
                )

            elif key == "param_req_list":

                host["dhcp"]["parameter_request_list"] = safe_text(
                    value
                )

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    def process_dns(self, packet, src_ip):

        if not self.settings["analysis"]["dns_analysis"]:
            return

        if not packet.haslayer(DNS):
            return

        names = extract_dns_names(packet)

        host = self.ensure_host(src_ip)
        host["services"]["DNS"] += 1

        for name in names:

            host["dns"][name] += 1

            self.result["dns_names"][name] += 1

            lowered = name.lower()

            vendor_keywords = (
                "tuya",
                "hik-connect",
                "hikvision",
                "ezviz",
                "ring",
                "nest",
                "googleapis",
                "amazonaws",
                "amazon",
                "espressif",
                "mqtt",
                "homekit",
                "mi.com",
                "xiaomi",
                "tplink",
                "tp-link",
                "dyndns",
                "no-ip",
                "arlo",
                "eufy",
                "wyze",
                "samsung",
                "sonos",
                "chromecast",
            )

            matched = None

            for keyword in vendor_keywords:

                if keyword in lowered:

                    matched = keyword
                    break

            if matched:

                vendor = self.identify_vendor_from_text(name)
                device = self.identify_device_from_text(name)
                if vendor and self.settings.get("fingerprinting", {}).get("use_dns_vendor_hints", True):
                    self.add_vendor_candidate(src_ip, vendor, 10, "DNS", f"DNS vendor hint: {vendor} ({name})")
                if device:
                    host["device_model"] = device
                    self.add_device_fingerprint(src_ip, device, f"DNS device fingerprint: {device} ({name})", 8, "DNS")

                self.add_evidence(
                    src_ip,
                    "DNS",
                    f"Device/vendor-related DNS name: {name}",
                    12,
                    "MEDIUM",
                )

    # --------------------------------------------------------
    # mDNS
    # --------------------------------------------------------

    def process_mdns(self, packet, src_ip, dst_ip):

        if not self.settings["analysis"]["mdns_analysis"]:
            return

        if not packet.haslayer(UDP):
            return

        udp = packet[UDP]

        if not (
            udp.sport == 5353
            or udp.dport == 5353
        ):
            return

        host = self.ensure_host(src_ip)

        host["services"]["mDNS"] += 1

        payload = b""

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)

        text = extract_ascii(payload)

        indicators = [
            "_homekit",
            "_hap._tcp",
            "_airplay",
            "_raop",
            "_googlecast",
            "_ipp",
            "_printer",
            "_http",
            "_https",
            "_spotify-connect",
            "_sonos",
            "_mqtt",
            "_camera",
        ]

        for indicator in indicators:

            if indicator.lower() in text.lower():
                vendor = self.identify_vendor_from_text(text)
                device = self.identify_device_from_text(text)
                if vendor:
                    self.add_vendor_candidate(src_ip, vendor, 16, "mDNS", f"mDNS vendor fingerprint: {vendor}")
                if device:
                    host["device_model"] = device
                    self.add_device_fingerprint(src_ip, device, f"mDNS device fingerprint: {device}", 12, "mDNS")

                self.add_evidence(
                    src_ip,
                    "mDNS",
                    f"mDNS service indicator: {indicator}",
                    15,
                    "HIGH",
                )

                break

        if "._tcp" in text or "._udp" in text:

            self.add_evidence(
                src_ip,
                "mDNS",
                "mDNS service advertisement observed",
                8,
                "MEDIUM",
            )

    # --------------------------------------------------------
    # SSDP
    # --------------------------------------------------------

    def process_ssdp(self, packet, src_ip, dst_ip):

        if not self.settings["analysis"]["ssdp_analysis"]:
            return

        if not packet.haslayer(UDP):
            return

        udp = packet[UDP]

        if not (
            udp.sport == 1900
            or udp.dport == 1900
        ):
            return

        host = self.ensure_host(src_ip)

        host["services"]["SSDP"] += 1

        payload = b""

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)

        text = extract_ascii(payload)

        interesting = (
            "upnp",
            "urn:",
            "mediarenderer",
            "mediaserver",
            "internetgatewaydevice",
            "printer",
            "camera",
            "dlink",
            "roku",
            "sonos",
            "wemo",
        )

        matched = []

        lower = text.lower()

        for item in interesting:

            if item in lower:
                matched.append(item)

        if matched:
            vendor = self.identify_vendor_from_text(text)
            device = self.identify_device_from_text(text)
            if vendor:
                self.add_vendor_candidate(src_ip, vendor, 18, "SSDP", f"SSDP vendor fingerprint: {vendor}")
            if device:
                host["device_model"] = device
                self.add_device_fingerprint(src_ip, device, f"SSDP device fingerprint: {device}", 15, "SSDP/UPnP")

            self.add_evidence(
                src_ip,
                "SSDP/UPnP",
                "SSDP/UPnP indicator: "
                + ", ".join(matched[:5]),
                20,
                "HIGH",
            )

        else:

            self.add_evidence(
                src_ip,
                "SSDP",
                "SSDP traffic observed",
                8,
                "MEDIUM",
            )

    # --------------------------------------------------------
    # TCP services
    # --------------------------------------------------------

    def process_tcp(
        self,
        packet,
        src_ip,
        dst_ip,
    ):

        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]

        sport = int(tcp.sport)
        dport = int(tcp.dport)

        payload = b""

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)

        # ----------------------------------------------------
        # source / destination hosts
        # ----------------------------------------------------

        src_host = self.ensure_host(src_ip)
        dst_host = self.ensure_host(dst_ip)

        src_host["ports"][sport] += 1
        dst_host["ports"][dport] += 1

        # ----------------------------------------------------
        # RTSP
        # ----------------------------------------------------

        if (
            sport in (554, 8554)
            or dport in (554, 8554)
        ):

            if self.settings["analysis"]["rtsp_detection"]:

                src_host["services"]["RTSP"] += 1

                self.add_evidence(
                    src_ip,
                    "RTSP",
                    f"RTSP-related traffic on TCP/{sport if sport in (554, 8554) else dport}",
                    20,
                    "HIGH",
                )

        # ----------------------------------------------------
        # MQTT
        # ----------------------------------------------------

        if (
            sport in (1883, 8883)
            or dport in (1883, 8883)
        ):

            if self.settings["analysis"]["mqtt_detection"]:

                src_host["services"]["MQTT"] += 1

                self.add_evidence(
                    src_ip,
                    "MQTT",
                    f"MQTT-related traffic on TCP/{sport if sport in (1883, 8883) else dport}",
                    20,
                    "HIGH",
                )

        # ----------------------------------------------------
        # HTTP
        # ----------------------------------------------------

        if (
            sport in (80, 8080, 8000, 8008, 8088)
            or dport in (80, 8080, 8000, 8008, 8088)
        ):

            self.result["services"]["HTTP"] += 1

            if self.settings["analysis"]["http_fingerprinting"]:

                if looks_like_http(payload):

                    headers = parse_http_headers(payload)

                    user_agent = headers.get(
                        "user-agent",
                        ""
                    )

                    server = headers.get(
                        "server",
                        ""
                    )

                    if user_agent:
                        vendor = self.identify_vendor_from_text(user_agent)
                        device = self.identify_device_from_text(user_agent)
                        if vendor:
                            self.add_vendor_candidate(src_ip, vendor, 10, "HTTP", f"HTTP User-Agent vendor fingerprint: {vendor} ({user_agent[:120]})")
                        if device:
                            src_host["device_model"] = device
                            self.add_device_fingerprint(src_ip, device, f"HTTP User-Agent device fingerprint: {device}", 8, "HTTP")

                        self.add_evidence(
                            src_ip,
                            "HTTP",
                            f"HTTP User-Agent: {user_agent[:120]}",
                            8,
                            "MEDIUM",
                        )

                    http_host = headers.get("host", "")
                    if http_host:
                        vendor = self.identify_vendor_from_text(http_host)
                        device = self.identify_device_from_text(http_host)
                        if vendor:
                            self.add_vendor_candidate(src_ip, vendor, 10, "HTTP", f"HTTP Host vendor fingerprint: {vendor} ({http_host})")
                        if device:
                            src_host["device_model"] = device
                            self.add_device_fingerprint(src_ip, device, f"HTTP Host device fingerprint: {device}", 8, "HTTP")
                        self.add_evidence(src_ip, "HTTP", f"HTTP Host: {http_host[:120]}", 5, "INFO")

                    if server:
                        vendor = self.identify_vendor_from_text(server)
                        device = self.identify_device_from_text(server)
                        if vendor:
                            self.add_vendor_candidate(src_ip, vendor, 12, "HTTP", f"HTTP Server vendor fingerprint: {vendor} ({server})")
                        if device:
                            src_host["device_model"] = device
                            self.add_device_fingerprint(src_ip, device, f"HTTP Server device fingerprint: {device}", 10, "HTTP")

                        self.add_evidence(
                            src_ip,
                            "HTTP",
                            f"HTTP Server: {server[:120]}",
                            8,
                            "MEDIUM",
                        )

        # ----------------------------------------------------
        # Common IoT web ports
        # ----------------------------------------------------

        iot_ports = {
            81,
            443,
            5000,
            5001,
            7547,
            8000,
            8001,
            8008,
            8080,
            8081,
            8088,
            8443,
            8888,
            9000,
            9001,
        }

        if sport in iot_ports or dport in iot_ports:

            self.add_evidence(
                src_ip,
                "Service",
                f"Embedded/web service port observed: "
                f"{sport if sport in iot_ports else dport}",
                4,
                "INFO",
            )

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    def process_tls(
        self,
        packet,
        src_ip,
        dst_ip,
    ):

        if not self.settings["analysis"]["tls_analysis"]:
            return

        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]

        if tcp.dport != 443 and tcp.sport != 443:
            return

        if not packet.haslayer(Raw):
            return

        payload = bytes(packet[Raw].load)

        if len(payload) < 5:
            return

        # TLS handshake / record
        if payload[0] not in (
            0x16,
            0x17,
            0x14,
            0x15,
        ):
            return

        self.ensure_host(src_ip)["services"]["TLS"] += 1

        # Lightweight SNI extraction.
        # We intentionally do not decrypt TLS.

        sni = self.extract_tls_sni(payload)

        if sni:
            vendor = self.identify_vendor_from_text(sni)
            device = self.identify_device_from_text(sni)
            if vendor:
                self.add_vendor_candidate(src_ip, vendor, 12, "TLS/SNI", f"TLS SNI vendor fingerprint: {vendor} ({sni})")
            if device:
                self.ensure_host(src_ip)["device_model"] = device
                self.add_device_fingerprint(src_ip, device, f"TLS SNI device fingerprint: {device}", 8, "TLS/SNI")

            self.add_evidence(
                src_ip,
                "TLS/SNI",
                f"TLS SNI: {sni}",
                8,
                "MEDIUM",
            )

    # --------------------------------------------------------
    # TLS SNI
    # --------------------------------------------------------

    def extract_tls_sni(self, payload):

        try:

            text = payload.decode(
                "latin-1",
                errors="ignore"
            )

            # Hostname-like strings.
            candidates = re.findall(
                r"([A-Za-z0-9][A-Za-z0-9._-]{2,253}\.[A-Za-z]{2,})",
                text
            )

            for candidate in candidates:

                lower = candidate.lower()

                if any(
                    c in lower
                    for c in (
                        "amazonaws",
                        "google",
                        "microsoft",
                        "tuya",
                        "hik",
                        "ezviz",
                        "xiaomi",
                        "tplink",
                        "samsung",
                        "ring",
                        "arlo",
                        "wyze",
                        "eufy",
                    )
                ):
                    return candidate

        except Exception:
            pass

        return ""

    # --------------------------------------------------------
    # UDP
    # --------------------------------------------------------

    def process_udp(
        self,
        packet,
        src_ip,
        dst_ip,
    ):

        if not packet.haslayer(UDP):
            return

        udp = packet[UDP]

        sport = int(udp.sport)
        dport = int(udp.dport)

        src_host = self.ensure_host(src_ip)
        dst_host = self.ensure_host(dst_ip)

        src_host["ports"][sport] += 1
        dst_host["ports"][dport] += 1

        # CoAP
        if (
            sport in (5683, 5684)
            or dport in (5683, 5684)
        ):

            src_host["services"]["CoAP"] += 1

            self.add_evidence(
                src_ip,
                "CoAP",
                f"CoAP traffic on UDP/{sport if sport in (5683, 5684) else dport}",
                20,
                "HIGH",
            )

    # --------------------------------------------------------
    # Behaviour
    # --------------------------------------------------------

    def process_behaviour(
        self,
        src_ip,
        timestamp,
    ):

        if not self.settings["analysis"]["traffic_behaviour"]:
            return

        if not src_ip:
            return

        values = self._last_timestamps[src_ip]

        values.append(float(timestamp))

        # Keep manageable.
        if len(values) > 100:
            del values[:-100]

    # --------------------------------------------------------
    # Classify
    # --------------------------------------------------------

    def classify_hosts(self):

        threshold = int(
            self.settings["detection"]["iot_threshold"]
        )

        high_threshold = int(
            self.settings["detection"]["high_confidence"]
        )

        for ip, host in self.result["hosts"].items():

            score = 0
            reasons = []

            # ------------------------------------------------
            # Evidence scoring
            # ------------------------------------------------

            evidence_scores = defaultdict(int)

            for item in host["evidence"]:

                category = item["category"]

                evidence_scores[category] += int(
                    item.get("weight", 0)
                )

            # ------------------------------------------------
            # Cap individual categories.
            # ------------------------------------------------

            for category, value in evidence_scores.items():

                contribution = min(value, 30)

                score += contribution

            # ------------------------------------------------
            # Hostname indicators
            # ------------------------------------------------

            hostname = host["hostname"].lower()

            hostname_keywords = {
                "camera": 15,
                "cam": 15,
                "ipc": 15,
                "nvr": 15,
                "dvr": 15,
                "sensor": 12,
                "smart": 8,
                "plug": 12,
                "switch": 10,
                "bulb": 12,
                "light": 10,
                "tv": 10,
                "printer": 10,
                "speaker": 10,
                "doorbell": 15,
                "thermostat": 12,
                "esp": 12,
                "tuya": 15,
            }

            for keyword, weight in hostname_keywords.items():

                if keyword in hostname:

                    score += weight

                    reasons.append(
                        f"Hostname indicator: {keyword}"
                    )

                    break

            # ------------------------------------------------
            # Correlated vendor/device fingerprints
            # ------------------------------------------------

            vendor_candidates = host.get("vendor_candidates", Counter())
            if vendor_candidates:
                best_vendor, best_weight = vendor_candidates.most_common(1)[0]
                if not host.get("vendor") or host.get("vendor") == "Unknown":
                    host["vendor"] = best_vendor
                score += min(20, max(4, best_weight // 3))
                reasons.append(f"Fingerprint vendor: {best_vendor}")

            vendor = host["vendor"]

            embedded_vendors = {
                "Hikvision", "Dahua", "Espressif", "Tuya", "Ubiquiti",
                "Nest", "Google/Nest", "Raspberry Pi", "Xiaomi", "TP-Link",
                "Ring", "Arlo", "Eufy", "Wyze", "Sonos", "Amazon",
            }

            if vendor in embedded_vendors:

                score += 15

                reasons.append(
                    f"Embedded/IoT-associated vendor: {vendor}"
                )

            # ------------------------------------------------
            # Service combinations
            # ------------------------------------------------

            services = set(
                host["services"].keys()
            )

            if (
                "RTSP" in services
                and (
                    "SSDP" in services
                    or "mDNS" in services
                )
            ):

                score += 15

                reasons.append(
                    "RTSP combined with discovery protocol"
                )

            if (
                "MQTT" in services
                and (
                    "DNS" in host["protocols"]
                    or "TLS" in host["services"]
                )
            ):

                score += 10

                reasons.append(
                    "MQTT combined with application traffic"
                )

            if "CoAP" in services:

                score += 10

                reasons.append(
                    "CoAP protocol observed"
                )

            # ------------------------------------------------
            # Clamp
            # ------------------------------------------------

            score = min(100, score)

            # ------------------------------------------------
            # Classification
            # ------------------------------------------------

            classification = "Unknown"

            if score >= threshold:

                if host.get("device_model"):
                    classification = host["device_model"]
                elif "RTSP" in services:
                    classification = "IP Camera"

                elif "MQTT" in services:
                    classification = "IoT / MQTT Device"

                elif (
                    "SSDP" in services
                    and "mDNS" in services
                ):
                    classification = "Smart Home Device"

                elif vendor == "Espressif":
                    classification = "Embedded / IoT Device"

                elif vendor == "Tuya":
                    classification = "Smart Home Device"

                elif "CoAP" in services:
                    classification = "IoT Device"

                elif "SSDP" in services:
                    classification = "UPnP / IoT Device"

                elif "mDNS" in services:
                    classification = "Networked Smart Device"

                else:
                    classification = "Likely IoT Device"

            if score >= high_threshold:
                confidence = "HIGH"

            elif score >= threshold:
                confidence = "MEDIUM"

            else:
                confidence = "LOW"

            # ------------------------------------------------
            # Add evidence
            # ------------------------------------------------

            if hostname:
                reasons.append(
                    f"Hostname: {host['hostname']}"
                )

            if vendor:
                reasons.append(
                    f"Vendor: {vendor}"
                )

            if host.get("device_make"):
                reasons.append(
                    f"CSV Make: {host['device_make']}"
                )

            if host.get("device_model"):
                reasons.append(
                    f"CSV Model: {host['device_model']}"
                )

            if host.get("device_db_source"):
                reasons.append(
                    f"Device database: {host['device_db_source']}"
                )

            for service in sorted(services):
                reasons.append(
                    f"Service: {service}"
                )

            host["score"] = score
            host["classification"] = classification
            host["confidence"] = confidence

            host["classification_reasons"] = list(
                dict.fromkeys(reasons)
            )

            if score >= threshold:

                self.result["iot_devices"][ip] = host

                self.result["evidence"].append({
                    "ip": ip,
                    "category": "CLASSIFICATION",
                    "description": (
                        f"{classification} "
                        f"with IoT confidence score {score}/100"
                    ),
                    "weight": score,
                    "severity": confidence,
                })

    # --------------------------------------------------------
    # Finalize protocol counters
    # --------------------------------------------------------

    def finalize(self):

        for ip, host in self.result["hosts"].items():

            for service in host["services"]:

                self.result["services"][service] += (
                    host["services"][service]
                )

            for protocol in host["protocols"]:

                self.result["protocols"][protocol] += (
                    host["protocols"][protocol]
                )

            # Behaviour evidence
            timestamps = host["timestamps"]

            if len(timestamps) >= 10:

                timestamps = sorted(timestamps)

                intervals = []

                for i in range(
                    1,
                    min(len(timestamps), 50)
                ):

                    delta = (
                        timestamps[i]
                        - timestamps[i - 1]
                    )

                    if delta > 0:
                        intervals.append(delta)

                if intervals:

                    avg = sum(intervals) / len(intervals)

                    if 5 <= avg <= 3600:

                        self.add_evidence(
                            ip,
                            "Traffic Behaviour",
                            (
                                "Repeated periodic traffic observed; "
                                f"average interval ~{avg:.1f}s"
                            ),
                            5,
                            "MEDIUM",
                        )

    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    def analyze(self, filepath):

        self.cancel_requested = False
        self.reset()

        start = time.time()

        self.result["metadata"]["file"] = filepath
        self.result["metadata"]["started"] = (
            datetime.now().isoformat(
                timespec="seconds"
            )
        )

        self.emit(
            "status",
            "Calculating SHA-256..."
        )

        digest = sha256_file(
            filepath,
            lambda p: self.emit(
                "hash_progress",
                p
            )
        )

        self.result["metadata"]["sha256"] = digest

        self.emit(
            "status",
            "Reading PCAP..."
        )

        packet_count = 0
        total_bytes = 0

        try:

            reader = PcapReader(filepath)

            for packet in reader:

                if self.cancel_requested:

                    reader.close()

                    self.emit(
                        "cancelled",
                        None
                    )

                    return None

                packet_count += 1

                try:
                    packet_len = len(packet)
                except Exception:
                    packet_len = 0

                total_bytes += packet_len

                timestamp = getattr(
                    packet,
                    "time",
                    time.time()
                )

                src_ip, dst_ip = self.get_ips(packet)

                # ------------------------------------------------
                # Source host
                # ------------------------------------------------

                if src_ip:

                    src_host = self.ensure_host(
                        src_ip
                    )

                    src_host["packets"] += 1
                    src_host["bytes"] += packet_len
                    src_host["timestamps"].append(
                        float(timestamp)
                    )

                    self.process_behaviour(
                        src_ip,
                        timestamp
                    )

                # ------------------------------------------------
                # Destination host
                # ------------------------------------------------

                if dst_ip:

                    dst_host = self.ensure_host(
                        dst_ip
                    )

                    dst_host["packets"] += 1
                    dst_host["bytes"] += packet_len

                # ------------------------------------------------
                # Ethernet / OUI
                # ------------------------------------------------

                if src_ip:
                    self.process_mac(
                        packet,
                        src_ip
                    )

                # ------------------------------------------------
                # ARP
                # ------------------------------------------------

                self.process_arp(packet)

                # ------------------------------------------------
                # DHCP
                # ------------------------------------------------

                if src_ip:
                    self.process_dhcp(
                        packet,
                        src_ip
                    )

                # ------------------------------------------------
                # DNS
                # ------------------------------------------------

                if src_ip:
                    self.process_dns(
                        packet,
                        src_ip
                    )

                # ------------------------------------------------
                # Protocol identification
                # ------------------------------------------------

                protocol = "Other"

                if packet.haslayer(TCP):
                    protocol = "TCP"

                    self.process_tcp(
                        packet,
                        src_ip,
                        dst_ip
                    )

                    self.process_tls(
                        packet,
                        src_ip,
                        dst_ip
                    )

                elif packet.haslayer(UDP):
                    protocol = "UDP"

                    self.process_udp(
                        packet,
                        src_ip,
                        dst_ip
                    )

                elif packet.haslayer(ARP):
                    protocol = "ARP"

                elif packet.haslayer(DNS):
                    protocol = "DNS"

                elif packet.haslayer(ICMP):
                    protocol = "ICMP"

                self.result["protocols"][protocol] += 1

                if src_ip:

                    self.ensure_host(
                        src_ip
                    )["protocols"][protocol] += 1

                # ------------------------------------------------
                # Special protocols
                # ------------------------------------------------

                self.process_mdns(
                    packet,
                    src_ip,
                    dst_ip
                )

                self.process_ssdp(
                    packet,
                    src_ip,
                    dst_ip
                )

                # ------------------------------------------------
                # Timeline
                # ------------------------------------------------

                if (
                    src_ip
                    and dst_ip
                    and len(self.result["timeline"]) < 10000
                ):

                    src_port = ""
                    dst_port = ""

                    if packet.haslayer(TCP):

                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport

                    elif packet.haslayer(UDP):

                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport

                    self.result["timeline"].append({
                        "timestamp": float(timestamp),
                        "time": format_timestamp(timestamp),
                        "source": src_ip,
                        "source_port": src_port,
                        "destination": dst_ip,
                        "destination_port": dst_port,
                        "protocol": protocol,
                    })

                # ------------------------------------------------
                # Progress
                # ------------------------------------------------

                if packet_count % 5000 == 0:

                    self.emit(
                        "progress",
                        {
                            "packets": packet_count,
                            "bytes": total_bytes,
                        }
                    )

            reader.close()

        except Exception as exc:

            self.emit(
                "error",
                str(exc)
            )

            return None

        self.result["packets"] = packet_count
        self.result["bytes"] = total_bytes

        self.emit(
            "status",
            "Finalizing device fingerprints..."
        )

        self.finalize()

        self.emit(
            "status",
            "Classifying IoT devices..."
        )

        self.classify_hosts()

        completed = time.time()

        self.result["metadata"]["completed"] = (
            datetime.now().isoformat(
                timespec="seconds"
            )
        )

        self.result["metadata"]["duration"] = (
            completed - start
        )

        self.emit(
            "progress",
            {
                "packets": packet_count,
                "bytes": total_bytes,
            }
        )

        self.emit(
            "complete",
            self.result
        )

        return self.result


# ============================================================
# MAIN GUI
# ============================================================

class IoTPCAPAnalyzerApp(tk.Tk):

    def __init__(self):

        super().__init__()

        self.title(
            f"{APP_NAME} | CyberX"
        )

        self.geometry(
            "1480x900"
        )

        self.minsize(
            1200,
            720
        )

        self.configure(
            bg=COLORS["bg"]
        )

        # ----------------------------------------------------
        # Persistent application state
        # ----------------------------------------------------

        self.settings = self.load_settings()

        self.current_file = None

        self.analysis_result = None

        self.analysis_thread = None

        self.analysis_engine = None

        self.event_queue = queue.Queue()

        self.page_frames = {}

        self.nav_buttons = {}

        self.metric_labels = {}

        self.last_selected_iot = None

        self.protocol_tree = None
        self.host_tree = None
        self.iot_tree = None
        self.evidence_tree = None
        self.timeline_tree = None

        self._configure_styles()

        self._build_shell()

        self._build_pages()

        last_pcap = self.settings.get("paths", {}).get("last_pcap", "")
        if (
            self.settings.get("interface", {}).get("remember_last_pcap", True)
            and last_pcap
            and os.path.isfile(last_pcap)
        ):
            self.current_file = last_pcap

        self.show_page("Overview")
        if self.current_file:
            self.file_label.configure(text=os.path.basename(self.current_file))
            self.overview_file_label.configure(text=self.current_file)

        self.after(
            100,
            self.process_events
        )

        self.protocol(
            "WM_DELETE_WINDOW",
            self.on_close
        )

    # ========================================================
    # SETTINGS
    # ========================================================

    def load_settings(self):

        if not os.path.exists(
            SETTINGS_FILE
        ):
            return json.loads(
                json.dumps(DEFAULT_SETTINGS)
            )

        try:

            with open(
                SETTINGS_FILE,
                "r",
                encoding="utf-8"
            ) as handle:

                data = json.load(handle)

            merged = json.loads(
                json.dumps(DEFAULT_SETTINGS)
            )

            self.deep_merge(
                merged,
                data
            )

            return merged

        except Exception:

            return json.loads(
                json.dumps(DEFAULT_SETTINGS)
            )

    def deep_merge(self, base, update):

        for key, value in update.items():

            if (
                key in base
                and isinstance(base[key], dict)
                and isinstance(value, dict)
            ):

                self.deep_merge(
                    base[key],
                    value
                )

            else:

                base[key] = value

    def save_settings(self):

        try:

            with open(
                SETTINGS_FILE,
                "w",
                encoding="utf-8"
            ) as handle:

                json.dump(
                    self.settings,
                    handle,
                    indent=4
                )

            self.set_status(
                "Settings saved"
            )

            return True

        except Exception as exc:

            messagebox.showerror(
                "Settings Error",
                f"Could not save settings:\n\n{exc}"
            )

            return False

    # ========================================================
    # STYLE
    # ========================================================

    def _configure_styles(self):

        style = ttk.Style(self)

        try:
            style.theme_use(
                "clam"
            )
        except Exception:
            pass

        style.configure(
            "Treeview",
            background=COLORS["surface"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["surface"],
            rowheight=34,
            borderwidth=0,
            font=(
                "Segoe UI",
                9
            ),
        )

        style.configure(
            "Treeview.Heading",
            background="#E8EEF3",
            foreground=COLORS["text"],
            font=(
                "Segoe UI Semibold",
                9
            ),
            relief="flat",
            padding=(
                8,
                8
            ),
        )

        style.map(
            "Treeview",
            background=[
                (
                    "selected",
                    COLORS["accent_light"]
                )
            ],
            foreground=[
                (
                    "selected",
                    COLORS["text"]
                )
            ],
        )

        style.configure(
            "Horizontal.TProgressbar",
            troughcolor="#DCE6ED",
            background=COLORS["accent"],
            bordercolor="#DCE6ED",
            lightcolor=COLORS["accent"],
            darkcolor=COLORS["accent"],
        )

    # ========================================================
    # SHELL
    # ========================================================

    def _build_shell(self):

        self.grid_rowconfigure(
            0,
            weight=1
        )

        self.grid_columnconfigure(
            1,
            weight=1
        )

        self.build_sidebar()

        self.main = tk.Frame(
            self,
            bg=COLORS["bg"]
        )

        self.main.grid(
            row=0,
            column=1,
            sticky="nsew"
        )

        self.main.grid_rowconfigure(
            1,
            weight=1
        )

        self.main.grid_columnconfigure(
            0,
            weight=1
        )

        self.build_topbar()

        self.content = tk.Frame(
            self.main,
            bg=COLORS["bg"]
        )

        self.content.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=24,
            pady=18
        )

        self.content.grid_rowconfigure(
            0,
            weight=1
        )

        self.content.grid_columnconfigure(
            0,
            weight=1
        )

    # ========================================================
    # SIDEBAR
    # ========================================================

    def build_sidebar(self):

        self.sidebar = tk.Frame(
            self,
            bg=COLORS["sidebar"],
            width=255
        )

        self.sidebar.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        self.sidebar.grid_propagate(
            False
        )

        # ----------------------------------------------------
        # Branding
        # ----------------------------------------------------

        brand = tk.Frame(
            self.sidebar,
            bg=COLORS["sidebar"],
            height=92
        )

        brand.pack(
            fill="x"
        )

        brand.pack_propagate(
            False
        )

        tk.Label(
            brand,
            text="◈",
            bg=COLORS["sidebar"],
            fg=COLORS["accent"],
            font=(
                "Segoe UI",
                28,
                "bold"
            )
        ).place(
            x=20,
            y=17
        )

        tk.Label(
            brand,
            text="IoT ScouT",
            bg=COLORS["sidebar"],
            fg="#FFFFFF",
            font=(
                "Segoe UI Semibold",
                16
            )
        ).place(
            x=62,
            y=18
        )

        tk.Label(
            brand,
            text="IoT Discovery",
            bg=COLORS["sidebar"],
            fg="#8297A7",
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).place(
            x=64,
            y=45
        )

        # ----------------------------------------------------
        # Navigation
        # ----------------------------------------------------

        tk.Label(
            self.sidebar,
            text="ANALYSIS",
            bg=COLORS["sidebar"],
            fg="#71899B",
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=22,
            pady=(
                13,
                7
            )
        )

        pages = [
            ("Overview", "▦"),
            ("Hosts", "◉"),
            ("IoT Devices", "⌁"),
            ("Protocols", "◇"),
            ("Evidence", "✓"),
            ("Timeline", "◷"),
        ]

        for name, icon in pages:

            button = tk.Button(
                self.sidebar,
                text=f"  {icon}   {name}",
                anchor="w",
                bg=COLORS["sidebar"],
                fg="#B9C9D4",
                activebackground=COLORS["sidebar_hover"],
                activeforeground="#FFFFFF",
                relief="flat",
                borderwidth=0,
                cursor="hand2",
                font=(
                    "Segoe UI",
                    10
                ),
                padx=17,
                pady=10,
                command=lambda p=name: self.show_page(p)
            )

            button.pack(
                fill="x",
                padx=10,
                pady=2
            )

            self.nav_buttons[name] = button

        # ----------------------------------------------------
        # PCAP
        # ----------------------------------------------------

        tk.Label(
            self.sidebar,
            text="PCAP",
            bg=COLORS["sidebar"],
            fg="#71899B",
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w",
            padx=22,
            pady=(
                22,
                7
            )
        )

        tk.Button(
            self.sidebar,
            text="  📂   Open PCAP",
            anchor="w",
            bg=COLORS["accent"],
            fg="#FFFFFF",
            activebackground=COLORS["accent_dark"],
            activeforeground="#FFFFFF",
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            font=(
                "Segoe UI Semibold",
                10
            ),
            padx=17,
            pady=11,
            command=self.open_pcap
        ).pack(
            fill="x",
            padx=12,
            pady=2
        )

        tk.Button(
            self.sidebar,
            text="  ⚙   Settings",
            anchor="w",
            bg=COLORS["sidebar"],
            fg="#B9C9D4",
            activebackground=COLORS["sidebar_hover"],
            activeforeground="#FFFFFF",
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            font=(
                "Segoe UI",
                10
            ),
            padx=17,
            pady=10,
            command=lambda: self.show_page(
                "Settings"
            )
        ).pack(
            fill="x",
            padx=10,
            pady=2
        )

        # ----------------------------------------------------
        # Bottom
        # ----------------------------------------------------

        bottom = tk.Frame(
            self.sidebar,
            bg=COLORS["sidebar"]
        )

        bottom.pack(
            side="bottom",
            fill="x",
            padx=20,
            pady=18
        )

        tk.Label(
            bottom,
            text="CyberX",
            bg=COLORS["sidebar"],
            fg="#FFFFFF",
            font=(
                "Segoe UI Semibold",
                9
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            bottom,
            text=f"v{APP_VERSION}",
            bg=COLORS["sidebar"],
            fg="#71899B",
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w"
        )

    # ========================================================
    # TOPBAR
    # ========================================================

    def build_topbar(self):

        topbar = tk.Frame(
            self.main,
            bg="#FFFFFF",
            height=76
        )

        topbar.grid(
            row=0,
            column=0,
            sticky="ew"
        )

        topbar.grid_propagate(
            False
        )

        self.top_title = tk.Label(
            topbar,
#            text=,
            bg="#FFFFFF",
            fg=COLORS["text"],
            font=(
                "Segoe UI Semibold",
                17
            )
        )

        self.top_title.pack(
            side="left",
            padx=24,
            pady=17
        )

        right = tk.Frame(
            topbar,
            bg="#FFFFFF"
        )

        right.pack(
            side="right",
            padx=24
        )

        self.status_dot = tk.Label(
            right,
            text="●",
            bg="#FFFFFF",
            fg=COLORS["green"],
            font=(
                "Segoe UI",
                11
            )
        )

        self.status_dot.pack(
            side="left",
            padx=(0, 6)
        )

        self.status_label = tk.Label(
            right,
            text="Ready",
            bg="#FFFFFF",
            fg=COLORS["muted"],
            font=(
                "Segoe UI",
                9
            )
        )

        self.status_label.pack(
            side="left"
        )

        self.file_label = tk.Label(
            right,
            text="No PCAP loaded",
            bg="#FFFFFF",
            fg=COLORS["muted"],
            font=(
                "Segoe UI",
                9
            )
        )

        self.file_label.pack(
            side="left",
            padx=(25, 0)
        )

    # ========================================================
    # PAGES
    # ========================================================

    def _build_pages(self):

        self.page_frames = {}

        page_names = [
            "Overview",
            "Hosts",
            "IoT Devices",
            "Protocols",
            "Evidence",
            "Timeline",
            "Settings",
        ]

        builders = {
            "Overview": self.build_overview,
            "Hosts": self.build_hosts,
            "IoT Devices": self.build_iot_devices,
            "Protocols": self.build_protocols,
            "Evidence": self.build_evidence,
            "Timeline": self.build_timeline,
            "Settings": self.build_settings,
        }

        for name in page_names:

            frame = tk.Frame(
                self.content,
                bg=COLORS["bg"]
            )

            frame.grid(
                row=0,
                column=0,
                sticky="nsew"
            )

            self.page_frames[name] = frame

            builders[name](frame)

    # ========================================================
    # SHOW PAGE
    # ========================================================

    def show_page(self, page):

        frame = self.page_frames.get(
            page
        )

        if frame is None:
            return

        frame.tkraise()

        for name, button in self.nav_buttons.items():

            if name == page:

                button.configure(
                    bg=COLORS["sidebar_active"],
                    fg="#FFFFFF"
                )

            else:

                button.configure(
                    bg=COLORS["sidebar"],
                    fg="#B9C9D4"
                )

        self.refresh_page(
            page
        )

    # ========================================================
    # PAGE REFRESH
    # ========================================================

    def refresh_page(self, page):

        if page == "Overview":
            self.refresh_overview()

        elif page == "Hosts":
            self.refresh_hosts()

        elif page == "IoT Devices":
            self.refresh_iot_devices()

        elif page == "Protocols":
            self.refresh_protocols()

        elif page == "Evidence":
            self.refresh_evidence()

        elif page == "Timeline":
            self.refresh_timeline()

    # ========================================================
    # PAGE HEADER
    # ========================================================

    def page_header(
        self,
        parent,
        title,
        subtitle
    ):

        header = tk.Frame(
            parent,
            bg=COLORS["bg"]
        )

        header.pack(
            fill="x",
            pady=(0, 16)
        )

        tk.Label(
            header,
            text=title,
            bg=COLORS["bg"],
            fg=COLORS["text"],
            font=(
                "Segoe UI Semibold",
                20
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            header,
            text=subtitle,
            bg=COLORS["bg"],
            fg=COLORS["muted"],
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            anchor="w",
            pady=(3, 0)
        )

    # ========================================================
    # OVERVIEW
    # ========================================================

    def build_overview(self, parent):

        self.page_header(
            parent,
            "Overview",
            "PCAP summary and IoT detection overview"
        )

        # ----------------------------------------------------
        # File card
        # ----------------------------------------------------

        file_card = tk.Frame(
            parent,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )

        file_card.pack(
            fill="x",
            pady=(0, 14)
        )

        file_card.grid_columnconfigure(
            0,
            weight=1
        )

        info = tk.Frame(
            file_card,
            bg=COLORS["surface"]
        )

        info.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=18,
            pady=13
        )

        tk.Label(
            info,
            text="CURRENT PCAP",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=(
                "Segoe UI",
                8,
                "bold"
            )
        ).pack(
            anchor="w"
        )

        self.overview_file_label = tk.Label(
            info,
            text="No PCAP loaded",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=(
                "Segoe UI Semibold",
                10
            )
        )

        self.overview_file_label.pack(
            anchor="w",
            pady=(3, 0)
        )

        self.analyze_button = tk.Button(
            file_card,
            text="▶  Analyze PCAP",
            bg=COLORS["accent"],
            fg="#FFFFFF",
            activebackground=COLORS["accent_dark"],
            activeforeground="#FFFFFF",
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            font=(
                "Segoe UI Semibold",
                10
            ),
            padx=20,
            pady=9,
            command=self.start_analysis
        )

        self.analyze_button.grid(
            row=0,
            column=1,
            padx=18,
            pady=12
        )

        self.cancel_button = tk.Button(
            file_card,
            text="■  Cancel",
            bg=COLORS["red"],
            fg="#FFFFFF",
            activebackground="#B93D39",
            activeforeground="#FFFFFF",
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            font=(
                "Segoe UI Semibold",
                10
            ),
            padx=17,
            pady=9,
            command=self.cancel_analysis,
            state="disabled"
        )

        self.cancel_button.grid(
            row=0,
            column=2,
            padx=(
                0,
                18
            ),
            pady=12
        )

        # ----------------------------------------------------
        # Progress
        # ----------------------------------------------------

        progress_frame = tk.Frame(
            parent,
            bg=COLORS["bg"]
        )

        progress_frame.pack(
            fill="x",
            pady=(0, 14)
        )

        self.progress = ttk.Progressbar(
            progress_frame,
            mode="indeterminate",
            style="Horizontal.TProgressbar"
        )

        self.progress.pack(
            fill="x"
        )

        self.analysis_progress_label = tk.Label(
            progress_frame,
            text="Ready",
            bg=COLORS["bg"],
            fg=COLORS["muted"],
            font=(
                "Segoe UI",
                8
            )
        )

        self.analysis_progress_label.pack(
            anchor="w",
            pady=(4, 0)
        )

        # ----------------------------------------------------
        # Metrics
        # ----------------------------------------------------

        metrics = tk.Frame(
            parent,
            bg=COLORS["bg"]
        )

        metrics.pack(
            fill="x",
            pady=(0, 15)
        )

        for i in range(5):

            metrics.grid_columnconfigure(
                i,
                weight=1
            )

        data = [
            (
                "Packets",
                "0",
                COLORS["blue"],
                COLORS["blue_light"]
            ),
            (
                "Traffic",
                "0 B",
                COLORS["purple"],
                COLORS["purple_light"]
            ),
            (
                "Hosts",
                "0",
                COLORS["cyan"],
                COLORS["cyan_light"]
            ),
            (
                "IoT Devices",
                "0",
                COLORS["green"],
                COLORS["green_light"]
            ),
            (
                "Alerts",
                "0",
                COLORS["orange"],
                COLORS["orange_light"]
            ),
        ]

        for index, (
            name,
            value,
            accent,
            light
        ) in enumerate(data):

            card = tk.Frame(
                metrics,
                bg=COLORS["surface"],
                highlightbackground=COLORS["border"],
                highlightthickness=1
            )

            card.grid(
                row=0,
                column=index,
                sticky="nsew",
                padx=(
                    0 if index == 0 else 5,
                    5 if index < 4 else 0
                )
            )

            tk.Label(
                card,
                text="●",
                bg=light,
                fg=accent,
                font=(
                    "Segoe UI",
                    12
                ),
                width=3
            ).pack(
                anchor="w",
                padx=14,
                pady=(12, 5)
            )

            value_label = tk.Label(
                card,
                text=value,
                bg=COLORS["surface"],
                fg=COLORS["text"],
                font=(
                    "Segoe UI Semibold",
                    20
                )
            )

            value_label.pack(
                anchor="w",
                padx=14
            )

            tk.Label(
                card,
                text=name,
                bg=COLORS["surface"],
                fg=COLORS["muted"],
                font=(
                    "Segoe UI",
                    8
                )
            ).pack(
                anchor="w",
                padx=14,
                pady=(0, 12)
            )

            self.metric_labels[name] = value_label

        # ----------------------------------------------------
        # Lower cards
        # ----------------------------------------------------

        lower = tk.Frame(
            parent,
            bg=COLORS["bg"]
        )

        lower.pack(
            fill="both",
            expand=True
        )

        lower.grid_columnconfigure(
            0,
            weight=3
        )

        lower.grid_columnconfigure(
            1,
            weight=2
        )

        lower.grid_rowconfigure(
            0,
            weight=1
        )

        # ----------------------------------------------------
        # IoT table
        # ----------------------------------------------------

        iot_card = tk.Frame(
            lower,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )

        iot_card.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 7)
        )

        tk.Label(
            iot_card,
            text="Detected IoT Devices",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=(
                "Segoe UI Semibold",
                12
            )
        ).pack(
            anchor="w",
            padx=16,
            pady=(13, 3)
        )

        tk.Label(
            iot_card,
            text="Classification is based on correlated packet-level indicators",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w",
            padx=16,
            pady=(0, 9)
        )

        columns = (
            "ip",
            "make",
            "model",
            "classification",
            "vendor",
            "score",
            "confidence",
        )

        self.overview_iot_tree = ttk.Treeview(
            iot_card,
            columns=columns,
            show="headings"
        )

        headings = {
            "ip": "IP",
            "make": "Make",
            "model": "Model",
            "classification": "Classification",
            "vendor": "Vendor",
            "score": "Score",
            "confidence": "Confidence",
        }

        widths = {
            "ip": 120,
            "mac": 140,
            "vendor": 180,
            "make": 180,
            "device": 150,
            "model": 180,
        }

        for column in columns:

            self.overview_iot_tree.heading(
                column,
                text=headings[column]
            )

            self.overview_iot_tree.column(
                column,
                width=widths.get(column, 150)
            )

        self.overview_iot_tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        # ----------------------------------------------------
        # Summary
        # ----------------------------------------------------

        summary_card = tk.Frame(
            lower,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )

        summary_card.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(7, 0)
        )

        tk.Label(
            summary_card,
            text="Analysis Summary",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=(
                "Segoe UI Semibold",
                12
            )
        ).pack(
            anchor="w",
            padx=16,
            pady=(13, 3)
        )

        self.summary_text = tk.Text(
            summary_card,
            bg=COLORS["surface"],
            fg=COLORS["text"],
            relief="flat",
            borderwidth=0,
            font=(
                "Consolas",
                9
            ),
            wrap="word"
        )

        self.summary_text.pack(
            fill="both",
            expand=True,
            padx=16,
            pady=10
        )

        self.summary_text.insert(
            "1.0",
            "Load a PCAP to begin analysis."
        )

        self.summary_text.configure(
            state="disabled"
        )

    # ========================================================
    # HOSTS PAGE
    # ========================================================

    def build_hosts(self, parent):

        self.page_header(
            parent,
            "Hosts",
            "Network entities observed in the capture"
        )

        container = tk.Frame(
            parent,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )

        container.pack(
            fill="both",
            expand=True
        )

        columns = (
            "ip",
            "mac",
            "make",
            "model",
            "vendor",
            "hostname",
            "packets",
            "bytes",
            "classification",
            "score",
        )

        self.host_tree = ttk.Treeview(
            container,
            columns=columns,
            show="headings"
        )

        headings = {
            "ip": "IP Address",
            "mac": "MAC",
            "make": "Make",
            "model": "Model",
            "vendor": "Vendor",
            "hostname": "Hostname",
            "packets": "Packets",
            "bytes": "Bytes",
            "classification": "Classification",
            "score": "IoT Score",
        }

        widths = {
            "ip": 125,
            "mac": 150,
            "make": 125,
            "model": 170,
            "vendor": 125,
            "hostname": 160,
            "packets": 95,
            "bytes": 95,
            "classification": 160,
            "score": 85,
        }

        for column in columns:

            self.host_tree.heading(
                column,
                text=headings[column]
            )

            self.host_tree.column(
                column,
                width=widths[column],
                anchor="w"
            )

        scrollbar = ttk.Scrollbar(
            container,
            orient="vertical",
            command=self.host_tree.yview
        )

        self.host_tree.configure(
            yscrollcommand=scrollbar.set
        )

        self.host_tree.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(10, 0),
            pady=10
        )

        scrollbar.pack(
            side="right",
            fill="y",
            padx=(
                0,
                10
            ),
            pady=10
        )

    # ========================================================
    # IOT PAGE
    # ========================================================

    def build_iot_devices(self, parent):

        self.page_header(
            parent,
            "IoT Devices",
            "Devices classified using correlated network indicators"
        )

        container = tk.Frame(
            parent,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )

        container.pack(
            fill="both",
            expand=True
        )

        columns = (
            "ip",
            "make",
            "model",
            "classification",
            "vendor",
            "score",
            "confidence",
            "services",
            "hostname",
        )

        self.iot_tree = ttk.Treeview(
            container,
            columns=columns,
            show="headings"
        )

        headings = {
            "ip": "IP",
            "make": "Make",
            "model": "Model",
            "classification": "Classification",
            "vendor": "Vendor",
            "score": "Score",
            "confidence": "Confidence",
            "services": "Services",
            "hostname": "Hostname",
        }

        widths = {
            "ip": 125,
            "make": 125,
            "model": 180,
            "classification": 175,
            "vendor": 130,
            "score": 75,
            "confidence": 90,
            "services": 240,
            "hostname": 160,
        }

        for column in columns:

            self.iot_tree.heading(
                column,
                text=headings[column]
            )

            self.iot_tree.column(
                column,
                width=widths[column]
            )

        self.iot_tree.bind(
            "<<TreeviewSelect>>",
            self.on_iot_selected
        )

        self.iot_tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

    # ========================================================
    # PROTOCOLS PAGE
    # ========================================================

    def build_protocols(self, parent):

        self.page_header(
            parent,
            "Protocols & Services",
            "Observed protocol distribution and detected application services"
        )

        container = tk.Frame(
            parent,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )

        container.pack(
            fill="both",
            expand=True
        )

        columns = (
            "protocol",
            "packets",
            "percentage",
        )

        self.protocol_tree = ttk.Treeview(
            container,
            columns=columns,
            show="headings"
        )

        self.protocol_tree.heading(
            "protocol",
            text="Protocol"
        )

        self.protocol_tree.heading(
            "packets",
            text="Packets"
        )

        self.protocol_tree.heading(
            "percentage",
            text="%"
        )

        self.protocol_tree.column(
            "protocol",
            width=250
        )

        self.protocol_tree.column(
            "packets",
            width=150
        )

        self.protocol_tree.column(
            "percentage",
            width=120
        )

        self.protocol_tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

    # ========================================================
    # EVIDENCE PAGE
    # ========================================================

    def build_evidence(self, parent):

        self.page_header(
            parent,
            "Evidence",
            "Packet-derived evidence supporting IoT classification"
        )

        container = tk.Frame(
            parent,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )

        container.pack(
            fill="both",
            expand=True
        )

        columns = (
            "ip",
            "category",
            "description",
            "weight",
            "severity",
        )

        self.evidence_tree = ttk.Treeview(
            container,
            columns=columns,
            show="headings"
        )

        headings = {
            "ip": "IP",
            "category": "Evidence",
            "description": "Description",
            "weight": "Weight",
            "severity": "Severity",
        }

        widths = {
            "ip": 125,
            "category": 130,
            "description": 520,
            "weight": 75,
            "severity": 100,
        }

        for column in columns:

            self.evidence_tree.heading(
                column,
                text=headings[column]
            )

            self.evidence_tree.column(
                column,
                width=widths[column]
            )

        self.evidence_tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

    # ========================================================
    # TIMELINE PAGE
    # ========================================================

    def build_timeline(self, parent):

        self.page_header(
            parent,
            "Timeline",
            "Chronological packet activity"
        )

        container = tk.Frame(
            parent,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )

        container.pack(
            fill="both",
            expand=True
        )

        columns = (
            "time",
            "source",
            "sport",
            "destination",
            "dport",
            "protocol",
        )

        self.timeline_tree = ttk.Treeview(
            container,
            columns=columns,
            show="headings"
        )

        headings = {
            "time": "Timestamp",
            "source": "Source",
            "sport": "Src Port",
            "destination": "Destination",
            "dport": "Dst Port",
            "protocol": "Protocol",
        }

        widths = {
            "time": 175,
            "source": 130,
            "sport": 75,
            "destination": 130,
            "dport": 75,
            "protocol": 100,
        }

        for column in columns:

            self.timeline_tree.heading(
                column,
                text=headings[column]
            )

            self.timeline_tree.column(
                column,
                width=widths[column]
            )

        self.timeline_tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

    # ========================================================
    # SETTINGS PAGE
    # ========================================================

    def build_settings(self, parent):

        self.page_header(
            parent,
            "Settings",
            "Configure analysis and IoT detection behaviour"
        )

        outer = tk.Frame(
            parent,
            bg=COLORS["surface"],
            highlightbackground=COLORS["border"],
            highlightthickness=1
        )

        outer.pack(
            fill="both",
            expand=True
        )

        # ----------------------------------------------------
        # Analysis settings
        # ----------------------------------------------------

        analysis_card = tk.Frame(
            outer,
            bg=COLORS["surface"]
        )

        analysis_card.pack(
            fill="x",
            padx=25,
            pady=20
        )

        tk.Label(
            analysis_card,
            text="Analysis Modules",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=(
                "Segoe UI Semibold",
                12
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            analysis_card,
            text="Enable or disable individual packet analysis modules.",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w",
            pady=(3, 12)
        )

        settings_items = [
            (
                "oui_analysis",
                "MAC / OUI vendor analysis"
            ),
            (
                "arp_analysis",
                "ARP analysis"
            ),
            (
                "dhcp_analysis",
                "DHCP fingerprinting"
            ),
            (
                "dns_analysis",
                "DNS analysis"
            ),
            (
                "mdns_analysis",
                "mDNS / Bonjour analysis"
            ),
            (
                "ssdp_analysis",
                "SSDP / UPnP analysis"
            ),
            (
                "mqtt_detection",
                "MQTT detection"
            ),
            (
                "rtsp_detection",
                "RTSP detection"
            ),
            (
                "http_fingerprinting",
                "HTTP fingerprinting"
            ),
            (
                "tls_analysis",
                "TLS / SNI analysis"
            ),
            (
                "traffic_behaviour",
                "Traffic behaviour analysis"
            ),
        ]

        self.setting_vars = {}

        grid = tk.Frame(
            analysis_card,
            bg=COLORS["surface"]
        )

        grid.pack(
            fill="x"
        )

        for index, (
            key,
            label
        ) in enumerate(settings_items):

            variable = tk.BooleanVar(
                value=self.settings[
                    "analysis"
                ][key]
            )

            self.setting_vars[key] = variable

            check = tk.Checkbutton(
                grid,
                text=label,
                variable=variable,
                bg=COLORS["surface"],
                fg=COLORS["text"],
                activebackground=COLORS["surface"],
                activeforeground=COLORS["text"],
                selectcolor=COLORS["accent_light"],
                font=(
                    "Segoe UI",
                    9
                ),
                anchor="w"
            )

            check.grid(
                row=index // 2,
                column=index % 2,
                sticky="w",
                padx=4,
                pady=6
            )

        grid.grid_columnconfigure(
            0,
            weight=1
        )

        grid.grid_columnconfigure(
            1,
            weight=1
        )

        # ----------------------------------------------------
        # Detection
        # ----------------------------------------------------

        detection = tk.Frame(
            outer,
            bg=COLORS["surface"]
        )

        detection.pack(
            fill="x",
            padx=25,
            pady=(0, 20)
        )

        tk.Label(
            detection,
            text="IoT Detection",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=(
                "Segoe UI Semibold",
                12
            )
        ).pack(
            anchor="w"
        )

        row = tk.Frame(
            detection,
            bg=COLORS["surface"]
        )

        row.pack(
            fill="x",
            pady=(12, 0)
        )

        tk.Label(
            row,
            text="IoT threshold:",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            side="left"
        )

        self.threshold_var = tk.IntVar(
            value=self.settings[
                "detection"
            ]["iot_threshold"]
        )

        tk.Spinbox(
            row,
            from_=1,
            to=100,
            textvariable=self.threshold_var,
            width=8,
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            side="left",
            padx=10
        )

        tk.Label(
            row,
            text="High-confidence threshold:",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            side="left",
            padx=(30, 0)
        )

        self.high_threshold_var = tk.IntVar(
            value=self.settings[
                "detection"
            ]["high_confidence"]
        )

        tk.Spinbox(
            row,
            from_=1,
            to=100,
            textvariable=self.high_threshold_var,
            width=8,
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            side="left",
            padx=10
        )

        # ----------------------------------------------------
        # Persistence
        # ----------------------------------------------------

        remember = tk.BooleanVar(
            value=self.settings[
                "interface"
            ]["remember_last_pcap"]
        )

        self.remember_var = remember

        tk.Checkbutton(
            detection,
            text="Remember last PCAP path",
            variable=remember,
            bg=COLORS["surface"],
            fg=COLORS["text"],
            activebackground=COLORS["surface"],
            selectcolor=COLORS["accent_light"],
            font=(
                "Segoe UI",
                9
            )
        ).pack(
            anchor="w",
            pady=(12, 0)
        )

        # ----------------------------------------------------
        # MAC -> Make / Model CSV
        # ----------------------------------------------------

        csv_card = tk.Frame(
            outer,
            bg=COLORS["surface"]
        )

        csv_card.pack(
            fill="x",
            padx=25,
            pady=(0, 10)
        )

        tk.Label(
            csv_card,
            text="MAC → Make / Model Database",
            bg=COLORS["surface"],
            fg=COLORS["text"],
            font=(
                "Segoe UI Semibold",
                12
            )
        ).pack(
            anchor="w"
        )

        tk.Label(
            csv_card,
            text=(
                "Select a CSV containing MAC, Make and Model columns. "
                "Exact MAC matches are preferred; OUI matches are used as fallback."
            ),
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=(
                "Segoe UI",
                8
            )
        ).pack(
            anchor="w",
            pady=(3, 8)
        )

        csv_row = tk.Frame(
            csv_card,
            bg=COLORS["surface"]
        )

        csv_row.pack(
            fill="x"
        )

        self.device_csv_var = tk.StringVar(
            value=self.settings.get(
                "paths",
                {}
            ).get(
                "device_csv",
                ""
            )
        )

        self.device_csv_entry = tk.Entry(
            csv_row,
            textvariable=self.device_csv_var,
            bg="#F7FAFC",
            fg=COLORS["text"],
            relief="flat",
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            font=(
                "Segoe UI",
                9
            )
        )

        self.device_csv_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=7,
            padx=(0, 8)
        )

        tk.Button(
            csv_row,
            text="Browse CSV",
            bg=COLORS["blue"],
            fg="#FFFFFF",
            activebackground=COLORS["blue"],
            activeforeground="#FFFFFF",
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            font=(
                "Segoe UI Semibold",
                9
            ),
            padx=14,
            pady=8,
            command=self.browse_device_csv
        ).pack(
            side="left"
        )

        tk.Label(
            csv_card,
            text="Example: MAC,Make,Model",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=(
                "Consolas",
                8
            )
        ).pack(
            anchor="w",
            pady=(6, 0)
        )

        # ----------------------------------------------------
        # Buttons
        # ----------------------------------------------------

        buttons = tk.Frame(
            outer,
            bg=COLORS["surface"]
        )

        buttons.pack(
            fill="x",
            padx=25,
            pady=20
        )

        tk.Button(
            buttons,
            text="Save Settings",
            bg=COLORS["accent"],
            fg="#FFFFFF",
            activebackground=COLORS["accent_dark"],
            activeforeground="#FFFFFF",
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            font=(
                "Segoe UI Semibold",
                10
            ),
            padx=18,
            pady=9,
            command=self.save_settings_from_ui
        ).pack(
            side="left"
        )

        tk.Button(
            buttons,
            text="Reset Defaults",
            bg="#E8EEF3",
            fg=COLORS["text"],
            activebackground="#DCE5EB",
            relief="flat",
            borderwidth=0,
            cursor="hand2",
            font=(
                "Segoe UI Semibold",
                10
            ),
            padx=18,
            pady=9,
            command=self.reset_settings
        ).pack(
            side="left",
            padx=10
        )

    def browse_device_csv(self):
        path = filedialog.askopenfilename(
            title="Select MAC → Make / Model CSV",
            filetypes=[
                (
                    "CSV Files",
                    "*.csv"
                ),
                (
                    "All Files",
                    "*.*"
                ),
            ]
        )

        if not path:
            return

        self.device_csv_var.set(path)

    # ========================================================
    # SAVE SETTINGS FROM UI
    # ========================================================

    def save_settings_from_ui(self):

        for key, variable in self.setting_vars.items():

            self.settings[
                "analysis"
            ][key] = bool(
                variable.get()
            )

        try:

            threshold = int(
                self.threshold_var.get()
            )

            high = int(
                self.high_threshold_var.get()
            )

        except Exception:

            messagebox.showerror(
                "Invalid Settings",
                "Threshold values must be integers."
            )

            return

        if not 1 <= threshold <= 100:
            messagebox.showerror(
                "Invalid Settings",
                "IoT threshold must be between 1 and 100."
            )
            return

        if not 1 <= high <= 100:
            messagebox.showerror(
                "Invalid Settings",
                "High-confidence threshold must be between 1 and 100."
            )
            return

        if high < threshold:

            messagebox.showerror(
                "Invalid Settings",
                "High-confidence threshold should be "
                "greater than or equal to IoT threshold."
            )

            return

        self.settings[
            "detection"
        ]["iot_threshold"] = threshold

        self.settings[
            "detection"
        ]["high_confidence"] = high

        self.settings[
            "interface"
        ]["remember_last_pcap"] = bool(
            self.remember_var.get()
        )

        self.settings[
            "paths"
        ]["device_csv"] = self.device_csv_var.get().strip()

        self.save_settings()

    # ========================================================
    # RESET SETTINGS
    # ========================================================

    def reset_settings(self):

        answer = messagebox.askyesno(
            "Reset Settings",
            "Restore all settings to defaults?"
        )

        if not answer:
            return

        self.settings = json.loads(
            json.dumps(DEFAULT_SETTINGS)
        )

        for key, variable in self.setting_vars.items():

            variable.set(
                self.settings[
                    "analysis"
                ][key]
            )

        self.threshold_var.set(
            self.settings[
                "detection"
            ]["iot_threshold"]
        )

        self.high_threshold_var.set(
            self.settings[
                "detection"
            ]["high_confidence"]
        )

        self.remember_var.set(
            self.settings[
                "interface"
            ]["remember_last_pcap"]
        )

        if hasattr(self, "device_csv_var"):
            self.device_csv_var.set(
                self.settings[
                    "paths"
                ].get(
                    "device_csv",
                    ""
                )
            )

        self.save_settings()

    # ========================================================
    # OPEN PCAP
    # ========================================================

    def open_pcap(self):

        if (
            self.analysis_thread
            and self.analysis_thread.is_alive()
        ):

            messagebox.showwarning(
                "Analysis Running",
                "Please wait for the current analysis to finish."
            )

            return

        filepath = filedialog.askopenfilename(
            title="Open PCAP / PCAPNG",
            filetypes=[
                (
                    "Packet Capture",
                    "*.pcap *.pcapng *.cap"
                ),
                (
                    "PCAP",
                    "*.pcap"
                ),
                (
                    "PCAPNG",
                    "*.pcapng"
                ),
                (
                    "All Files",
                    "*.*"
                ),
            ]
        )

        if not filepath:
            return

        self.current_file = filepath
        if self.settings.get("interface", {}).get("remember_last_pcap", True):
            self.settings.setdefault("paths", {})["last_pcap"] = filepath
            self.save_settings()

        self.file_label.configure(
            text=os.path.basename(
                filepath
            )
        )

        self.overview_file_label.configure(
            text=filepath
        )

        self.set_status(
            "PCAP loaded",
            COLORS["blue"]
        )

        # New PCAP means new analysis.
        self.analysis_result = None

        self.clear_result_views()

        self.refresh_overview()

    # ========================================================
    # START ANALYSIS
    # ========================================================

    def start_analysis(self):

        if not self.current_file:

            messagebox.showwarning(
                "No PCAP",
                "Please open a PCAP or PCAPNG file first."
            )

            return

        if (
            self.analysis_thread
            and self.analysis_thread.is_alive()
        ):

            return

        self.analysis_engine = PCAPAnalyzer(
            self.settings,
            self.event_queue
        )

        self.analyze_button.configure(
            state="disabled"
        )

        self.cancel_button.configure(
            state="normal"
        )

        self.progress.configure(
            mode="indeterminate"
        )

        self.progress.start(
            12
        )

        self.analysis_progress_label.configure(
            text="Starting analysis..."
        )

        self.set_status(
            "Analyzing PCAP",
            COLORS["orange"]
        )

        self.analysis_thread = threading.Thread(
            target=self.analysis_worker,
            args=(
                self.current_file,
            ),
            daemon=True
        )

        self.analysis_thread.start()

    # ========================================================
    # ANALYSIS WORKER
    # ========================================================

    def analysis_worker(self, filepath):

        try:

            self.analysis_engine.analyze(
                filepath
            )

        except Exception as exc:

            self.event_queue.put(
                (
                    "error",
                    str(exc)
                )
            )

    # ========================================================
    # CANCEL
    # ========================================================

    def cancel_analysis(self):

        if self.analysis_engine:

            self.analysis_engine.cancel()

            self.set_status(
                "Cancelling...",
                COLORS["orange"]
            )

    # ========================================================
    # EVENT PROCESSOR
    # ========================================================

    def process_events(self):

        try:

            while True:

                event, payload = (
                    self.event_queue.get_nowait()
                )

                if event == "status":

                    self.analysis_progress_label.configure(
                        text=safe_text(
                            payload
                        )
                    )

                elif event == "hash_progress":

                    self.analysis_progress_label.configure(
                        text=(
                            "Calculating SHA-256 "
                            f"{float(payload):.0f}%"
                        )
                    )

                elif event == "progress":

                    packets = payload.get(
                        "packets",
                        0
                    )

                    bytes_count = payload.get(
                        "bytes",
                        0
                    )

                    self.analysis_progress_label.configure(
                        text=(
                            f"Packets: {packets:,}    "
                            f"Traffic: {format_bytes(bytes_count)}"
                        )
                    )

                elif event == "complete":

                    self.analysis_finished(
                        payload
                    )

                elif event == "cancelled":

                    self.analysis_cancelled()

                elif event == "error":

                    self.analysis_error(
                        payload
                    )

        except queue.Empty:
            pass

        self.after(
            100,
            self.process_events
        )

    # ========================================================
    # FINISHED
    # ========================================================

    def analysis_finished(
        self,
        result
    ):

        self.analysis_result = result

        self.progress.stop()

        self.progress.configure(
            mode="determinate",
            value=100
        )

        self.analyze_button.configure(
            state="normal"
        )

        self.cancel_button.configure(
            state="disabled"
        )

        self.set_status(
            "Analysis complete",
            COLORS["green"]
        )

        self.analysis_progress_label.configure(
            text=(
                f"Analysis complete • "
                f"{result['packets']:,} packets • "
                f"{len(result['hosts']):,} hosts • "
                f"{len(result['iot_devices']):,} IoT devices"
            )
        )

        self.refresh_all_pages()

        messagebox.showinfo(
            "Analysis Complete",
            (
                "PCAP analysis completed successfully.\n\n"
                f"Packets: {result['packets']:,}\n"
                f"Hosts: {len(result['hosts']):,}\n"
                f"IoT devices: {len(result['iot_devices']):,}\n"
                f"SHA-256: {result['metadata']['sha256']}"
            )
        )

    # ========================================================
    # CANCELLED
    # ========================================================

    def analysis_cancelled(self):

        self.progress.stop()

        self.progress.configure(
            mode="determinate",
            value=0
        )

        self.analyze_button.configure(
            state="normal"
        )

        self.cancel_button.configure(
            state="disabled"
        )

        self.set_status(
            "Analysis cancelled",
            COLORS["red"]
        )

        self.analysis_progress_label.configure(
            text="Analysis cancelled."
        )

    # ========================================================
    # ERROR
    # ========================================================

    def analysis_error(self, error):

        self.progress.stop()

        self.analyze_button.configure(
            state="normal"
        )

        self.cancel_button.configure(
            state="disabled"
        )

        self.set_status(
            "Analysis failed",
            COLORS["red"]
        )

        self.analysis_progress_label.configure(
            text="Analysis failed."
        )

        messagebox.showerror(
            "Analysis Error",
            (
                "The PCAP could not be analyzed.\n\n"
                f"{error}"
            )
        )

    # ========================================================
    # CLEAR VIEWS
    # ========================================================

    def clear_tree(self, tree):

        if tree is None:
            return

        for item in tree.get_children():
            tree.delete(item)

    def clear_result_views(self):

        self.clear_tree(
            self.host_tree
        )

        self.clear_tree(
            self.iot_tree
        )

        self.clear_tree(
            self.protocol_tree
        )

        self.clear_tree(
            self.evidence_tree
        )

        self.clear_tree(
            self.timeline_tree
        )

        self.clear_tree(
            self.overview_iot_tree
        )

        for label in self.metric_labels.values():

            if label.winfo_exists():
                label.configure(
                    text="0"
                )

        self.summary_text.configure(
            state="normal"
        )

        self.summary_text.delete(
            "1.0",
            "end"
        )

        self.summary_text.insert(
            "1.0",
            "Load a PCAP to begin analysis."
        )

        self.summary_text.configure(
            state="disabled"
        )

    # ========================================================
    # REFRESH ALL
    # ========================================================

    def refresh_all_pages(self):

        self.refresh_overview()
        self.refresh_hosts()
        self.refresh_iot_devices()
        self.refresh_protocols()
        self.refresh_evidence()
        self.refresh_timeline()

    # ========================================================
    # OVERVIEW REFRESH
    # ========================================================

    def refresh_overview(self):

        if not self.analysis_result:

            if self.current_file:

                self.overview_file_label.configure(
                    text=self.current_file
                )

            return

        result = self.analysis_result

        self.overview_file_label.configure(
            text=result["metadata"]["file"]
        )

        self.metric_labels[
            "Packets"
        ].configure(
            text=f"{result['packets']:,}"
        )

        self.metric_labels[
            "Traffic"
        ].configure(
            text=format_bytes(
                result["bytes"]
            )
        )

        self.metric_labels[
            "Hosts"
        ].configure(
            text=f"{len(result['hosts']):,}"
        )

        self.metric_labels[
            "IoT Devices"
        ].configure(
            text=f"{len(result['iot_devices']):,}"
        )

        self.metric_labels[
            "Alerts"
        ].configure(
            text=f"{len(result['alerts']):,}"
        )

        self.clear_tree(
            self.overview_iot_tree
        )

        for ip, host in sorted(
            result["iot_devices"].items(),
            key=lambda item: item[1]["score"],
            reverse=True
        ):

            self.overview_iot_tree.insert(
                "",
                "end",
                values=(
                    ip,
                    host.get("device_make") or "Unknown",
                    host.get("device_model") or "Unknown",
                    host["classification"],
                    host["vendor"] or "Unknown",
                    f"{host['score']}/100",
                    host["confidence"],
                )
            )

        metadata = result["metadata"]

        summary = (
            "PCAP ANALYSIS\n"
            "────────────────────────────\n\n"
            f"File:\n{metadata['file']}\n\n"
            f"SHA-256:\n{metadata['sha256']}\n\n"
            f"Packets: {result['packets']:,}\n"
            f"Traffic: {format_bytes(result['bytes'])}\n"
            f"Hosts: {len(result['hosts']):,}\n"
            f"IoT devices: {len(result['iot_devices']):,}\n"
            f"Duration: {metadata['duration']:.2f}s\n\n"
            "DETECTION\n"
            "────────────────────────────\n"
        )

        if result["iot_devices"]:

            for ip, host in list(
                result["iot_devices"].items()
            )[:8]:

                summary += (
                    f"\n{ip}\n"
                    f"  Make: {host.get('device_make') or 'Unknown'}\n"
                    f"  Model: {host.get('device_model') or 'Unknown'}\n"
                    f"  {host['classification']} "
                    f"({host['score']}/100)\n"
                )

        else:

            summary += (
                "\nNo device crossed the configured "
                "IoT detection threshold."
            )

        self.summary_text.configure(
            state="normal"
        )

        self.summary_text.delete(
            "1.0",
            "end"
        )

        self.summary_text.insert(
            "1.0",
            summary
        )

        self.summary_text.configure(
            state="disabled"
        )

    # ========================================================
    # HOST REFRESH
    # ========================================================

    def refresh_hosts(self):

        if not self.host_tree:
            return

        self.clear_tree(
            self.host_tree
        )

        if not self.analysis_result:
            return

        hosts = self.analysis_result[
            "hosts"
        ]

        for ip, host in sorted(
            hosts.items()
        ):

            self.host_tree.insert(
                "",
                "end",
                values=(
                    ip,
                    host["mac"] or "Unknown",
                    host.get("device_make") or "Unknown",
                    host.get("device_model") or "Unknown",
                    host["vendor"] or "Unknown",
                    host["hostname"] or "",
                    f"{host['packets']:,}",
                    format_bytes(
                        host["bytes"]
                    ),
                    host["classification"],
                    host["score"],
                )
            )

    # ========================================================
    # IOT REFRESH
    # ========================================================

    def refresh_iot_devices(self):

        if not self.iot_tree:
            return

        self.clear_tree(
            self.iot_tree
        )

        if not self.analysis_result:
            return

        devices = self.analysis_result[
            "iot_devices"
        ]

        for ip, host in sorted(
            devices.items(),
            key=lambda item: item[1]["score"],
            reverse=True
        ):

            services = ", ".join(
                sorted(
                    host["services"].keys()
                )
            )

            self.iot_tree.insert(
                "",
                "end",
                values=(
                    ip,
                    host.get("device_make") or "Unknown",
                    host.get("device_model") or "Unknown",
                    host["classification"],
                    host["vendor"] or "Unknown",
                    f"{host['score']}/100",
                    host["confidence"],
                    services or "—",
                    host["hostname"] or "—",
                )
            )

    # ========================================================
    # IOT SELECTED
    # ========================================================

    def on_iot_selected(self, event):

        selection = self.iot_tree.selection()

        if not selection:
            return

        item = self.iot_tree.item(
            selection[0]
        )

        values = item.get(
            "values",
            []
        )

        if not values:
            return

        ip = values[0]

        self.last_selected_iot = ip

        host = self.analysis_result[
            "hosts"
        ].get(ip)

        if not host:
            return

        reasons = host.get(
            "classification_reasons",
            []
        )

        detail = (
            f"Device: {ip}\n"
            f"MAC: {host.get('mac') or 'Unknown'}\n"
            f"Make: {host.get('device_make') or 'Unknown'}\n"
            f"Model: {host.get('device_model') or 'Unknown'}\n"
            f"Classification: {host['classification']}\n"
            f"Vendor: {host['vendor'] or 'Unknown'}\n"
            f"Hostname: {host['hostname'] or 'Unknown'}\n"
            f"IoT Score: {host['score']}/100\n"
            f"Confidence: {host['confidence']}\n\n"
            "WHY THIS DEVICE WAS CLASSIFIED\n"
            "────────────────────────────────\n"
        )

        if reasons:

            for reason in reasons:
                detail += f"• {reason}\n"

        else:

            detail += (
                "No additional classification reasons recorded.\n"
            )

        messagebox.showinfo(
            "IoT Device Evidence",
            detail
        )

    # ========================================================
    # PROTOCOL REFRESH
    # ========================================================

    def refresh_protocols(self):

        if not self.protocol_tree:
            return

        self.clear_tree(
            self.protocol_tree
        )

        if not self.analysis_result:
            return

        protocols = self.analysis_result[
            "protocols"
        ]

        total = max(
            1,
            self.analysis_result[
                "packets"
            ]
        )

        for protocol, count in sorted(
            protocols.items(),
            key=lambda item: item[1],
            reverse=True
        ):

            percentage = (
                count / total
            ) * 100

            self.protocol_tree.insert(
                "",
                "end",
                values=(
                    protocol,
                    f"{count:,}",
                    f"{percentage:.2f}%"
                )
            )

    # ========================================================
    # EVIDENCE REFRESH
    # ========================================================

    def refresh_evidence(self):

        if not self.evidence_tree:
            return

        self.clear_tree(
            self.evidence_tree
        )

        if not self.analysis_result:
            return

        for item in self.analysis_result[
            "evidence"
        ]:

            self.evidence_tree.insert(
                "",
                "end",
                values=(
                    item.get(
                        "ip",
                        ""
                    ),
                    item.get(
                        "category",
                        ""
                    ),
                    item.get(
                        "description",
                        ""
                    ),
                    item.get(
                        "weight",
                        ""
                    ),
                    item.get(
                        "severity",
                        ""
                    ),
                )
            )

    # ========================================================
    # TIMELINE REFRESH
    # ========================================================

    def refresh_timeline(self):

        if not self.timeline_tree:
            return

        self.clear_tree(
            self.timeline_tree
        )

        if not self.analysis_result:
            return

        for event in self.analysis_result[
            "timeline"
        ]:

            self.timeline_tree.insert(
                "",
                "end",
                values=(
                    event["time"],
                    event["source"],
                    event["source_port"],
                    event["destination"],
                    event["destination_port"],
                    event["protocol"],
                )
            )

    # ========================================================
    # STATUS
    # ========================================================

    def set_status(
        self,
        text,
        color=None
    ):

        if color is None:
            color = COLORS["green"]

        self.status_label.configure(
            text=text
        )

        self.status_dot.configure(
            fg=color
        )

    # ========================================================
    # EXPORT JSON
    # ========================================================

    def export_report(self):

        if not self.analysis_result:

            messagebox.showwarning(
                "No Analysis",
                "Analyze a PCAP before exporting a report."
            )

            return

        path = filedialog.asksaveasfilename(
            title="Export Analysis Report",
            defaultextension=".json",
            filetypes=[
                (
                    "JSON Report",
                    "*.json"
                )
            ]
        )

        if not path:
            return

        data = self.make_json_serializable(
            self.analysis_result
        )

        try:

            with open(
                path,
                "w",
                encoding="utf-8"
            ) as handle:

                json.dump(
                    data,
                    handle,
                    indent=4
                )

            messagebox.showinfo(
                "Report Exported",
                f"Report saved to:\n\n{path}"
            )

        except Exception as exc:

            messagebox.showerror(
                "Export Error",
                str(exc)
            )

    # ========================================================
    # JSON SERIALIZATION
    # ========================================================

    def make_json_serializable(
        self,
        obj
    ):

        if isinstance(
            obj,
            Counter
        ):

            return {
                str(k): self.make_json_serializable(v)
                for k, v in obj.items()
            }

        if isinstance(
            obj,
            defaultdict
        ):

            return {
                str(k): self.make_json_serializable(v)
                for k, v in obj.items()
            }

        if isinstance(
            obj,
            dict
        ):

            return {
                str(k): self.make_json_serializable(v)
                for k, v in obj.items()
            }

        if isinstance(
            obj,
            list
        ):

            return [
                self.make_json_serializable(v)
                for v in obj
            ]

        if isinstance(
            obj,
            tuple
        ):

            return [
                self.make_json_serializable(v)
                for v in obj
            ]

        return obj

    # ========================================================
    # CLOSE
    # ========================================================

    def on_close(self):

        if (
            self.analysis_thread
            and self.analysis_thread.is_alive()
        ):

            answer = messagebox.askyesno(
                "Analysis Running",
                "Analysis is still running. Cancel and exit?"
            )

            if not answer:
                return

            if self.analysis_engine:
                self.analysis_engine.cancel()

            self.after(
                200,
                self.on_close
            )

            return

        self.destroy()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    app = IoTPCAPAnalyzerApp()

    app.mainloop()
