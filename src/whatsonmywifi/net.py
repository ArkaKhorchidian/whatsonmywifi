"""Find the devices on the network you're on, and what they say about themselves. No root needed.

Discovery: a UDP nudge to every address in your subnet fills the ARP table; then the ARP table, mDNS (Bonjour),
SSDP (UPnP), reverse DNS and a short TCP connect check on a handful of well-known ports.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from xml.etree import ElementTree

PORTS = {22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 445: "SMB", 548: "AFP", 554: "RTSP video",
         1883: "MQTT", 3389: "Remote Desktop", 5000: "UPnP/HTTP", 5900: "VNC", 8008: "Cast", 8080: "HTTP",
         8443: "HTTPS", 9100: "Printing", 62078: "iPhone sync"}

MDNS_SERVICES = ["_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_spotify-connect._tcp", "_ipp._tcp",
                 "_printer._tcp", "_pdl-datastream._tcp", "_hap._tcp", "_companion-link._tcp", "_device-info._tcp",
                 "_smb._tcp", "_afpovertcp._tcp", "_ssh._tcp", "_sonos._tcp", "_amzn-wplay._tcp", "_matter._tcp",
                 "_hue._tcp", "_workstation._tcp", "_androidtvremote2._tcp", "_nvstream._tcp", "_sleep-proxy._udp",
                 "_rfb._tcp", "_http._tcp", "_homekit._tcp", "_mqtt._tcp", "_esphomelib._tcp", "_axis-video._tcp",
                 "_rtsp._tcp", "_daap._tcp", "_touch-able._tcp", "_adisk._tcp", "_scanner._tcp", "_uscan._tcp"]


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    names: list[str] = field(default_factory=list)  # what it announces: Bonjour instance names, UPnP friendlyName
    services: set[str] = field(default_factory=set)  # mDNS service types and SSDP device types
    info: dict[str, str] = field(default_factory=dict)  # model, manufacturer… from TXT records and UPnP XML
    ports: dict[int, str] = field(default_factory=dict)
    is_me: bool = False
    is_gateway: bool = False

    @property
    def private_mac(self) -> bool:
        """Phones and new laptops use a random MAC per network; the "locally administered" bit gives it away."""
        try:
            return bool(int(self.mac.split(":")[0], 16) & 0x02)
        except (ValueError, IndexError):
            return False


# ---------------------------------------------------------------------------
# your own address, subnet and router
# ---------------------------------------------------------------------------
def my_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # no packet is sent; this just picks the outgoing interface
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def run(cmd: list[str], timeout: float = 10) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def gateway() -> str:
    if sys.platform == "darwin":
        m = re.search(r"gateway:\s*([\d.]+)", run(["route", "-n", "get", "default"]))
    elif sys.platform == "win32":
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)", run(["route", "print", "-4"]))
    else:
        m = re.search(r"default via ([\d.]+)", run(["ip", "-4", "route", "show", "default"]))
    return m.group(1) if m else ""


def subnet(ip: str, prefix: int = 24) -> ipaddress.IPv4Network:
    return ipaddress.ip_network(f"{ip}/{prefix}", strict=False)


# ---------------------------------------------------------------------------
# ARP
# ---------------------------------------------------------------------------
def norm_mac(mac: str) -> str:
    parts = re.split(r"[:-]", mac.strip().lower())
    if len(parts) != 6:
        return ""
    try:
        return ":".join(f"{int(p, 16):02x}" for p in parts)
    except ValueError:
        return ""


def parse_arp(text: str) -> dict[str, str]:
    """ip -> mac from `ip neigh`, /proc/net/arp, macOS/BSD `arp -an` or Windows `arp -a` output."""
    out = {}
    for line in text.splitlines():
        ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac = re.search(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b", line)
        if not ip or not mac or "incomplete" in line.lower() or "FAILED" in line:
            continue
        m = norm_mac(mac.group(1))
        if m and m not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") and not m.startswith("01:00:5e"):
            out[ip.group(1)] = m
    return out


def arp_table() -> dict[str, str]:
    if sys.platform.startswith("linux"):
        text = run(["ip", "neigh"])
        if not text.strip():
            try:
                with open("/proc/net/arp") as fh:
                    text = fh.read()
            except OSError:
                text = ""
        return parse_arp(text)
    return parse_arp(run(["arp", "-an"] if sys.platform != "win32" else ["arp", "-a"]))


def nudge(net: ipaddress.IPv4Network, me: str) -> None:
    """Send one empty UDP packet to every address so the OS asks "who has this IP?" and fills the ARP table."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(False)
    for host in net.hosts():
        if str(host) == me:
            continue
        for _ in range(2):
            try:
                s.sendto(b"", (str(host), 9))
            except OSError:
                pass
        time.sleep(0.002)
    s.close()


def vendor(mac: str) -> str:
    if not mac:
        return ""
    try:
        from netaddr import EUI
        org = EUI(mac).oui.registration().org
    except Exception:
        return ""
    return clean_vendor(org)


def clean_vendor(org: str) -> str:
    org = re.sub(r"[,.]?\s*(inc|ltd|llc|co|corp|corporation|gmbh|limited|technologies|technology|electronics|"
                 r"international|company|s\.?a|ab|bv|plc)\b\.?", "", org, flags=re.I).strip(" ,.")
    org = re.sub(r"\b(Hangzhou|Shenzhen|Beijing|Guangdong|Zhejiang|Shanghai|Xiamen|Digital|Industries|Interactive|"
                 r"Entertainment|Lighting|Labs|Networks|Communications|Communication|Products|Systems|Device|Devices|"
                 r"Mobile|Holdings|Group|Information|Science|Tech)\b", "", org, flags=re.I)
    return re.sub(r"\s{2,}", " ", org).strip(" ,.") or org.strip()


# ---------------------------------------------------------------------------
# mDNS / Bonjour
# ---------------------------------------------------------------------------
def dns_query(names: list[str], qtype: int = 12) -> bytes:
    """A DNS query for PTR records with the "unicast response please" bit, so we don't need port 5353."""
    q = b""
    for name in names:
        for label in name.rstrip(".").split("."):
            b = label.encode()
            q += bytes([len(b)]) + b
        q += b"\x00" + struct.pack(">HH", qtype, 0x8001)
    return struct.pack(">HHHHHH", 0, 0, len(names), 0, 0, 0) + q


def read_name(data: bytes, i: int) -> tuple[str, int]:
    labels, end, hops = [], None, 0
    while i < len(data):
        n = data[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:
            if end is None:
                end = i + 2
            i = ((n & 0x3F) << 8) | data[i + 1]
            hops += 1
            if hops > 30:
                break
            continue
        labels.append(data[i + 1:i + 1 + n].decode("utf-8", "replace"))
        i += 1 + n
    return ".".join(labels), (end if end is not None else i)


def parse_dns(data: bytes) -> list[tuple[str, int, object]]:
    """(name, type, value) for every record in a response. PTR/SRV/A values decoded, TXT as dict."""
    try:
        _, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return []
    i, out = 12, []
    try:
        for _ in range(qd):
            _, i = read_name(data, i)
            i += 4
        for _ in range(an + ns + ar):
            name, i = read_name(data, i)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[i:i + 10])
            i += 10
            rd = data[i:i + rdlen]
            if rtype == 12:  # PTR
                value: object = read_name(data, i)[0]
            elif rtype == 33:  # SRV
                value = read_name(data, i + 6)[0]
            elif rtype == 1 and rdlen == 4:
                value = socket.inet_ntoa(rd)
            elif rtype == 16:  # TXT
                txt, j = {}, 0
                while j < len(rd):
                    n = rd[j]
                    k, _, v = rd[j + 1:j + 1 + n].decode("utf-8", "replace").partition("=")
                    if k:
                        txt[k.lower()] = v
                    j += 1 + n
                value = txt
            else:
                value = None
            out.append((name, rtype, value))
            i += rdlen
    except (struct.error, IndexError):
        pass
    return out


def instance_label(instance: str, service: str) -> str:
    """'Living Room TV._googlecast._tcp.local' -> 'Living Room TV'. Strips the @MAC prefix AirPlay adds."""
    label = instance[: -len(service) - 1] if instance.endswith(service) else instance.split("._")[0]
    label = label.replace(".local", "").rstrip(".")
    return re.sub(r"^[0-9A-Fa-f]{12}@", "", label)


def mdns(wait: float = 2.5) -> dict[str, dict]:
    """ip -> {"names": [...], "services": {...}, "info": {...}}"""
    found: dict[str, dict] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        names = [f"{t}.local" for t in MDNS_SERVICES]
        for k in range(0, len(names), 8):
            s.sendto(dns_query(names[k:k + 8]), ("224.0.0.251", 5353))
    except OSError:
        s.close()
        return found
    end = time.time() + wait
    while time.time() < end:
        try:
            data, (src, _) = s.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError:
            break
        absorb_mdns(found, src, parse_dns(data))
    s.close()
    return found


INFO_KEYS = {"md": "model", "model": "model", "am": "model", "fn": "name", "ty": "model", "usb_mdl": "model",
             "rpmd": "model", "manufacturer": "manufacturer", "usb_mfg": "manufacturer", "mf": "manufacturer",
             "deviceid": "", "osxvers": "macOS"}


def absorb_mdns(found: dict, src: str, records: list) -> None:
    d = found.setdefault(src, {"names": [], "services": set(), "info": {}})
    for name, rtype, value in records:
        if rtype == 12 and isinstance(value, str):
            svc = name.replace(".local", "")
            if svc.startswith("_") and svc in MDNS_SERVICES:
                d["services"].add(svc)
                label = instance_label(value, name)
                if label and label not in d["names"] and svc not in ("_device-info._tcp", "_sleep-proxy._udp"):
                    d["names"].append(label)
        elif rtype == 16 and isinstance(value, dict):
            for k, v in value.items():
                key = INFO_KEYS.get(k)
                if key and v and key not in d["info"]:
                    d["info"][key] = v.strip()
        elif rtype == 33 and isinstance(value, str) and value.endswith(".local"):
            d["info"].setdefault("host", value[:-6])


# ---------------------------------------------------------------------------
# SSDP / UPnP
# ---------------------------------------------------------------------------
def parse_ssdp(data: bytes) -> dict[str, str]:
    h = {}
    for line in data.decode("utf-8", "replace").splitlines()[1:]:
        k, _, v = line.partition(":")
        if k.strip():
            h[k.strip().lower()] = v.strip()
    return h


def parse_upnp_xml(xml: bytes) -> dict[str, str]:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return {}
    out = {}
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag in ("friendlyName", "manufacturer", "modelName", "modelDescription", "deviceType") and el.text \
                and tag not in out:
            out[tag] = el.text.strip()
    return out


def ssdp(wait: float = 2.5) -> dict[str, dict]:
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           "ST: ssdp:all\r\n\r\n").encode()
    found: dict[str, dict] = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.3)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
    except OSError:
        s.close()
        return found
    end = time.time() + wait
    while time.time() < end:
        try:
            data, (src, _) = s.recvfrom(9000)
        except socket.timeout:
            continue
        except OSError:
            break
        h = parse_ssdp(data)
        d = found.setdefault(src, {"st": set(), "server": "", "location": ""})
        if h.get("st"):
            d["st"].add(h["st"])
        d["server"] = d["server"] or h.get("server", "")
        loc = h.get("location", "")
        # only fetch descriptions the device serves about itself, on its own address
        if loc and not d["location"] and re.match(rf"https?://{re.escape(src)}[:/]", loc):
            d["location"] = loc
    s.close()
    for src, d in found.items():
        if d["location"]:
            try:
                with urllib.request.urlopen(d["location"], timeout=2) as r:
                    d.update(parse_upnp_xml(r.read(200_000)))
            except Exception:
                pass
    return found


# ---------------------------------------------------------------------------
# names and ports
# ---------------------------------------------------------------------------
def reverse_dns(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""
    return "" if name == ip else name


def open_ports(ip: str, ports=PORTS, timeout: float = 0.6) -> dict[int, str]:
    out = {}
    for p, label in ports.items():
        try:
            with socket.create_connection((ip, p), timeout=timeout):
                out[p] = label
        except OSError:
            pass
    return out


def discover(prefix: int = 24, scan_ports: bool = True, progress=lambda msg: None) -> list[Device]:
    me = my_ip()
    net = subnet(me, prefix)
    gw = gateway()
    progress(f"Looking for devices on {net}…")
    with ThreadPoolExecutor(2) as pool:
        m_future = pool.submit(mdns)
        s_future = pool.submit(ssdp)
        nudge(net, me)
        time.sleep(1.5)
        found_mdns, found_ssdp = m_future.result(), s_future.result()
    table = {ip: mac for ip, mac in arp_table().items() if ipaddress.ip_address(ip) in net}
    ips = set(table) | {ip for ip in list(found_mdns) + list(found_ssdp) if ipaddress.ip_address(ip) in net} | {me}
    devices = {ip: Device(ip, table.get(ip, ""), is_me=ip == me, is_gateway=ip == gw) for ip in ips}
    for ip, d in devices.items():
        d.vendor = vendor(d.mac)
        if ip in found_mdns:
            m = found_mdns[ip]
            d.names += m["names"]
            d.services |= m["services"]
            d.info.update(m["info"])
        if ip in found_ssdp:
            s = found_ssdp[ip]
            if s.get("friendlyName") and s["friendlyName"] not in d.names:
                d.names.append(s["friendlyName"])
            d.services |= {st for st in s["st"] if "device:" in st or "service:" in st}
            for k_from, k_to in (("manufacturer", "manufacturer"), ("modelName", "model"),
                                 ("modelDescription", "description"), ("server", "server")):
                if s.get(k_from):
                    d.info.setdefault(k_to, s[k_from])
    progress(f"Asking {len(devices)} devices what they are…")
    with ThreadPoolExecutor(64) as pool:
        names = dict(zip(devices, pool.map(reverse_dns, devices)))
        ports = dict(zip(devices, pool.map(open_ports, devices))) if scan_ports else {}
    for ip, d in devices.items():
        d.hostname = names.get(ip, "")
        d.ports = ports.get(ip, {})
    return sorted(devices.values(), key=lambda d: tuple(int(x) for x in d.ip.split(".")))
