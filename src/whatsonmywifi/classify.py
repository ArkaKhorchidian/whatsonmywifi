"""Turn what each device says about itself into "what is it" and "what should you know about it"."""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass

from .net import Device

ROUTER, PHONE, COMPUTER, TV, SPEAKER, CAMERA, PRINTER, SMART, CONSOLE, NAS, PI, UNKNOWN = (
    "Router", "Phone or tablet", "Computer", "TV or streamer", "Speaker", "Camera", "Printer", "Smart home",
    "Game console", "Storage", "Single-board computer", "Unknown")

ICON = {ROUTER: "📡", PHONE: "📱", COMPUTER: "💻", TV: "📺", SPEAKER: "🔊", CAMERA: "📷", PRINTER: "🖨 ", SMART: "💡",
        CONSOLE: "🎮", NAS: "🗄 ", PI: "🧩", UNKNOWN: "❓"}

# (regex over vendor + names + model + services, kind). First match wins, so specific beats generic.
RULES = [
    (r"axis-video|_rtsp\._tcp|\b(hikvision|dahua|wyze|reolink|arlo|ring|blink|eufy|amcrest|foscam|ezviz|nest cam|"
     r"camera|doorbell|ipcam)\b", CAMERA),
    (r"_ipp\._tcp|_printer\._tcp|_pdl-datastream|_uscan|_scanner|\b(printer|laserjet|officejet|deskjet|envy|"
     r"brother|epson|canon|lexmark|xerox|kyocera)\b", PRINTER),
    (r"\b(playstation|ps[45]|xbox|nintendo|switch)\b|sony interactive", CONSOLE),
    (r"_googlecast|_amzn-wplay|_androidtvremote|_nvstream|mediarenderer|\b(roku|chromecast|fire ?tv|apple ?tv|"
     r"appletv|smart ?tv|bravia|vizio|tcl|hisense|webos|tizen|shield|tv)\b", TV),
    (r"_sonos|_spotify-connect|_raop\._tcp(?!.*_companion)|\b(sonos|homepod|echo|alexa|bose|google home|nest (mini|"
     r"audio|hub)|speaker|denon|yamaha)\b", SPEAKER),
    (r"_hap\._tcp|_homekit|_matter|_hue|_mqtt|_esphomelib|\b(philips hue|signify|tuya|espressif|shelly|tp-?link "
     r"kasa|kasa|wemo|belkin|ecobee|nest|smartthings|ikea|meross|lifx|govee|tado|switchbot|bridge|plug|bulb|"
     r"thermostat)\b", SMART),
    (r"_adisk|\b(synology|qnap|western digital|wd ?my|nas|diskstation|truenas|unraid)\b", NAS),
    (r"raspberry|\bpi\b", PI),
    (r"\b(iphone|ipad|android|galaxy|pixel|oneplus|xiaomi|redmi|oppo|huawei|motorola|phone)\b|_companion-link.*"
     r"\b(iphone|ipad)", PHONE),
    (r"_workstation|_rfb|_ssh|_smb|_afpovertcp|_companion-link|\b(macbook|imac|mac ?mini|mac ?studio|desktop|"
     r"laptop|thinkpad|surface|windows|ubuntu|intel|dell|lenovo|hewlett|asustek|micro-star)\b", COMPUTER),
    (r"internetgatewaydevice|wanipconnection|\b(router|gateway|eero|orbi|netgear|ubiquiti|unifi|mikrotik|"
     r"asus router|linksys|fritz|arris|sagemcom|technicolor|huawei hg|xfinity|starlink|google wifi|nest wifi|deco)\b",
     ROUTER),
]

DEVICE_WORDS = (r"iPhone|iPad|MacBook(?: (?:Pro|Air))?|iMac|Mac(?: mini| Studio)?|Apple Watch|Watch|Galaxy|Pixel|"
                r"Phone|Android|Laptop|PC|Desktop|Kindle|Echo|Switch|AirPods|Chromebook|Surface|ThinkPad|Room|TV")
# "Jordan's iPhone", "Jordans-MacBook-Pro" (macOS turns "Jordan's" into "Jordans" in host names), "Jordan’s Room"
PERSON = re.compile(rf"^([A-Za-z]{{2,15}}?)(?:['’]s|s)? (?:{DEVICE_WORDS})\b|^([A-Za-z]{{2,15}})['’]s ", re.I)
NOT_NAMES = {"my", "the", "home", "office", "living", "guest", "kids", "new", "old", "work", "family", "bed", "main",
             "dining", "master", "android", "galaxy", "apple", "google", "smart", "basement", "kitchen", "garage"}


@dataclass
class Finding:
    severity: str  # high, medium, low, info
    title: str
    detail: str
    devices: list[Device]


def blob(d: Device) -> str:
    return " ".join([d.vendor, d.hostname, *d.names, *d.info.values(), *sorted(d.services)]).lower()


def kind(d: Device) -> str:
    if d.is_gateway:
        return ROUTER
    text = blob(d)
    for pattern, k in RULES:
        if re.search(pattern, text, re.I):
            return k
    if d.vendor.lower().startswith("apple") and 62078 in d.ports:
        return PHONE
    if d.private_mac and not d.vendor:
        return PHONE  # random per-network MACs are mostly phones, tablets and watches
    return UNKNOWN


def label(d: Device) -> str:
    """Best human name for a device."""
    for n in d.names:
        if n and not re.fullmatch(r"[0-9a-f:-]{12,}", n, re.I):
            return n
    if d.hostname:
        return re.sub(r"\.(lan|local|home|localdomain|station|router|fritz\.box|attlocal\.net)$", "", d.hostname)
    if d.info.get("model"):
        return d.info["model"]
    return ""


def display(d: Device) -> str:
    """label(), or "Hikvision camera" for a device that never said its name."""
    if label(d):
        return label(d)
    k = kind(d)
    noun = {SMART: "smart device", UNKNOWN: "device", PHONE: "phone", TV: "TV", PI: "board"}.get(k, k.lower())
    return f"{d.vendor} {noun}" if d.vendor else ""


def person(d: Device) -> str:
    """The first name a device announces, as in "Jordan's iPhone" or Jordans-MacBook-Pro."""
    for n in [*d.names, d.hostname.split(".")[0]]:
        m = PERSON.search(re.sub(r"[-_]+", " ", n or ""))
        if m:
            name = m.group(1) or m.group(2)
            if name.lower() not in NOT_NAMES:
                return name.capitalize()
    return ""


def findings(devices: list[Device]) -> list[Finding]:
    f: list[Finding] = []
    kinds = {d.ip: kind(d) for d in devices}
    others = [d for d in devices if not d.is_me]

    named = [d for d in others + [d for d in devices if d.is_me] if person(d)]
    if named:
        people = sorted({person(d) for d in named})
        f.append(Finding("medium", f"{len(named)} device{'s' * (len(named) != 1)} announce{'s' * (len(named) == 1)} "
                         f"whose {'they are' if len(named) != 1 else 'it is'}",
                         f"Names on the network: {', '.join(people)}. Anyone on this WiFi (a guest, a neighbor who "
                         "knows the password, everyone at a café if this isn't home) sees them too. Rename devices "
                         "to something that isn't your name.", named))
    telnet = [d for d in others if 23 in d.ports]
    if telnet:
        f.append(Finding("high", "Telnet is open", "Telnet sends passwords in plain text and is how botnets like Mirai "
                         "take over cameras and routers. Turn it off or replace the device.", telnet))
    cams = [d for d in others if kinds[d.ip] == CAMERA]
    rtsp = [d for d in others if 554 in d.ports]
    if cams or rtsp:
        f.append(Finding("medium", f"{len({d.ip for d in cams + rtsp})} camera{'s' * (len({d.ip for d in cams + rtsp}) != 1)} or video "
                         f"stream{'s' * (len({d.ip for d in cams + rtsp}) != 1)}", "Video streams (RTSP) "
                         "on the local network often have no password or the default one. Check each camera's app for "
                         "a stream password and firmware updates.", list({d.ip: d for d in cams + rtsp}.values())))
    upnp = [d for d in others if any("internetgatewaydevice" in s.lower() or "wanipconnection" in s.lower()
                                     for s in d.services)]
    if upnp:
        f.append(Finding("medium", "Your router lets devices open ports to the internet",
                         "UPnP port mapping is on: any device here (including a hacked camera or plug) can ask the "
                         "router to expose it to the internet without asking you. Turn UPnP off in the router's "
                         "settings unless a game console needs it.", upnp))
    remote = [d for d in others if set(d.ports) & {3389, 5900} and kinds[d.ip] != COMPUTER]
    if remote:
        f.append(Finding("medium", "Remote control is open on a non-computer", "Remote Desktop or VNC is listening on a "
                         "device that isn't a computer.", remote))
    admin = [d for d in others if d.is_gateway and 80 in d.ports and 443 not in d.ports]
    if admin:
        f.append(Finding("low", "The router's admin page has no HTTPS", "Its password crosses the WiFi unencrypted "
                         "every time you log in.", admin))
    smart = [d for d in others if kinds[d.ip] in (SMART, TV, SPEAKER, CAMERA)]
    if len(smart) >= 3:
        f.append(Finding("low", f"{len(smart)} smart devices share the network with your laptop and phone",
                         "If one gets hacked it can reach everything else here. Many routers can put smart devices on "
                         "a separate guest or IoT network.", smart))
    unknown = [d for d in others if kinds[d.ip] == UNKNOWN]
    if unknown:
        f.append(Finding("info", f"{len(unknown)} device{'s' * (len(unknown) != 1)} didn't say what "
                         f"{'they are' if len(unknown) != 1 else 'it is'}",
                         "Check them against your router's list of connected devices. Something you don't recognize "
                         "might be a neighbor on your WiFi.", unknown))
    private = [d for d in others if d.private_mac]
    if private:
        f.append(Finding("info", f"{len(private)} device{'s' * (len(private) != 1)} use a private MAC address",
                         "Good: phones and laptops now make up a MAC per network, so they can't be tracked across "
                         "networks by it.", private))
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(f, key=lambda x: order[x.severity])


def summary(devices: list[Device]) -> Counter:
    return Counter(kind(d) for d in devices if not d.is_me)
