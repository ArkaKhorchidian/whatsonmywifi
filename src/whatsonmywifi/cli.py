"""whatsonmywifi: every device on your network, what it is, and what it gives away."""
from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __version__
from .classify import (CAMERA, COMPUTER, CONSOLE, NAS, PHONE, PI, PRINTER, ROUTER, SMART, SPEAKER, TV, UNKNOWN,
                       display, findings, kind, label, person, summary)
from .net import Device, discover, subnet

COLOR = {ROUTER: "#87afff", PHONE: "#5fd7ff", COMPUTER: "#5fd7ff", TV: "#d787ff", SPEAKER: "#d787ff",
         CAMERA: "#ff5f5f", PRINTER: "#afaf87", SMART: "#ffaf5f", CONSOLE: "#d787ff", NAS: "#87d787",
         PI: "#87d787", UNKNOWN: "#ff5faf"}
SEV = {"high": ("HIGH", "bold #ff5f5f"), "medium": ("MED", "bold #ffaf5f"), "low": ("LOW", "#87afff"),
       "info": ("INFO", "dim")}
PLURAL = {PHONE: "phones or tablets", TV: "TVs or streamers", NAS: "storage boxes", PI: "single-board computers",
          SMART: "smart home devices", UNKNOWN: "unknown"}


def plural(k: str, n: int) -> str:
    if n == 1:
        return {TV: "TV or streamer", UNKNOWN: "unknown device"}.get(k, k.lower())
    return PLURAL.get(k, k.lower() + "s")


def share_line(devices: list[Device]) -> str:
    c = summary(devices)
    n = sum(c.values())
    bits = [f"{c[k]} {plural(k, c[k])}" for k in (CAMERA, TV, SPEAKER, SMART) if c[k]]
    tail = f" and {c[UNKNOWN]} I can't identify" if c[UNKNOWN] else ""
    lead = ", ".join(bits)
    return f"There are {n} devices on my WiFi{': ' + lead if lead else ''}{tail}. What's on yours? uvx whatsonmywifi"


def notes(d: Device) -> Text:
    t = Text()
    if d.is_me:
        t.append("this computer  ", "bold")
    if d.is_gateway:
        t.append("your router  ", "bold")
    who = person(d)
    if who:
        t.append(f"named after {who}  ", "#ffaf5f")
    for p in [p for p in d.ports if p not in (80, 443, 8080, 8443, 62078)][:3]:
        t.append(f"{d.ports[p]}  ", "#ff5f5f" if p in (23, 554, 3389, 5900) else "dim")
    return t


def render(devices: list[Device], network: str, console: Console) -> None:
    c = summary(devices)
    n = sum(c.values())
    head = Text.assemble((f"{n}", "bold #5fd7ff"), f" other device{'s' * (n != 1)} on your network ",
                         (f"({network})", "dim"))
    kinds = Text()
    for k, cnt in c.most_common():
        kinds.append(f"{cnt} {plural(k, cnt)}", COLOR[k]).append("   ")
    parts: list = [head, kinds, Text("")]

    t = Table(box=None, header_style="dim", padding=(0, 2), expand=True)
    t.add_column("Device", no_wrap=True, overflow="ellipsis", max_width=28)
    t.add_column("What", no_wrap=True)
    t.add_column("Maker", max_width=16, no_wrap=True, overflow="ellipsis")
    t.add_column("IP", no_wrap=True, style="dim")
    t.add_column("Notes", ratio=1, no_wrap=True, overflow="ellipsis")
    order = [ROUTER, COMPUTER, PHONE, TV, SPEAKER, CONSOLE, CAMERA, SMART, PRINTER, NAS, PI, UNKNOWN]
    for d in sorted(devices, key=lambda d: (order.index(kind(d)), not d.is_me, display(d).lower() or "~")):
        k = kind(d)
        t.add_row(Text(display(d) or "(no name)", "bold" if label(d) else "dim"), Text(k, COLOR[k]),
                  d.vendor or d.info.get("manufacturer", "") or ("private MAC" if d.private_mac else "?"), d.ip,
                  notes(d))
    parts += [t, Text("")]

    ft = Table.grid(padding=(0, 2))
    ft.add_column(no_wrap=True)
    ft.add_column(ratio=1)
    for f in findings(devices):
        lab, style = SEV[f.severity]
        names = ", ".join(label(d) or (f"{display(d)} ({d.ip})" if display(d) else d.ip) for d in f.devices[:5])
        names += f" and {len(f.devices) - 5} more" if len(f.devices) > 5 else ""
        if ft.row_count:
            ft.add_row("", "")
        ft.add_row(Text(lab, style), Text.assemble((f.title, "bold"), "\n" + f.detail, ("\n" + names, "dim")))
    parts.append(ft)
    console.print(Panel(Group(*parts), title="[bold]What's on my WiFi?[/]", border_style="#5fd7ff", padding=(1, 2)))
    console.print(Text("  Share: ", "dim") + Text(share_line(devices), "italic"))
    console.print()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="whatsonmywifi",
                                 description="Every device on your network, what it is, and what it gives away. "
                                             "No root, nothing installed, nothing sent off your network.")
    ap.add_argument("--prefix", type=int, default=24, help="subnet size to scan around your IP (default /24)")
    ap.add_argument("--no-ports", action="store_true", help="skip checking a few well-known ports on each device")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("-V", "--version", action="version", version=f"whatsonmywifi {__version__}")
    a = ap.parse_args(argv)
    if not 16 <= a.prefix <= 30:
        ap.error("--prefix must be between 16 and 30")
    console = Console(stderr=a.json, highlight=False)
    with console.status("Looking around your network…") as status:
        devices = discover(a.prefix, not a.no_ports, progress=status.update)
    me = next((d for d in devices if d.is_me), None)
    network = str(subnet(me.ip, a.prefix)) if me else "?"
    if a.json:
        print(json.dumps([{"ip": d.ip, "mac": d.mac, "vendor": d.vendor, "kind": kind(d), "name": label(d),
                           "hostname": d.hostname, "announces": d.names, "services": sorted(d.services),
                           "info": d.info, "ports": d.ports, "private_mac": d.private_mac, "is_me": d.is_me,
                           "is_router": d.is_gateway} for d in devices], indent=2))
        return 0
    if len(devices) <= 1:
        console.print("No other devices answered. You may be on a network that isolates clients (most public and "
                      "office WiFi does), or a VPN is on.")
        return 0
    render(devices, network, console)
    return 0


if __name__ == "__main__":
    sys.exit(main())
