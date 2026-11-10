import io
import json
import struct

from rich.console import Console

from whatsonmywifi import classify, cli, net
from whatsonmywifi.classify import CAMERA, PHONE, PRINTER, ROUTER, SMART, SPEAKER, TV, UNKNOWN
from whatsonmywifi.net import Device


def test_parse_arp_all_platforms():
    linux = ("192.168.1.1 dev wlan0 lladdr 3c:37:86:aa:bb:cc REACHABLE\n"
             "192.168.1.20 dev wlan0 lladdr DA:A1:19:01:02:03 STALE\n"
             "192.168.1.30 dev wlan0  FAILED\n")
    mac = ("? (192.168.1.1) at 3c:37:86:aa:bb:cc on en0 ifscope [ethernet]\n"
           "? (192.168.1.21) at 0:1e:c2:a:b:c on en0 ifscope [ethernet]\n"
           "? (192.168.1.31) at (incomplete) on en0 ifscope [ethernet]\n"
           "? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n")
    win = ("Interface: 192.168.1.5 --- 0x7\n  Internet Address      Physical Address      Type\n"
           "  192.168.1.1           3c-37-86-aa-bb-cc     dynamic\n"
           "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n")
    proc = ("IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         3c:37:86:aa:bb:cc     *        eth0\n")
    assert net.parse_arp(linux) == {"192.168.1.1": "3c:37:86:aa:bb:cc", "192.168.1.20": "da:a1:19:01:02:03"}
    assert net.parse_arp(mac) == {"192.168.1.1": "3c:37:86:aa:bb:cc", "192.168.1.21": "00:1e:c2:0a:0b:0c"}
    assert net.parse_arp(win) == {"192.168.1.1": "3c:37:86:aa:bb:cc"}
    assert net.parse_arp(proc) == {"192.168.1.1": "3c:37:86:aa:bb:cc"}


def name(s: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in s.split(".")) + b"\x00"


def rr(n: bytes, rtype: int, rdata: bytes) -> bytes:
    return n + struct.pack(">HHIH", rtype, 0x8001, 120, len(rdata)) + rdata


def cast_response() -> bytes:
    """What a Chromecast answers to a _googlecast._tcp PTR query (with a compression pointer)."""
    q = name("_googlecast._tcp.local")
    inst = name("Living Room TV._googlecast._tcp.local")
    txt = b"".join(bytes([len(x)]) + x for x in [b"md=Chromecast Ultra", b"fn=Living Room TV", b"id=abc"])
    answers = [rr(b"\xc0\x0c", 12, inst),  # pointer to the question name
               rr(inst, 16, txt),
               rr(inst, 33, struct.pack(">HHH", 0, 0, 8009) + name("abc123.local")),
               rr(name("abc123.local"), 1, bytes([192, 168, 1, 40]))]
    return struct.pack(">HHHHHH", 0, 0x8400, 1, 1, 0, 3) + q + struct.pack(">HH", 12, 1) + b"".join(answers)


def test_dns_query_and_parse():
    q = net.dns_query(["_googlecast._tcp.local", "_ipp._tcp.local"])
    assert struct.unpack(">H", q[4:6])[0] == 2 and b"\x0b_googlecast" in q
    recs = net.parse_dns(cast_response())
    assert ("_googlecast._tcp.local", 12, "Living Room TV._googlecast._tcp.local") in recs
    assert any(t == 16 and v["md"] == "Chromecast Ultra" for _, t, v in recs)
    assert ("abc123.local", 1, "192.168.1.40") in recs
    found = {}
    net.absorb_mdns(found, "192.168.1.40", recs)
    d = found["192.168.1.40"]
    assert d["names"] == ["Living Room TV"] and d["services"] == {"_googlecast._tcp"}
    assert d["info"]["model"] == "Chromecast Ultra" and d["info"]["host"] == "abc123"
    assert net.parse_dns(b"\x00\x01garbage") == []


def test_instance_label():
    assert net.instance_label("A1B2C3D4E5F6@Kitchen._raop._tcp.local", "_raop._tcp.local") == "Kitchen"


def test_ssdp_and_upnp():
    h = net.parse_ssdp(b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\nSERVER: Linux UPnP/1.0\r\n"
                       b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n")
    assert h["location"].endswith("desc.xml") and "InternetGatewayDevice" in h["st"]
    xml = (b'<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
           b"<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><friendlyName>Bedroom TV"
           b"</friendlyName><manufacturer>Samsung</manufacturer><modelName>QN55Q60</modelName></device></root>")
    assert net.parse_upnp_xml(xml) == {"deviceType": "urn:schemas-upnp-org:device:MediaRenderer:1",
                                       "friendlyName": "Bedroom TV", "manufacturer": "Samsung", "modelName": "QN55Q60"}
    assert net.parse_upnp_xml(b"<nope") == {}


def test_vendor_and_private_mac():
    assert net.vendor("b8:27:eb:12:34:56").startswith("Raspberry Pi")
    assert net.vendor("") == ""
    assert Device("x", "da:a1:19:00:00:01").private_mac and not Device("x", "b8:27:eb:00:00:01").private_mac


def home_network() -> list[Device]:
    return [
        Device("192.168.1.1", "3c:37:86:00:00:01", "NETGEAR", is_gateway=True, ports={80: "HTTP", 53: "DNS"},
               services={"urn:schemas-upnp-org:device:InternetGatewayDevice:1"}),
        Device("192.168.1.5", "f0:18:98:00:00:02", "Apple", "Jordans-MacBook-Pro.lan", is_me=True),
        Device("192.168.1.20", "da:a1:19:00:00:03", "", "", ["Jordan’s iPhone"], {"_companion-link._tcp"}),
        Device("192.168.1.40", "54:60:09:00:00:04", "Google", "", ["Living Room TV"], {"_googlecast._tcp"},
               {"model": "Chromecast Ultra"}),
        Device("192.168.1.41", "48:a6:b8:00:00:05", "Sonos", "", ["Kitchen"], {"_sonos._tcp"}),
        Device("192.168.1.50", "c0:56:e3:00:00:06", "Hangzhou Hikvision Digital", "", [], set(), {},
               {554: "RTSP video", 23: "Telnet"}),
        Device("192.168.1.60", "ec:fa:bc:00:00:07", "Espressif", "", [], set()),
        Device("192.168.1.61", "00:17:88:00:00:08", "Philips Lighting", "", ["Hue Bridge"], {"_hue._tcp"}),
        Device("192.168.1.70", "30:05:5c:00:00:09", "Brother Industries", "", ["Brother HL-L2350DW"],
               {"_ipp._tcp"}),
        Device("192.168.1.90", "00:00:00:00:00:00", "", "", []),
    ]


def test_kinds():
    k = {d.ip: classify.kind(d) for d in home_network()}
    assert k["192.168.1.1"] == ROUTER and k["192.168.1.20"] == PHONE and k["192.168.1.40"] == TV
    assert k["192.168.1.41"] == SPEAKER and k["192.168.1.50"] == CAMERA and k["192.168.1.61"] == SMART
    assert k["192.168.1.60"] == SMART and k["192.168.1.70"] == PRINTER and k["192.168.1.90"] == UNKNOWN


def test_person_names():
    p = lambda **kw: classify.person(Device("x", **kw))
    assert p(hostname="Jordans-MacBook-Pro.lan") == "Jordan"
    assert p(names=["Amy's iPad"]) == "Amy" and p(names=["Sam’s Room"]) == "Sam"
    assert p(names=["Living Room TV"]) == "" and p(hostname="android-3f2a91") == "" and p(names=["Kitchen"]) == ""


def test_findings():
    f = {x.title: x for x in classify.findings(home_network())}
    titles = list(f)
    assert titles[0] == "Telnet is open"
    assert "2 devices announce whose they are" in f and "Jordan" in f["2 devices announce whose they are"].detail
    assert "1 camera or video stream" in f
    assert "Your router lets devices open ports to the internet" in f
    assert "The router's admin page has no HTTPS" in f
    assert any(t.startswith("1 device didn't say") for t in titles)


def test_render_and_share():
    c = Console(width=140, record=True, file=io.StringIO())
    cli.render(home_network(), "192.168.1.0/24", c)
    out = c.export_text()
    assert "9 other devices on your network" in out and "Living Room TV" in out and "named after Jordan" in out
    assert "uvx whatsonmywifi" in out
    assert cli.share_line(home_network()).startswith("There are 9 devices on my WiFi: 1 camera, 1 TV or streamer")


def test_main_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "discover", lambda prefix, ports, progress: home_network())
    assert cli.main(["--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 10 and {d["kind"] for d in data} >= {"Router", "Camera"}
    monkeypatch.setattr(cli, "discover", lambda prefix, ports, progress: home_network()[1:2])
    assert cli.main([]) == 0
    assert "isolates clients" in capsys.readouterr().out


def test_discover_merges_sources(monkeypatch):
    """discover() with every network call replaced: checks how ARP, mDNS, SSDP, DNS and ports are combined."""
    monkeypatch.setattr(net, "my_ip", lambda: "192.168.1.5")
    monkeypatch.setattr(net, "gateway", lambda: "192.168.1.1")
    monkeypatch.setattr(net, "nudge", lambda n, me: None)
    monkeypatch.setattr(net.time, "sleep", lambda s: None)
    monkeypatch.setattr(net, "arp_table", lambda: {"192.168.1.1": "3c:37:86:00:00:01",
                                                   "192.168.1.40": "54:60:09:00:00:04", "10.0.0.9": "aa:aa:aa:aa:aa:aa"})
    recs = net.parse_dns(cast_response())
    monkeypatch.setattr(net, "mdns", lambda: (lambda f: (net.absorb_mdns(f, "192.168.1.40", recs), f)[1])({}))
    monkeypatch.setattr(net, "ssdp", lambda: {"192.168.1.1": {
        "st": {"urn:schemas-upnp-org:device:InternetGatewayDevice:1"}, "server": "Linux UPnP/1.0", "location": "",
        "friendlyName": "Home Router", "manufacturer": "NETGEAR", "modelName": "R7000"}})
    monkeypatch.setattr(net, "reverse_dns", lambda ip: {"192.168.1.5": "laptop.lan"}.get(ip, ""))
    monkeypatch.setattr(net, "open_ports", lambda ip: {80: "HTTP"} if ip.endswith(".1") else {})
    devs = net.discover()
    assert [d.ip for d in devs] == ["192.168.1.1", "192.168.1.5", "192.168.1.40"]  # 10.0.0.9 is another subnet
    gw, me, tv = devs
    assert gw.is_gateway and gw.names == ["Home Router"] and gw.info["model"] == "R7000" and gw.ports == {80: "HTTP"}
    assert me.is_me and me.hostname == "laptop.lan"
    assert tv.names == ["Living Room TV"] and tv.info["model"] == "Chromecast Ultra" and classify.kind(tv) == TV
