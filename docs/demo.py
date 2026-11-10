"""Run whatsonmywifi against a made-up home network (no real scanning). Used to record the README GIF."""
import sys
import time

from whatsonmywifi import cli
from whatsonmywifi.net import Device

D = Device
NETWORK = [
    D("192.168.1.1", "3c:37:86:10:20:01", "NETGEAR", "routerlogin.net", ["Nighthawk R7000"],
      {"urn:schemas-upnp-org:device:InternetGatewayDevice:1"}, {"model": "R7000"}, {80: "HTTP", 5000: "UPnP/HTTP"},
      is_gateway=True),
    D("192.168.1.12", "f0:18:98:10:20:02", "Apple", "Jordans-MacBook-Pro.lan", [], {"_companion-link._tcp"}, is_me=True),
    D("192.168.1.14", "da:a1:19:10:20:03", "", "", ["Jordan’s iPhone"], {"_companion-link._tcp"}, ports={62078: "iPhone sync"}),
    D("192.168.1.15", "ae:4f:22:10:20:04", "", "", ["Maya's iPad"], {"_companion-link._tcp"}),
    D("192.168.1.16", "f2:c1:7a:10:20:05", "", "android-8c1f2d3a9b", []),
    D("192.168.1.20", "54:60:09:10:20:06", "Google", "", ["Living Room TV"], {"_googlecast._tcp"},
      {"model": "Chromecast with Google TV"}, {8008: "Cast"}),
    D("192.168.1.21", "b0:a7:37:10:20:07", "Roku", "", ["Bedroom Roku"], {"urn:dial-multiscreen-org:device:dial:1"}),
    D("192.168.1.22", "48:a6:b8:10:20:08", "Sonos", "", ["Kitchen"], {"_sonos._tcp", "_spotify-connect._tcp"}),
    D("192.168.1.23", "f0:81:73:10:20:09", "Amazon", "", ["Jordan's Echo Dot"], {"_amzn-alexa._tcp"}),
    D("192.168.1.30", "c0:56:e3:10:20:0a", "Hikvision", "", [], set(), {},
      {80: "HTTP", 554: "RTSP video", 23: "Telnet"}),
    D("192.168.1.31", "2c:aa:8e:10:20:0b", "Wyze", "", [], set(), {}, {554: "RTSP video"}),
    D("192.168.1.40", "00:17:88:10:20:0c", "Philips", "", ["Hue Bridge"], {"_hue._tcp", "_hap._tcp"}),
    D("192.168.1.41", "ec:fa:bc:10:20:0d", "Espressif", "", [], set()),
    D("192.168.1.42", "50:02:91:10:20:0e", "Espressif", "", [], set()),
    D("192.168.1.43", "18:b4:30:10:20:0f", "Nest", "", ["Hallway Thermostat"], set()),
    D("192.168.1.50", "30:05:5c:10:20:10", "Brother", "", ["Brother HL-L2350DW"], {"_ipp._tcp"}, {},
      {80: "HTTP", 9100: "Printing"}),
    D("192.168.1.60", "70:9e:29:10:20:11", "Sony", "", ["PS5"], set()),
    D("192.168.1.77", "a4:cf:12:10:20:12", "", "", [], set()),
]


def fake_discover(prefix, ports, progress):
    progress("Looking for devices on 192.168.1.0/24…")
    time.sleep(1.5)
    progress(f"Asking {len(NETWORK)} devices what they are…")
    time.sleep(1.2)
    return NETWORK


cli.discover = fake_discover
sys.exit(cli.main(sys.argv[1:]))
