import argparse
import base64
import sys
import json

import dptrp1

def do_screenshot():
    pass

def do_wifi_list(d):
    data = d.get_endpoint('/system/configs/wifi_accesspoints').json()
    res  = []
    for ap in data['aplist']:
        ap['ssid_plain'] = base64.b64decode(ap['ssid']).decode('utf-8', errors='replace')
        res.append(ap)
    print(json.dumps(res, indent=2))

def do_wifi_scan(d):
    data = d.post_endpoint('/system/controls/wifi_accesspoints/scan').json()
    res  = []
    for ap in data['aplist']:
        ap['ssid_plain'] = base64.b64decode(ap['ssid']).decode('utf-8', errors='replace')
        res.append(ap)
    print(json.dumps(res, indent=2))

def do_wifi(d):
    print(json.dumps(d.get_endpoint('/system/configs/wifi').json(), indent=2))

def do_conf_wifi(d):
    cnf = {
        "ssid": base64.b64encode(b'YYY').decode('utf-8'),
        "security": "nonsec", # psk, nonsec, XXX
        # "passwd": "XXX",
        "dhcp": "false",
        "static_address": "172.20.123.4",
        "gateway": "172.20.123.160",
        "network_mask": "24",
        "dns1": "172.20.123.160",
        "dns2": "",
        "proxy": "false"
    }
    res = d.put_endpoint('/system/controls/wifi_accesspoints/register', data=cnf)
    try:
        print(res.json())
    except:
        print(res.text)

_commands = {
    "screenshot": do_screenshot,
    "wifi-list": do_wifi_list,
    "wifi-scan": do_wifi_scan,
    "wifi-conf": do_conf_wifi,
    "wifi": do_wifi,
}

def build_parser():
    p = argparse.ArgumentParser(description="Remote control for Sony DPT RP1")
    p.add_argument('--addr', default='172.20.123.4', help="Address of device to be controlled")
    p.add_argument('command', help='Command to run', choices=sorted(_commands.keys()))
    return p

if __name__ == "__main__":
    args = build_parser().parse_args()
    print('arguments', args)

    d = dptrp1.DigitalPaper(addr=args.addr)
    d.authenticate()

    assert args.command in _commands

    _commands[args.command](d)
