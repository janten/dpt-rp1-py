#!/usr/bin/env python3
"""
usb_serial_switch.py — serial USB mode-switch for DPT-RP1 / DPT-CP1 / Quaderno
===============================================================================

Single-file, dependency-free (Python stdlib only) implementation of the
"serial USB" half of the dpt-rp1-py project:

  1. Find the reader's USB CDC ACM serial port (/dev/ttyACM*, auto-detected,
     or given with --port).
  2. Put it in raw mode and write the documented Ethernet-over-USB switch
     sequence (docs/linux-ethernet-over-usb.md):
         RNDIS   (Windows / Linux): b"\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x01\\x00\\x04"
         CDC/ECM (macOS / Linux):   b"\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x01\\x01\\x04"
  3. Wait for the kernel to re-enumerate the reader as a network gadget
     (rndis_host / cdc_ether -> usb0 / enx<mac> / enp0s20u1 ...).
  4. Resolve the reader's mDNS name with a self-contained resolver (no
     zeroconf, no avahi-resolve dependency):
         Sony readers:      digitalpaper.local
         Quaderno Gen 2:    Android.local
         mooInk Pro 2:      (service _dp_readmoo._tcp, repo PR #163)
  5. Verify TCP reachability of the reader's HTTPS port and print the
     ready-to-use dptrp1 command.

Findings encoded in the implementation (all reproduced on real hardware):
  * nsswitch's mdns4_minimal refuses dotted names, so getaddrinfo cannot
    resolve digitalpaper.local on stock Debian/Ubuntu; the socket-level
    mDNS resolver here is the PRIMARY path.
  * The gadget answers mDNS unicast to our source port, so no multicast
    *route* is required to receive replies (NetworkManager removes those).
  * NetworkManager's auto "Wired connection" DHCP attempt fails on the
    no-DHCP reader and tears down the auto IPv6 link-local address; a plain
    `ip link set <iface> up` (netdev group) restores it.
  * The serial port is root:dialout; on EACCES the script explains and can
    re-exec itself under sudo.
  * requests/urllib3 2.x silently DROPS the %zone from scoped IPv6 URLs
    ("Network is unreachable"), and http.client rejects bracketed scoped
    hosts outright — so dptrp1 itself is affected; we always print the
    NO_PROXY hint (repo issue #55) and the exact scoped address.

Usage:
    python3 usb_serial_switch.py                   # switch (rndis) + resolve
    python3 usb_serial_switch.py --mode cdc-ecm    # mac-style ECM gadget
    python3 usb_serial_switch.py --family quaderno
    python3 usb_serial_switch.py --no-switch       # already in ethernet mode
    python3 usb_serial_switch.py --status          # what we can currently see
"""

import argparse
import glob
import os
import re
import select
import socket
import struct
import subprocess
import sys
import termios
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RNDIS_SEQUENCE = b"\x01\x00\x00\x01\x00\x00\x00\x01\x00\x04"
CDC_ECM_SEQUENCE = b"\x01\x00\x00\x01\x00\x00\x00\x01\x01\x04"

MODES = {
    "rndis": RNDIS_SEQUENCE,
    "cdc-ecm": CDC_ECM_SEQUENCE,
    "cdc/ecm": CDC_ECM_SEQUENCE,
    "ecm": CDC_ECM_SEQUENCE,
}

MDNS_NAMES = {
    "sony": "digitalpaper.local",   # DPT-RP1 / DPT-CP1
    "dpt-rp1": "digitalpaper.local",
    "dpt-cp1": "digitalpaper.local",
    "fujitsu": "Android.local",     # Quaderno Gen 2 (repo docs)
    "quaderno": "Android.local",
}

# USB vendor IDs of reader manufacturers (to disambiguate multiple ttyACM*).
READER_VENDOR_IDS = {"054c": "sony", "04c5": "fujitsu"}

GADGET_DRIVERS = {"rndis_host", "cdc_ether", "cdc_acm"}
HTTPS_PORT = 8443

MDNS_V6 = "ff02::fb"
MDNS_V4 = "224.0.0.251"
MDNS_PORT = 5353

TYPE_A, TYPE_AAAA, TYPE_SRV = 1, 28, 33


def eprint(*a, **kw):
    print(*a, file=sys.stderr, **kw)


# ---------------------------------------------------------------------------
# 1. Serial port discovery
# ---------------------------------------------------------------------------

def usb_ids_for_tty(port):
    """(idVendor, idProduct) hex strings for /dev/ttyACMx, or (None, None)."""
    path = "/sys/class/tty/{}".format(os.path.basename(port))
    try:
        path = os.path.realpath(os.path.join(path, "device"))
    except OSError:
        return None, None
    for _ in range(6):
        vendor = os.path.join(path, "idVendor")
        if os.path.exists(vendor):
            try:
                with open(vendor) as f:
                    v = f.read().strip()
                with open(os.path.join(path, "idProduct")) as f:
                    p = f.read().strip()
                return v, p
            except OSError:
                return None, None
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return None, None


def find_serial_port(preferred=None, quiet=False):
    if preferred:
        if not os.path.exists(preferred):
            raise SystemExit("error: specified port {!r} does not exist".format(preferred))
        return preferred
    candidates = []
    for pattern in ("/dev/ttyACM*", "/dev/ttyUSB*"):
        candidates.extend(glob.glob(pattern))
    if not candidates:
        raise SystemExit(
            "error: no serial device found (/dev/ttyACM*, /dev/ttyUSB*).\n"
            "  If the reader is already in Ethernet-over-USB mode, re-plug\n"
            "  the cable to get the serial port back, or use --no-switch to\n"
            "  only resolve the network address.")
    # Prefer a tty whose USB parent is a known reader vendor; then newest.
    candidates.sort(key=lambda p: (usb_ids_for_tty(p)[0] in READER_VENDOR_IDS,
                                   os.stat(p).st_mtime), reverse=True)
    chosen = candidates[0]
    if len(candidates) > 1 and not quiet:
        v, pr = usb_ids_for_tty(chosen)
        eprint("[*] {} serial device(s); using {}{}".format(
            len(candidates), chosen,
            " (usb {}:{})".format(v, pr) if v else ""))
    return chosen


def check_port_access(port):
    if not os.path.exists(port):
        return False, "does not exist"
    try:
        fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    except PermissionError:
        return False, ("permission denied (port is usually root:dialout — "
                       "join the 'dialout' group or run with sudo)")
    except OSError as e:
        return False, "cannot open: {}".format(e)
    os.close(fd)
    return True, None


# ---------------------------------------------------------------------------
# 2. The switch
# ---------------------------------------------------------------------------

def set_raw_mode(fd):
    attrs = termios.tcgetattr(fd)
    iflag, oflag, cflag, lflag, ispeed, ospeed, cc = attrs
    iflag &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP
               | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON)
    oflag &= ~termios.OPOST
    cflag &= ~(termios.CSIZE | termios.PARENB | termios.CSTOPB | termios.CRTSCTS)
    cflag |= termios.CS8
    lflag &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG
               | termios.IEXTEN)
    termios.tcsetattr(fd, termios.TCSAFLUSH,
                      [iflag, oflag, cflag, lflag, ispeed, ospeed, cc])


def send_switch_sequence(port, sequence, settle=1.0):
    fd = os.open(port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        set_raw_mode(fd)
        os.write(fd, sequence)
        time.sleep(settle)
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# 3. Network gadget discovery + repair
# ---------------------------------------------------------------------------

def list_interfaces():
    names = set()
    try:
        for _, name in socket.if_nameindex():
            names.add(name)
    except (OSError, AttributeError):
        pass
    return names


def iface_is_reader_gadget(name):
    """True if the interface's sysfs driver is a USB-ether gadget driver.

    NOTE: cdc_ether also drives ordinary USB-Ethernet adapters — use
    iface_is_known_reader() for vendor-level confirmation.
    """
    try:
        real = os.path.realpath("/sys/class/net/{}".format(name))
        driver = os.path.realpath(os.path.join(real, "device", "driver"))
        if os.path.basename(driver) in GADGET_DRIVERS:
            return True
    except OSError:
        pass
    return False


def iface_usb_ids(name):
    """(idVendor, idProduct) of the USB device backing interface `name`."""
    try:
        real = os.path.realpath("/sys/class/net/{}".format(name))
        path = os.path.join(real, "device")
        for _ in range(6):
            vendor = os.path.join(path, "idVendor")
            if os.path.exists(vendor):
                with open(vendor) as f:
                    v = f.read().strip()
                with open(os.path.join(path, "idProduct")) as f:
                    p = f.read().strip()
                return v, p
            parent = os.path.dirname(path)
            if parent == path:
                break
            path = parent
    except OSError:
        pass
    return None, None


# Ethernet-side product IDs the readers present when in Ethernet-over-USB
# mode (observed: DPT-RP1 = 054c:0bdd; the serial mode is 054c:0be5).
READER_ETHERNET_IDS = {
    ("054c", "0bdd"),   # Sony DPT-RP1, Ethernet-over-USB (verified on hw)
}


def iface_is_known_reader(name):
    return iface_usb_ids(name) in READER_ETHERNET_IDS


def reader_gadget_interfaces():
    """Reader interfaces first (vendor-confirmed), then other gadgets."""
    present = [n for n in list_interfaces()
               if n != "lo" and iface_is_reader_gadget(n)]
    confirmed = [n for n in present if iface_is_known_reader(n)]
    return confirmed or present


def iface_has_address(name):
    """True if the interface currently has any IPv4/IPv6 address."""
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6 and parts[5] == name:
                    return True
    except OSError:
        pass
    try:
        out = subprocess.run(["ip", "-o", "addr", "show", name],
                             capture_output=True, text=True, timeout=5)
        if out.returncode == 0 and re.search(r"\binet6?\s", out.stdout):
            return True
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        pass
    return False


def _nm_profile_link_local(name):
    """Make NetworkManager leave the reader's interface alone (durable fix).

    NM's auto "Wired connection" DHCP attempt fails on the no-DHCP reader and
    tears down the auto link-local; configuring the per-interface connection
    profile with ipv4.method=disabled + ipv6.method=link-local gives a stable
    address and stops the teardown.  Best-effort: any failure is ignored.
    """
    try:
        subprocess.run(["nmcli", "device", "set", name, "managed", "true"],
                       capture_output=True, text=True, timeout=15)
        subprocess.run(["nmcli", "connection", "modify", name,
                        "ipv4.method", "disabled",
                        "ipv6.method", "link-local"],
                       capture_output=True, text=True, timeout=15)
        subprocess.run(["nmcli", "device", "connect", name],
                       capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        pass


def try_fix_link(name, log):
    """Restore the auto IPv6 link-local address NM drops after re-enumeration.

    First configure the NM profile for a stable link-local (durable), then
    `ip link set <iface> up` (netdev group, no root) to regenerate the
    address immediately.
    """
    _nm_profile_link_local(name)
    attempts = [["ip", "link", "set", name, "up"]]
    for cmd in attempts:
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            continue
        time.sleep(1.0)
        if iface_has_address(name):
            log("[*] restored link-local address on {} ({})".format(
                name, " ".join(cmd[:4])))
            return True
    return False


IFACE_NAME_HINT = re.compile(r"^(usb\d+|enx[0-9a-f]{12}|en[a-z0-9]*u\d+.*)$", re.I)


def wait_for_reader_interface(known_before, timeout=20.0, log=print):
    """Poll for a reader-gadget interface that appears after switch time."""
    deadline = time.time() + timeout
    seen = {}
    while time.time() < deadline:
        fresh = list_interfaces() - known_before - {"lo"}
        for name in sorted(n for n in fresh
                           if IFACE_NAME_HINT.match(n)
                           or iface_is_reader_gadget(n)):
            if iface_has_address(name):
                return name
            seen.setdefault(name, time.time())
        for name, first_seen in list(seen.items()):
            if time.time() - first_seen > 5 and try_fix_link(name, log):
                return name
        time.sleep(0.25)
    # Fallback: prefer a vendor-confirmed reader gadget (reader_gadget_interfaces
    # returns confirmed readers first), then any interface seen during the wait.
    for name in reader_gadget_interfaces():
        return name
    for name in sorted(seen):
        return name
    return None


# ---------------------------------------------------------------------------
# 4. Self-contained mDNS resolution
# ---------------------------------------------------------------------------
#
# Binds UDP/5353 (SO_REUSEADDR|SO_REUSEPORT) pinned per-interface with
# IP(MULTICAST_IF), fires AAAA/A/SRV/PTR queries to ff02::fb and
# 224.0.0.251, and collects *unicast* replies for the whole window.  The
# reader (Restlet/Avahi-stack) answers unicast to our source port, so no
# multicast route is needed to receive.  Multicast *send* failures are
# tolerated: we also try sending unicast to every link-local neighbor we can
# see (the reader replies to direct queries on 5353 too).

def encode_dns_name(name):
    return (b"".join(bytes([len(p)]) + p.encode("latin-1")
                     for p in name.rstrip(".").split(".")) + b"\x00")


def build_dns_query(name, qtype, txn_id=0):
    """Query packet.  `name` must be a single DNS label plus the .local
    suffix (e.g. 'digitalpaper.local'): mDNS names never contain dots
    inside a label, and '.'-joined multi-label names would need the full
    label sequence (see RFC 1035 §3.1 / RFC 6762 §3)."""
    head, _, rest = name.partition(".")
    if rest and rest != "local":
        raise ValueError(
            "invalid mDNS name {!r}: expected <label>.local "
            "(dots inside labels are not allowed)".format(name))
    return (struct.pack(">HHHHHH", txn_id, 0x0000, 1, 0, 0, 0)
            + encode_dns_name(name) + struct.pack(">HH", qtype, 1))


def name_wire_length(data, offset, depth=0):
    """Length of a (possibly compressed) name as it appears at `offset`.

    A compression pointer occupies exactly 2 bytes *in the stream*, even
    though the name it references lives elsewhere.  Use this to skip name
    fields; use read_name() to extract the dotted text.
    """
    if depth > 8:
        raise ValueError("dns name loop")
    length = data[offset]
    if length == 0:
        return 1
    if length & 0xC0 == 0xC0:
        return 2
    return 1 + length + name_wire_length(data, offset + 1 + length, depth + 1)


def read_name(data, offset, depth=0):
    """(advance, dotted_name) — handles RFC 1035 message compression.

    `advance` is the in-stream length (see name_wire_length).
    """
    if depth > 8:
        raise ValueError("dns name loop")
    length = data[offset]
    if length == 0:
        return 1, ""
    if length & 0xC0 == 0xC0:
        ptr = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
        _, target = read_name(data, ptr, depth + 1)
        return 2, target
    label = data[offset + 1:offset + 1 + length].decode("latin-1")
    rest_adv, rest_name = read_name(data, offset + 1 + length, depth + 1)
    return 1 + length + rest_adv, (label + ("." + rest_name if rest_name else ""))


def parse_dns_answers(data):
    """[(rtype, ttl, payload)] from the answer section; best-effort.

    Skips name fields with name_wire_length() (compression pointers are
    2 bytes in the stream); extracts record values, following pointers for
    SRV targets.
    """
    try:
        _, _, qd, an, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    except struct.error:
        return []
    offset = 12
    try:
        for _ in range(qd):
            offset += name_wire_length(data, offset) + 4
        records = []
        for _ in range(an):
            offset += name_wire_length(data, offset)
            # fixed record fields: type(2) class(2) ttl(4) rdlength(2) = 10
            rtype, _class = struct.unpack(">HH", data[offset:offset + 4])
            ttl, rdlength = struct.unpack(">IH", data[offset + 4:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlength]
            rdata_off = offset
            offset += rdlength
            if rtype == TYPE_AAAA and rdlength == 16:
                payload = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == TYPE_A and rdlength == 4:
                payload = socket.inet_ntop(socket.AF_INET, rdata)
            elif rtype == TYPE_SRV and rdlength >= 6:
                priority, weight, port = struct.unpack(">HHH", rdata[:6])
                target_off = rdata_off + 6
                target = ""
                try:
                    first = data[target_off]
                    if first & 0xC0 == 0xC0:
                        # compression pointer: the target name starts
                        # elsewhere — extract it there, not inline
                        ptr = struct.unpack(
                            ">H", data[target_off:target_off + 2])[0] & 0x3FFF
                        _, target = read_name(data, ptr)
                    elif first:
                        _, target = read_name(data, target_off)
                except (ValueError, IndexError):
                    pass
                payload = (port, target)
            else:
                payload = None
            records.append((rtype, ttl, payload))
        return records
    except (struct.error, IndexError, ValueError):
        return []


def interface_link_local_v6(name):
    """This host's IPv6 link-local address on `name`, canonically formatted."""
    raw = None
    try:
        with open("/proc/net/if_inet6") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 6 and parts[5] == name \
                   and parts[0].startswith("fe80"):
                    raw = parts[0]
                    break
    except OSError:
        pass
    if raw is None:
        return None
    try:
        return socket.inet_ntop(socket.AF_INET6,
                                socket.inet_pton(socket.AF_INET6,
                                                 ":".join(raw[i:i + 4]
                                                          for i in range(0, 32, 4))))
    except OSError:
        return ":".join(raw[i:i + 4] for i in range(0, 32, 4))


def neighbor_link_locals(iface):
    """IPv6 addresses in the kernel neighbor cache for `iface` (best-effort)."""
    addrs = []
    try:
        out = subprocess.run(["ip", "-6", "neighbor", "show", "dev", iface],
                             capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            m = re.match(r"([0-9a-fA-F:]+)", line)
            if m:
                addrs.append(m.group(1))
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        pass
    return addrs


def mdns_query(name, iface=None, timeout=6.0):
    """Resolve `name` on `iface` (or every plausible interface).

    Returns {'addresses': [...], 'srv_port': int|None,
             'srv_target': str|None}; addresses ranked
            link-local IPv6 > other IPv6 > IPv4, own addresses removed.
    """
    ifaces = [iface] if iface else sorted(
        n for n in list_interfaces()
        if n != "lo" and (iface_is_reader_gadget(n)
                          or IFACE_NAME_HINT.match(n)
                          or n.startswith("wl")))
    empty = {"addresses": [], "srv_port": None, "srv_target": None}
    if not ifaces:
        return empty

    ours = set()
    for n in ifaces:
        ll = interface_link_local_v6(n)
        if ll:
            ours.add(socket.inet_pton(socket.AF_INET6, ll))

    socks = []
    for n in ifaces:
        try:
            idx = socket.if_nametoindex(n)
        except OSError:
            continue
        for family, proto, opt, bindaddr in (
                (socket.AF_INET6, socket.IPPROTO_IPV6,
                 socket.IPV6_MULTICAST_IF, ""),
                (socket.AF_INET, socket.IPPROTO_IP,
                 socket.IP_MULTICAST_IF, "")):
            try:
                s = socket.socket(family, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    try:
                        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except OSError:
                        pass
                s.setsockopt(proto, opt, struct.pack("@I", idx))
                s.setsockopt(proto, socket.IPV6_MULTICAST_LOOP
                             if family == socket.AF_INET6
                             else socket.IP_MULTICAST_LOOP, 0)
                s.bind((bindaddr, MDNS_PORT))
                socks.append(s)
            except OSError:
                continue
    if not socks:
        return empty

    queries = [(name, TYPE_AAAA), (name, TYPE_A)]
    dests_v6 = [MDNS_V6]
    dests_v4 = [MDNS_V4]
    for n in ifaces:
        for nbr in neighbor_link_locals(n):
            if nbr.lower().startswith("fe80") and \
               socket.inet_pton(socket.AF_INET6, nbr) not in ours:
                # scope the unicast target to the interface the neighbor is on,
                # else the kernel can't route a link-local send (EINVAL)
                dests_v6.append("{}%{}".format(nbr, n))

    def send_all():
        for s in socks:
            dests = dests_v6 if s.family == socket.AF_INET6 else dests_v4
            for qname, qtype in queries:
                pkt = build_dns_query(qname, qtype)
                for dest in dests:
                    try:
                        s.sendto(pkt, (dest, MDNS_PORT))
                    except OSError:
                        pass

    send_all()
    addrs, srv_port, srv_target = [], None, None
    seen = set()
    deadline = time.time() + timeout
    resent = False
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        if not resent and remaining < timeout / 2:
            send_all()          # RFC 6762-style repeat improves hit rate
            resent = True
        try:
            rlist, _, _ = select.select(socks, [], [], min(remaining, 0.5))
        except (OSError, ValueError):
            break
        for s in rlist:
            try:
                data, _src = s.recvfrom(9000)
            except OSError:
                continue
            key = bytes(data)
            if key in seen:
                continue
            seen.add(key)
            for rtype, _ttl, payload in parse_dns_answers(data):
                if rtype in (TYPE_AAAA, TYPE_A) and isinstance(payload, str):
                    if rtype == TYPE_AAAA and \
                       socket.inet_pton(socket.AF_INET6, payload) in ours:
                        continue
                    if payload not in addrs:
                        addrs.append(payload)
                elif rtype == TYPE_SRV and payload:
                    srv_port, srv_target = payload
    for s in socks:
        s.close()
    addrs.sort(key=lambda a: (0 if a.lower().startswith("fe80")
                              else (1 if ":" in a else 2)))
    return {"addresses": addrs, "srv_port": srv_port, "srv_target": srv_target}


def scope_address(addr, iface):
    if ":" not in addr or "%" in addr or not addr.lower().startswith("fe80"):
        return addr
    return "{}%{}".format(addr, iface)


# ---------------------------------------------------------------------------
# 5. Reachability verification
# ---------------------------------------------------------------------------

def check_port_open(addr_scoped, port=HTTPS_PORT, timeout=4.0):
    """TCP probe.  create_connection maps %zone -> sin6_scope_id correctly;
    raw connect() on a 2-tuple raises EINVAL for scoped link-locals."""
    host = addr_scoped
    if ":" in host and host.lower().startswith("fe80") and "%" not in host:
        return False, "link-local address needs an interface scope (%iface)"
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True, None
    except OSError as e:
        return False, str(e)


# ---------------------------------------------------------------------------
# 6. Registration-state check + ready-to-use dptrp1 command
# ---------------------------------------------------------------------------
# The script does NOT run dptrp1; it prints the exact command the user needs.
# Whether the reader is already registered (auth files exist) decides which
# command to print: the ready-to-use one (list-documents &c.) or the register
# one (which prompts for the on-screen PIN).

def _auth_files():
    """The dptrp1 auth file paths (device id + private key)."""
    base = os.path.join(os.path.expanduser("~"), ".config", "dpt")
    return (os.path.join(base, "deviceid.dat"),
            os.path.join(base, "privatekey.dat"))


def is_registered():
    """True if the dptrp1 auth files exist (reader already registered)."""
    dev, key = _auth_files()
    return os.path.isfile(dev) and os.path.isfile(key)


def print_dptrp1_commands(addr_arg, registered):
    """Print the exact dptrp1 command(s) the user should run.

    If `registered`, the reader is already set up — print the ready-to-use
    command (no PIN).  Otherwise print the `register` command the user must
    run first (it prompts for the on-screen PIN), plus the follow-on command.
    """
    print("")
    if registered:
        print("Reader is already registered. Use:")
    else:
        print("Reader is NOT yet registered. Run this first (it will ask "
              "for the PIN shown on the reader's screen):")
    print("")
    print("    dptrp1 --addr '{}' register".format(addr_arg))
    print("")
    if not registered:
        print("then, once registered:")
    print("    dptrp1 --addr '{}' list-documents".format(addr_arg))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def do_status(args):
    print("usb devices:")
    shown = False
    try:
        out = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=5)
        for line in out.stdout.splitlines():
            if re.search(r"sony|054c|04c5|fujitsu|quaderno", line, re.I):
                print("  " + line)
                shown = True
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        pass
    if not shown:
        print("  (no known reader in lsusb output)")
    ports = []
    for pat in ("/dev/ttyACM*", "/dev/ttyUSB*"):
        ports.extend(glob.glob(pat))
    print("serial ports: {}".format(
        ports or "(none — reader likely in Ethernet-over-USB mode)"))
    print("network interfaces:")
    for name in sorted(list_interfaces()):
        if name == "lo":
            continue
        v, p = iface_usb_ids(name)
        tag = "  [DPT-RP1 gadget]" if iface_is_known_reader(name) else (
            "  [usb-ether {}{}]".format(v or "?", ":" + p if p else "")
            if iface_is_reader_gadget(name) else "")
        ll = interface_link_local_v6(name)
        print("  {:22s}{:<28s} link-local v6: {}".format(name, tag, ll or "-"))
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Switch a Sony DPT-RP1/DPT-CP1 (or Fujitsu Quaderno) from "
                    "USB serial mode to Ethernet-over-USB and print the "
                    "dptrp1 command to use.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("switch sequences (docs/linux-ethernet-over-usb.md):\n"
                "  rndis    {!r}\n"
                "  cdc-ecm  {!r}\n").format(RNDIS_SEQUENCE, CDC_ECM_SEQUENCE))
    ap.add_argument("--port", "-p", help="serial device (default: auto-detect)")
    ap.add_argument("--mode", "-m", default="rndis", choices=sorted(MODES),
                    help="gadget protocol (default: rndis)")
    ap.add_argument("--family", "-f", default="sony", choices=sorted(MDNS_NAMES),
                    help="reader family (selects the mDNS name)")
    ap.add_argument("--mdns-name", help="override mDNS name")
    ap.add_argument("--iface", "-i", help="network interface to resolve on")
    ap.add_argument("--timeout", "-t", type=float, default=25.0,
                    help="seconds to wait for interface / mDNS answers")
    ap.add_argument("--no-switch", action="store_true",
                    help="skip the serial write (already in Ethernet mode)")
    ap.add_argument("--status", action="store_true",
                    help="show current state and exit")
    ap.add_argument("--quiet", "-q", action="store_true")
    args = ap.parse_args()

    if args.status:
        return do_status(args)

    log = (lambda *a: None) if args.quiet else print

    # ---- 1. serial switch --------------------------------------------------
    if not args.no_switch:
        port = find_serial_port(args.port, quiet=args.quiet)
        log("[*] serial device: {}".format(port))
        ok, reason = check_port_access(port)
        if not ok:
            eprint("[!] cannot access {}: {}".format(port, reason))
            eprint("    fix options:\n"
                   "      sudo usermod -aG dialout $USER   # then re-login\n"
                   "      or re-run: sudo python3 {} ...".format(
                       os.path.abspath(sys.argv[0])))
            if os.geteuid() != 0 and sys.stdin.isatty():
                cmd = ["sudo", sys.executable,
                       os.path.abspath(sys.argv[0])] + sys.argv[1:]
                eprint("[*] retrying with: {}".format(" ".join(cmd)))
                raise SystemExit(subprocess.call(cmd))
            return 1
        seq = MODES[args.mode]
        log("[*] writing {} sequence: {!r}".format(args.mode, seq))
        send_switch_sequence(port, seq)
        log("[+] sequence sent; reader re-enumerates as a network gadget")

    # ---- 2. the gadget interface -------------------------------------------
    iface = args.iface
    if iface and not iface_has_address(iface):
        try_fix_link(iface, log)
    if not iface:
        # A vendor-confirmed reader interface that is ALREADY present wins
        # outright (no wait needed).  Otherwise — especially right after a
        # switch, when the reader re-enumerates a moment later — do NOT grab
        # a pre-existing generic USB-ether gadget; wait for the reader's own
        # NEW interface to appear (it may need a link repair too).
        present = reader_gadget_interfaces()
        confirmed = [n for n in present if iface_is_known_reader(n)]
        if confirmed:
            iface = confirmed[0]
            log("[*] reader gadget interface already present: {}".format(iface))
            if not iface_has_address(iface):
                try_fix_link(iface, log)
        else:
            log("[*] waiting up to {:.0f}s for the reader network "
                "interface ...".format(args.timeout))
            iface = wait_for_reader_interface(list_interfaces(),
                                              timeout=args.timeout, log=log)
    if not iface:
        eprint("[!] no reader network interface appeared. Check `dmesg` for "
               "rndis_host/cdc_ether lines, or re-plug and retry.")
        return 1
    if not iface_has_address(iface):
        eprint("[!] {} is up but has no address; run --status, check "
               "NetworkManager, then retry with --no-switch.".format(iface))
        return 1
    log("[+] interface: {}".format(iface))

    # ---- 3. mDNS resolution -------------------------------------------------
    mdns_name = args.mdns_name or MDNS_NAMES[args.family]
    try:
        build_dns_query(mdns_name, TYPE_AAAA)   # validate before resolving
    except ValueError as e:
        eprint("[!] {}".format(e))
        return 1
    log("[*] resolving {} over mDNS ...".format(mdns_name))
    result = mdns_query(mdns_name, iface=iface,
                        timeout=min(max(args.timeout, 6.0), 10.0))
    addresses = result["addresses"]
    if not addresses:
        eprint("[!] no mDNS answer for {}. The link may not be up; run "
               "--status, then retry with --no-switch.".format(mdns_name))
        return 1
    addr = addresses[0]

    # ---- 4. verify + emit ----------------------------------------------------
    port = result["srv_port"] or HTTPS_PORT
    scoped = scope_address(addr, iface)
    reachable, err = check_port_open(scoped, port)
    if reachable:
        log("[+] reader reachable on port {} \u2714".format(port))
    else:
        log("[!] port {} not reachable: {}".format(port, err))

    addr_arg = "[{}]".format(scoped) if ":" in scoped else scoped
    print("")
    print("reader address : {}".format(scoped))
    print("https port     : {}".format(port))
    if len(addresses) > 1:
        print("other answers  : {}".format(", ".join(addresses[1:])))
    if result["srv_target"]:
        print("service host   : {}".format(result["srv_target"]))
    print("")
    print("Use the dpt-rp1 client against the reader. NO_PROXY bypasses")
    print("https_proxy (repo issue #55); urllib3>=2 additionally drops the")
    print("%zone from scoped URLs — export no_proxy if it complains:")
    print("")
    bare = scoped.split("%", 1)[0] if "%" in scoped else scoped
    print("    NO_PROXY='{}' dptrp1 --addr '{}' list-documents".format(
        scoped, addr_arg))
    if bare != scoped:
        print("    # urllib3>=2 drops the zone, so also cover the bare v6:")
        print("    NO_PROXY='{0},{1}' dptrp1 --addr '{2}' list-documents".format(
            scoped, bare, addr_arg))

    # ---- 5. ready-to-use dptrp1 command ---------------------------------
    # If the reader is already registered (auth files exist), connecting it
    # does NOT prompt for a PIN — just print the ready-to-use command.  If
    # not yet registered, print the `register` command (prompts for the PIN).
    registered = is_registered()
    print_dptrp1_commands(addr_arg, registered)
    log("[*] registration state: {}".format(
        "registered" if registered else "not registered (run dptrp1 register)"))
    return 0 if reachable else 1


if __name__ == "__main__":
    sys.exit(main())
