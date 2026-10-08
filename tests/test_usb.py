import socket
import struct
import sys

import pytest

if sys.platform == "win32":
    pytest.skip("The USB helper requires POSIX termios", allow_module_level=True)

from dptrp1.cli.dptusb import build_dns_query, parse_dns_answers, read_name, scope_address


@pytest.mark.parametrize("name", ["digitalpaper.local", "Android.local"])
def test_mdns_query_requests_expected_record(name):
    query = build_dns_query(name, 28, txn_id=42)
    assert struct.unpack(">HHHHHH", query[:12]) == (42, 0, 1, 0, 0, 0)
    consumed, decoded = read_name(query, 12)
    assert decoded == name
    assert struct.unpack(">HH", query[12 + consumed:]) == (28, 1)


def test_dns_answers_with_compressed_names_and_srv_target():
    query = build_dns_query("digitalpaper.local", 28)
    header = struct.pack(">HHHHHH", 0, 0x8400, 1, 3, 0, 0)

    def record(kind, data):
        return b"\xc0\x0c" + struct.pack(">HHIH", kind, 1, 120, len(data)) + data

    packet = header + query[12:]
    packet += record(1, socket.inet_aton("192.0.2.1"))
    packet += record(28, socket.inet_pton(socket.AF_INET6, "fe80::1"))
    packet += record(33, struct.pack(">HHH", 0, 0, 8443) + b"\xc0\x0c")
    assert parse_dns_answers(packet) == [
        (1, 120, "192.0.2.1"), (28, 120, "fe80::1"), (33, 120, (8443, "digitalpaper.local")),
    ]


@pytest.mark.parametrize("packet", [b"", b"\x00" * 11, struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)])
def test_truncated_dns_packets_are_ignored(packet):
    assert parse_dns_answers(packet) == []


def test_recursive_dns_pointer_is_rejected():
    with pytest.raises(ValueError, match="dns name loop"):
        read_name(b"\xc0\x00", 0)


@pytest.mark.parametrize("name", ["digitalpaper.example.com", "reader.with.dots.local"])
def test_non_local_mdns_names_are_rejected(name):
    with pytest.raises(ValueError, match="invalid mDNS name"):
        build_dns_query(name, 28)


@pytest.mark.parametrize("address,expected", [
    ("fe80::1", "fe80::1%usb0"),
    ("fe80::1%eth0", "fe80::1%eth0"),
    ("2001:db8::1", "2001:db8::1"),
    ("192.0.2.1", "192.0.2.1"),
])
def test_ipv6_scope_is_added_only_where_needed(address, expected):
    assert scope_address(address, "usb0") == expected
