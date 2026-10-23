import base64
import hmac
import json
from http.cookies import SimpleCookie

import pytest
import requests
from unittest.mock import Mock
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from dptrp1.cli.dptrp1 import do_download
from dptrp1.dptrp1 import DigitalPaper, ResolveObjectFailed
from dptrp1.pyDH import DiffieHellman


BASE = "https://reader.example:8443"
ROOT = {"entry_id": "root", "entry_type": "folder", "entry_path": "Document"}
FOLDER = {"entry_id": "notes", "entry_type": "folder", "entry_path": "Document/Notes"}
DOCUMENT = {"entry_id": "pdf", "entry_type": "document", "entry_path": "Document/Notes/sample.pdf"}


@pytest.mark.parametrize("address,expected", [
    ("192.0.2.1", "https://192.0.2.1:8443"),
    ("reader.example:9443", "https://reader.example:9443"),
    ("[fe80::1%usb0]", "https://[fe80::1%usb0]:8443"),
])
def test_device_addresses(address, expected):
    client = DigitalPaper(addr=address)
    try:
        assert client.base_url == expected
    finally:
        client.session.close()


def test_authentication_signs_nonce_and_sends_cookie(device, http):
    key = RSA.generate(2048)
    nonce = "reader-provided-nonce"
    http.get(BASE + "/auth/nonce/test-client", json={"nonce": nonce})

    def authenticate(request):
        payload = json.loads(request.body)
        assert payload["client_id"] == "test-client"
        signature = base64.b64decode(payload["nonce_signed"])
        pkcs1_15.new(key.public_key()).verify(SHA256.new(nonce.encode()), signature)
        return 204, {"Set-Cookie": "Credentials=test-session; Path=/"}, ""

    def list_entries(request):
        assert SimpleCookie(request.headers["Cookie"])["Credentials"].value == "test-session"
        return 200, {}, json.dumps({"entry_list": [ROOT, DOCUMENT]})

    http.add_callback("PUT", BASE + "/auth", callback=authenticate)
    http.add_callback("GET", BASE + "/documents2?entry_type=all", callback=list_entries)
    assert device.authenticate("test-client", key.export_key()).status_code == 204
    assert device.list_all() == [ROOT, DOCUMENT]


def register_folder_responses(http):
    http.get(BASE + "/resolve/entry/path/Document", json=ROOT)
    http.get(BASE + "/folders/root/entries2", json={"entry_list": [FOLDER]})
    http.get(BASE + "/folders/notes/entries2", json={"entry_list": [DOCUMENT]})


def test_document_listing_traverses_nested_folders(device, http):
    register_folder_responses(http)
    assert device.list_documents() == [ROOT, FOLDER, DOCUMENT]


def test_traversal_falls_back_when_device_truncates_results(device, http):
    http.get(BASE + "/documents2?entry_type=all", json={"count": 3, "entry_list": [ROOT]})
    register_folder_responses(http)
    assert device.traverse_folder("Document") == [ROOT, FOLDER, DOCUMENT]


def test_complete_listing_uses_fast_traversal(device, http):
    http.get(BASE + "/documents2?entry_type=all", json={
        "count": 3, "entry_list": [ROOT, FOLDER, DOCUMENT],
    })
    assert device.traverse_folder("Document/Notes") == [FOLDER, DOCUMENT]
    assert len(http.calls) == 1


def test_download_encodes_remote_path_and_preserves_binary_content(device, http, tmp_path):
    path = "Document/café + notes.pdf"
    http.get(BASE + "/resolve/entry/path/Document%2Fcaf%C3%A9+%2B+notes.pdf", json=DOCUMENT)
    content = b"%PDF-1.4\n\x00\xff\r\n%%EOF\n"
    http.get(BASE + "/documents/pdf/file", body=content, content_type="application/pdf")
    destination = tmp_path / "download.pdf"
    do_download(device, path, str(destination))
    assert destination.read_bytes() == content


def test_missing_document_raises_resolution_error(device, http):
    http.get(BASE + "/resolve/entry/path/Document%2Fmissing.pdf",
             status=404, json={"message": "Entry not found"})
    with pytest.raises(ResolveObjectFailed, match="Entry not found"):
        device.download("Document/missing.pdf")


@pytest.mark.parametrize("sign_byte", [b"", b"\x00"], ids=["256-byte-key", "java-sign-byte"])
def test_registration_preserves_peer_public_key_bytes(device, http, sign_byte, capsys):
    # Java may prepend a sign byte to its 2048-bit BigInteger. That byte must
    # remain in the transcript HMAC even though both encodings mean the same int.
    group = DiffieHellman()
    peer_private = 12345
    while True:
        public = pow(group.g, peer_private, group.p)
        if public.bit_length() == 2048:
            break
        peer_private += 1
    peer_bytes = sign_byte + public.to_bytes(256, "big")
    nonce, mac = b"n" * 16, b"m" * 6
    def encode(value):
        return base64.b64encode(value).decode("ascii")

    registration = "http://reader.example:8080/register"
    http.put(registration + "/cleanup", status=204)
    http.post(registration + "/pin", json={
        "a": encode(nonce), "b": encode(mac), "c": encode(peer_bytes),
    })

    def check_transcript(request):
        message = {key: base64.b64decode(value) for key, value in json.loads(request.body).items()}
        shared = pow(int.from_bytes(message["d"], "big"), peer_private, group.p)
        keys = PBKDF2(shared.to_bytes(256, "big"), nonce + mac + message["b"],
                      dkLen=48, count=10000, hmac_hash_module=SHA256)
        transcript = nonce + mac + peer_bytes + nonce + message["b"] + mac + message["d"]
        assert message["e"] == hmac.digest(keys[:32], transcript, "sha256")
        # An invalid server nonce must stop registration before asking for a PIN.
        return 200, {}, json.dumps({"a": encode(b"wrong nonce")})

    http.add_callback("POST", registration + "/hash", callback=check_transcript)
    assert device.register() is None
    assert "Nonce N2 doesn't match" in capsys.readouterr().out


def test_download_failure_preserves_existing_file(device, http, tmp_path):
    http.get(BASE + "/resolve/entry/path/Document%2Fbook.pdf", json=DOCUMENT)
    http.get(BASE + "/documents/pdf/file", status=500, body="server error")
    target = tmp_path / "book.pdf"
    target.write_bytes(b"original PDF")
    with pytest.raises(requests.HTTPError):
        device.download_file("Document/book.pdf", target)
    assert target.read_bytes() == b"original PDF"


@pytest.mark.parametrize("status", [401, 403, 500])
def test_resolution_errors_are_not_missing_documents(device, http, status):
    http.get(BASE + "/resolve/entry/path/Document%2Fbook.pdf", status=status, json={"message": "failure"})
    with pytest.raises(requests.HTTPError):
        device.path_exists("Document/book.pdf")


@pytest.mark.parametrize("register", [False, True])
def test_requests_always_have_timeouts(device, register):
    response = requests.Response()
    response.status_code = 204
    device.session.send = Mock(return_value=response)
    request = device._reg_endpoint_request if register else device._endpoint_request
    request("PUT", "/test")
    timeout = device.session.send.call_args.kwargs["timeout"]
    assert len(timeout) == 2 and all(value > 0 for value in timeout)


def test_request_timeout_is_configurable():
    client = DigitalPaper(addr="reader.example", timeout=(2, 120))
    try:
        response = requests.Response()
        response.status_code = 204
        client.session.send = Mock(return_value=response)
        client._get_endpoint("/test")
        assert client.session.send.call_args.kwargs["timeout"] == (2, 120)
    finally:
        client.session.close()


def test_list_folders_returns_current_paths(device, http):
    http.get(BASE + "/documents2?entry_type=all", json={"entry_list": [ROOT, FOLDER, DOCUMENT]})
    assert device.list_folders() == ["Document", "Document/Notes"]


def test_fast_traversal_does_not_include_similarly_named_sibling(device, http):
    sibling = {**DOCUMENT, "entry_path": "Document/Notes-archive/book.pdf"}
    http.get(BASE + "/documents2?entry_type=all", json={"count": 3, "entry_list": [FOLDER, DOCUMENT, sibling]})
    assert device.traverse_folder("Document/Notes") == [FOLDER, DOCUMENT]


@pytest.mark.parametrize("failure", [requests.Timeout(), requests.ConnectionError()])
def test_discovery_ignores_unreachable_advertised_reader(monkeypatch, failure):
    from dptrp1.dptrp1 import LookUpDPT

    get = Mock(side_effect=failure)
    monkeypatch.setattr(requests, "get", get)
    zeroconf = Mock()
    zeroconf.get_service_info.return_value = Mock(addresses=[b"\xc0\x00\x02\x01"], port=8080)
    lookup = LookUpDPT(quiet=True)
    lookup.add_service(zeroconf, "_digitalpaper._tcp.local.", "reader")
    assert get.call_args.kwargs["timeout"] == (5, 10)
    assert lookup.addr is None
