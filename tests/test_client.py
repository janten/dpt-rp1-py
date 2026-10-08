import base64
import hashlib
import hmac
import json
from http.cookies import SimpleCookie

import pytest
from Crypto.Hash import SHA256
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
        keys = hashlib.pbkdf2_hmac("sha256", shared.to_bytes(256, "big"),
                                   nonce + mac + message["b"], 10000, 48)
        transcript = nonce + mac + peer_bytes + nonce + message["b"] + mac + message["d"]
        assert message["e"] == hmac.digest(keys[:32], transcript, "sha256")
        # An invalid server nonce must stop registration before asking for a PIN.
        return 200, {}, json.dumps({"a": encode(b"wrong nonce")})

    http.add_callback("POST", registration + "/hash", callback=check_transcript)
    assert device.register() is None
    assert "Nonce N2 doesn't match" in capsys.readouterr().out
