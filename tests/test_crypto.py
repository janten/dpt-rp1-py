import hmac

import pytest
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as reference_pad

from dptrp1.dptrp1 import pad, unpad, unwrap, wrap
from dptrp1.pyDH import DiffieHellman


@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 31, 32, 255, 256])
def test_key_wrapping_matches_device_wire_format(length):
    data = bytes(range(256))[:length]
    auth_key, wrapping_key = b"a" * 32, b"k" * 16
    wrapped = wrap(data, auth_key, wrapping_key)

    # The protocol appends the IV and an eight-byte HMAC to the plaintext.
    ciphertext, iv = wrapped[:-16], wrapped[-16:]
    expected = data + hmac.digest(auth_key, data, "sha256")[:8]
    assert AES.new(wrapping_key, AES.MODE_CBC, iv).decrypt(ciphertext) == reference_pad(expected, 16)
    assert unwrap(wrapped, auth_key, wrapping_key) == data


@pytest.mark.parametrize("data", [b"", b"hello", b"x" * 16, b"x" * 17])
def test_pkcs7_padding(data):
    expected = reference_pad(data, 16)
    assert pad(data) == expected
    assert unpad(expected) == data


def test_unpad_rejects_oversized_padding():
    with pytest.raises(ValueError, match="padding is corrupt"):
        unpad(b"x" * 15 + b"\x11")


def test_diffie_hellman_shared_secret():
    alice, bob = DiffieHellman(), DiffieHellman()
    shared = alice.gen_shared_key(bob.gen_public_key())
    assert shared == bob.gen_shared_key(alice.gen_public_key())


@pytest.mark.parametrize("public_key", [0, 1, -1])
def test_diffie_hellman_rejects_invalid_peer_keys(public_key):
    with pytest.raises(Exception, match="Bad public key"):
        DiffieHellman().gen_shared_key(public_key)


def test_unwrap_rejects_wrong_authentication_key():
    wrapped = wrap(b"secret", b"a" * 32, b"k" * 16)
    with pytest.raises(ValueError, match="authentication"):
        unwrap(wrapped, b"b" * 32, b"k" * 16)


@pytest.mark.parametrize("invalid", [b"", b"x" * 15 + b"\x00", b"x" * 15 + b"\x02", b"\x01"])
def test_unpad_rejects_malformed_padding(invalid):
    with pytest.raises(ValueError):
        unpad(invalid)


@pytest.mark.parametrize("invalid", [b"", b"x" * 16, b"x" * 31, b"x" * 33])
def test_unwrap_rejects_malformed_ciphertext(invalid):
    with pytest.raises(ValueError):
        unwrap(invalid, b"a" * 32, b"k" * 16)
