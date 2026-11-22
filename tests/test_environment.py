"""Phase 1 environment checks.

These tests confirm that the installed `cryptography` build provides every
primitive in docs/design.md section 3, and that it behaves the way the
protocol design assumes. If any of these fail, the later phases cannot be
trusted on this machine.
"""

from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import airlock


def test_package_metadata() -> None:
    """The package imports and exposes the protocol version byte."""
    assert airlock.PROTOCOL_VERSION == 1


def test_x25519_agreement() -> None:
    """Both sides of an X25519 exchange derive the same 32-byte secret."""
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    s1 = a.exchange(b.public_key())
    s2 = b.exchange(a.public_key())
    assert s1 == s2 and len(s1) == 32


def test_x25519_rejects_low_order_point() -> None:
    """Design section 5 assumes an all-zero shared secret is rejected.

    The all-zero u-coordinate is a low-order point. OpenSSL returns an error
    for it, and pyca turns that error into ValueError. A MITM could otherwise
    force a known shared secret.
    """
    zero_point = X25519PublicKey.from_public_bytes(b"\x00" * 32)
    with pytest.raises(ValueError):
        X25519PrivateKey.generate().exchange(zero_point)


def test_ed25519_sign_verify_and_reject() -> None:
    """A valid signature verifies; a signature over a changed message fails."""
    sk = Ed25519PrivateKey.generate()
    msg = b"airlock-R" + os.urandom(32)
    sig = sk.sign(msg)
    sk.public_key().verify(sig, msg)  # raises on failure
    with pytest.raises(InvalidSignature):
        sk.public_key().verify(sig, msg + b"x")


def test_ed25519_is_deterministic() -> None:
    """Ed25519 needs no per-signature randomness (no nonce-reuse risk)."""
    sk = Ed25519PrivateKey.generate()
    assert sk.sign(b"m") == sk.sign(b"m")


def test_hkdf_sha256_is_deterministic_and_context_bound() -> None:
    """The same inputs give the same keys; a different transcript gives different keys."""

    def derive(info: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(), length=120, salt=b"s" * 16, info=info
        ).derive(b"k" * 32)

    assert derive(b"t1") == derive(b"t1")
    assert derive(b"t1") != derive(b"t2")


def test_aesgcm_roundtrip_and_tamper_detection() -> None:
    """AES-256-GCM decrypts its own output and rejects changed ciphertext or AAD."""
    key = AESGCM.generate_key(bit_length=256)
    aead = AESGCM(key)
    nonce, aad = os.urandom(12), b"header"
    ct = aead.encrypt(nonce, b"secret chunk", aad)
    assert aead.decrypt(nonce, ct, aad) == b"secret chunk"

    flipped = bytes([ct[0] ^ 0x01]) + ct[1:]
    with pytest.raises(InvalidTag):
        aead.decrypt(nonce, flipped, aad)
    with pytest.raises(InvalidTag):
        aead.decrypt(nonce, ct, b"Header")


def test_media_dependencies_import() -> None:
    """Libraries for later phases are installed (QR, audio, ECC, plots)."""
    import cv2
    import matplotlib
    import numpy
    import qrcode
    import reedsolo
    import sounddevice

    assert hasattr(cv2, "QRCodeDetector")
    assert numpy and matplotlib and qrcode and reedsolo and sounddevice
