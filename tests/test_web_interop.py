"""Cross-implementation tests: the browser app (JavaScript) and the Python package must interoperate.

Each direction is a real transfer: one language builds the packets, the
other verifies and decrypts them. This shows the two independent
implementations agree byte for byte on the wire format, key schedule,
signatures and checks. Needs Node.js 20+; skipped if it is missing.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from airlock.core.identity import Identity, TrustStore, parse_compact_card
from airlock.core.oneway import SessionStore
from airlock.core.session import build_oneway_transfer, receive_file_oneway
from airlock.transports.loopback import make_loopback_pair
from airlock.transports.qr import QrDecoder, b45encode

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js not installed")
b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731


def _export(name: str, ident: Identity) -> dict[str, str]:
    """Hand an identity to the JS side as PKCS#8 private keys + raw public keys (tests only)."""
    der = serialization.Encoding.DER
    pkcs8 = serialization.PrivateFormat.PKCS8
    none = serialization.NoEncryption()
    return {
        "name": name,
        "sign_pkcs8": b64(ident._private_key.private_bytes(der, pkcs8, none)),
        "sign_pub": b64(ident.public_key),
        "recv_pkcs8": b64(ident._receive_key.private_bytes(der, pkcs8, none)),
        "recv_pub": b64(ident.receive_public_key),
    }


def _node(job: dict) -> dict:
    res = subprocess.run([NODE, str(ROOT / "tools" / "web_interop.mjs")], input=json.dumps(job),
                         capture_output=True, text=True, timeout=60, check=False)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout)


def test_python_sends_javascript_receives(tmp_path: Path) -> None:
    alice, bob = Identity.generate(), Identity.generate()
    trust = TrustStore()
    trust.add("bob", bob.public_key, bob.receive_public_key)
    src = tmp_path / "from python.txt"
    src.write_bytes(os.urandom(2345))
    packets, result = build_oneway_transfer(alice, trust, "bob", src)
    out = _node({"mode": "receive", "me": _export("Bob", bob), "sender": _export("Alice", alice),
                 "packets": [b64(p) for p in packets]})
    assert base64.b64decode(out["data"]) == src.read_bytes()
    assert out["sas"] == result.sas_text  # both sides show the same verification code
    assert out["filename"] == "from python.txt" and out["sender"] == "Alice"


def test_javascript_sends_python_receives(tmp_path: Path) -> None:
    alice, bob = Identity.generate(), Identity.generate()
    data = os.urandom(3100)
    out = _node({"mode": "send", "me": _export("Alice", alice), "recipient": _export("Bob", bob),
                 "filename": "from browser.bin", "data": b64(data)})
    trust = TrustStore()
    trust.add("alice", alice.public_key, alice.receive_public_key)
    tx, rx = make_loopback_pair()
    for p in out["packets"]:
        tx.send(base64.b64decode(p))
    tx.close()
    report = receive_file_oneway(rx, bob, trust, tmp_path / "out", SessionStore(),
                                 confirm_sas=lambda _p, sas: sas == out["sas"])
    assert report.path.read_bytes() == data and report.path.name == "from browser.bin"


def test_javascript_card_accepted_by_python() -> None:
    alice = Identity.generate()
    out = _node({"mode": "card", "me": _export("Alice", alice)})
    name, sign_key, receive_key = parse_compact_card(base64.b64decode(out["card"]))
    assert (name, sign_key, receive_key) == ("Alice", alice.public_key, alice.receive_public_key)
    assert out["fingerprint"] == alice.fingerprint


def test_javascript_qr_text_decodes_in_python() -> None:
    """The QR text the browser renders is exactly what the Python decoder expects."""
    packet = os.urandom(200)
    out = _node({"mode": "qr_text", "packet": b64(packet)})
    assert out["text"] == b45encode(packet)
    from airlock.transports.qr import b45decode

    assert b45decode(out["text"]) == packet
    assert QrDecoder  # same decoder path as the camera receiver


def test_app_qr_codes_readable_by_python_decoder() -> None:
    """A QR drawn by the browser's generator decodes with the Python (OpenCV) receiver."""
    import cv2
    import numpy as np

    packet = os.urandom(200)
    rows = _node({"mode": "qr_encode", "text": b45encode(packet)})["rows"]
    matrix = np.array([[c == "1" for c in row] for row in rows])
    matrix = np.pad(matrix, 4)  # quiet zone
    img = cv2.resize(np.where(matrix, 0, 255).astype(np.uint8), (720, 720), interpolation=cv2.INTER_NEAREST)
    assert QrDecoder().decode(img) == packet


def test_python_qr_codes_readable_by_app_decoder() -> None:
    """A QR drawn by Python decodes with the browser's jsQR."""
    from airlock.transports.qr import qr_image

    packet = os.urandom(200)
    img = qr_image(packet, 480)
    out = _node({"mode": "qr_decode", "gray": b64(img.tobytes()), "width": img.shape[1], "height": img.shape[0]})
    assert out["text"] == b45encode(packet)


def test_javascript_unit_tests() -> None:
    """The JS core's own unit tests (Base45 vectors, CRC, seal/open, tamper, replay, cards)."""
    res = subprocess.run([NODE, "--test", str(ROOT / "web" / "tests" / "core.test.mjs")],
                         capture_output=True, text=True, timeout=120, check=False)
    assert res.returncode == 0, res.stdout[-2000:] + res.stderr[-2000:]
    assert "# fail 0" in res.stdout
