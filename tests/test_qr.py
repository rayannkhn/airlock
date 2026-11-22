"""Tests for the QR transport: Base45, rendering, decoding, a full video round trip."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from airlock.core.identity import Identity, TrustStore
from airlock.core.oneway import SessionStore
from airlock.core.session import build_oneway_transfer, receive_file_oneway
from airlock.transports.base import TransportClosed, TransportError
from airlock.transports.qr import (
    QrDecoder,
    QrReceiver,
    b45decode,
    b45encode,
    qr_image,
    render_html,
    render_video,
    verify_video,
)


def test_base45_rfc9285_vectors() -> None:
    # Test vectors from RFC 9285 section 4.
    assert b45encode(b"AB") == "BB8"
    assert b45encode(b"Hello!!") == "%69 VD92EX0"
    assert b45encode(b"base-45") == "UJCLQE7W581"
    assert b45decode("QED8WEX0") == b"ietf!"


def test_base45_roundtrip_random() -> None:
    for n in range(0, 300, 7):
        data = os.urandom(n)
        assert b45decode(b45encode(data)) == data


@pytest.mark.parametrize("bad", ["A", "GGW", "ZZZZ", "abc"])
def test_base45_rejects_invalid(bad: str) -> None:
    with pytest.raises(ValueError):
        b45decode(bad)


def test_qr_image_decodes_reliably() -> None:
    """Every packet-sized QR decodes from a clean image (this caught a weak detector once)."""
    decoder = QrDecoder()
    for _ in range(60):
        packet = os.urandom(200)
        assert decoder.decode(qr_image(packet)) == packet


def test_foreign_qr_is_ignored() -> None:
    import qrcode
    import numpy as np

    img = np.array(qrcode.make("https://example.com").convert("L"), dtype="uint8")
    assert QrDecoder().decode(img) is None  # lowercase text is not Base45


def _demo_pair():
    alice, bob = Identity.generate(), Identity.generate()
    a_trust, b_trust = TrustStore(), TrustStore()
    a_trust.add("bob", bob.public_key, bob.receive_public_key)
    b_trust.add("alice", alice.public_key, alice.receive_public_key)
    return alice, a_trust, bob, b_trust


def test_video_roundtrip_end_to_end(tmp_path: Path) -> None:
    """File -> SEAL + encrypted packets -> MP4 -> decode frames -> verified file."""
    alice, a_trust, bob, b_trust = _demo_pair()
    src = tmp_path / "notes.txt"
    src.write_bytes(os.urandom(1200))
    packets, s_res = build_oneway_transfer(alice, a_trust, "bob", src, chunk_size=150)
    video = tmp_path / "out.mp4"
    render_video(packets, video, hold=4, loops=2, size=720)
    assert verify_video(video, packets, hold=4) == len(packets)

    with QrReceiver.open_video(video, frame_step=2) as rx:
        report = receive_file_oneway(rx, bob, b_trust, tmp_path / "out", SessionStore(),
                                     confirm_sas=lambda _p, sas: sas == s_res.sas_text)
    assert report.path.read_bytes() == src.read_bytes()


def test_video_ends_before_complete(tmp_path: Path) -> None:
    alice, a_trust, bob, b_trust = _demo_pair()
    src = tmp_path / "notes.txt"
    src.write_bytes(os.urandom(1200))
    packets, _ = build_oneway_transfer(alice, a_trust, "bob", src, chunk_size=150)
    video = tmp_path / "short.mp4"
    render_video(packets[:-2], video, hold=4, loops=1, size=720)
    with QrReceiver.open_video(video, frame_step=2) as rx:
        with pytest.raises(TransportClosed):
            receive_file_oneway(rx, bob, b_trust, tmp_path / "out", SessionStore())
    assert not (tmp_path / "out").exists()


def test_html_render(tmp_path: Path) -> None:
    packets = [os.urandom(100) for _ in range(3)]
    render_html(packets, tmp_path / "out.html")
    page = (tmp_path / "out.html").read_text(encoding="utf-8")
    assert page.count("data:image/png;base64,") == 3 and "setInterval" in page


def test_qr_receiver_is_receive_only(tmp_path: Path) -> None:
    video = tmp_path / "v.mp4"
    render_video([os.urandom(50)], video, hold=2, loops=1, size=360)
    with QrReceiver.open_video(video) as rx:
        with pytest.raises(TransportError):
            rx.send(b"x")


def test_missing_video_file(tmp_path: Path) -> None:
    with pytest.raises(TransportError):
        QrReceiver.open_video(tmp_path / "nope.mp4")


def test_gif_roundtrip_end_to_end(tmp_path: Path) -> None:
    """The phone-friendly GIF: lossless, every code readable, and a full verified receive."""
    from airlock.transports.qr import render_gif, verify_gif

    alice, a_trust, bob, b_trust = _demo_pair()
    src = tmp_path / "notes.txt"
    src.write_bytes(os.urandom(1500))
    packets, s_res = build_oneway_transfer(alice, a_trust, "bob", src, chunk_size=150)
    gif = tmp_path / "out.gif"
    seconds = render_gif(packets, gif)
    assert gif.read_bytes()[:4] == b"GIF8" and seconds > 0
    assert verify_gif(gif, packets) == len(packets)
    with QrReceiver.open_video(gif, frame_step=5) as rx:  # the step is ignored for GIFs
        report = receive_file_oneway(rx, bob, b_trust, tmp_path / "out", SessionStore(),
                                     confirm_sas=lambda _p, sas: sas == s_res.sas_text)
    assert report.path.read_bytes() == src.read_bytes()
