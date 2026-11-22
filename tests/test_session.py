"""Tests for airlock.core.session (threats T5, T6, T8, T15, T17)."""

from __future__ import annotations

import os
import random
from pathlib import Path

import pytest

from airlock.core.crypto import PacketSealer
from airlock.core.framing import Packet, PacketType
from airlock.core.identity import Identity
from airlock.core.session import (
    Manifest,
    Reassembler,
    TransferError,
    build_receipt,
    build_transfer_packets,
    sanitize_filename,
    verify_receipt,
    write_file_atomic,
)

DATA = os.urandom(5000)


def _receive_all(r_result, packets: list[bytes]) -> tuple[Manifest, bytes]:
    reasm = Reassembler(r_result)
    for raw in packets:
        reasm.feed(raw)
    return reasm.finalize()


def test_roundtrip(session) -> None:
    alice, _, i_res, r_res = session
    packets = build_transfer_packets(i_res, alice.identity, "report.pdf", DATA)
    assert len(packets) == 1 + 25  # manifest + ceil(5000/200)
    manifest, data = _receive_all(r_res, packets)
    assert data == DATA and manifest.filename == "report.pdf" and manifest.size == 5000


def test_empty_file(session) -> None:
    alice, _, i_res, r_res = session
    manifest, data = _receive_all(r_res, build_transfer_packets(i_res, alice.identity, "e", b""))
    assert data == b"" and manifest.chunk_count == 0


def test_ciphertext_hides_plaintext_and_filename(session) -> None:
    alice, _, i_res, _ = session
    secret = b"TOP-SECRET-MARKER" * 20
    wire = b"".join(build_transfer_packets(i_res, alice.identity, "salaries.xlsx", secret))
    assert b"TOP-SECRET" not in wire and b"salaries" not in wire


def test_duplicates_and_reorder(session) -> None:
    """T8: shuffled and repeated packets (looping QR) still reassemble exactly once."""
    alice, _, i_res, r_res = session
    packets = build_transfer_packets(i_res, alice.identity, "f.bin", DATA)
    stream = packets * 3
    random.Random(7).shuffle(stream)
    reasm = Reassembler(r_res)
    for raw in stream:
        reasm.feed(raw)
    _, data = reasm.finalize()
    assert data == DATA
    assert reasm.stats.accepted == len(packets)
    assert reasm.stats.duplicates == 2 * len(packets)


def test_noise_is_dropped_not_fatal(session) -> None:
    alice, _, i_res, r_res = session
    packets = build_transfer_packets(i_res, alice.identity, "f.bin", DATA)
    reasm = Reassembler(r_res)
    for raw in packets:
        noisy = bytearray(raw)
        noisy[len(noisy) // 2] ^= 0xFF  # corrupt copy, CRC no longer matches
        reasm.feed(bytes(noisy))
        reasm.feed(raw)  # then the clean retransmission
    assert reasm.finalize()[1] == DATA
    assert reasm.stats.crc_errors == len(packets) and reasm.stats.aead_failures == 0


def test_manifest_tamper_rejected(session) -> None:
    """T5: a manifest signed by anyone but the authenticated peer is rejected.

    The strongest version of this attack: suppose the session key leaked
    (Mallory can produce valid AEAD packets). Mallory still cannot forge the
    sender's Ed25519 signature on the manifest.
    """
    _, _, i_res, r_res = session
    mallory = Identity.generate()
    forged = Manifest("evil.exe", 5, b"\x00" * 32, 1).sign(mallory, i_res.session_id)
    key, iv = i_res.keys.outbound(i_res.role)
    raw = PacketSealer(key, iv, i_res.session_id).seal(
        PacketType.MANIFEST, 0, 2, forged.encode()
    ).encode()
    with pytest.raises(TransferError, match="signature"):
        Reassembler(r_res).feed(raw)


def test_hash_mismatch_rejected(session) -> None:
    """End-to-end SHA-256: authentic chunks that do not match the manifest are refused."""
    alice, _, i_res, r_res = session
    manifest = Manifest("f", 3, b"\x11" * 32, 1).sign(alice.identity, i_res.session_id)
    key, iv = i_res.keys.outbound(i_res.role)
    sealer = PacketSealer(key, iv, i_res.session_id)
    reasm = Reassembler(r_res)
    reasm.feed(sealer.seal(PacketType.MANIFEST, 0, 2, manifest.encode()).encode())
    reasm.feed(sealer.seal(PacketType.DATA, 1, 2, b"abc").encode())
    with pytest.raises(TransferError, match="SHA-256"):
        reasm.finalize()


@pytest.mark.parametrize(
    ("hostile", "expected"),
    [
        ("../../.bashrc", "bashrc"),
        ("..\\..\\Windows\\System32\\evil.dll", "evil.dll"),
        ("/etc/passwd", "passwd"),
        ("a\x00b\nc.txt", "abc.txt"),
        ("..", "received.bin"),
        ("", "received.bin"),
        ("CON.txt", "_CON.txt"),
        ("nul", "_nul"),
        ('re<po>rt:"?.pdf', "report.pdf"),
    ],
)
def test_filename_sanitised(hostile: str, expected: str) -> None:
    """T6: path traversal and OS-specific dangerous names are neutralised."""
    assert sanitize_filename(hostile) == expected


def test_long_filename_truncated_keeps_extension() -> None:
    name = sanitize_filename("x" * 400 + ".tar.gz")
    assert len(name.encode()) <= 255 and name.endswith(".gz")


def test_sender_path_traversal_lands_inside_out_dir(session, tmp_path: Path) -> None:
    alice, _, i_res, r_res = session
    manifest, data = _receive_all(
        r_res, build_transfer_packets(i_res, alice.identity, "../../escape.txt", b"hi")
    )
    written = write_file_atomic(tmp_path / "out", manifest.filename, data)
    assert written.parent == tmp_path / "out" and written.name == "escape.txt"


def test_aead_failure_threshold(session) -> None:
    """T15: a flood of forged packets aborts the session instead of running forever."""
    _, _, i_res, r_res = session
    reasm = Reassembler(r_res, max_aead_failures=5)
    for seq in range(1, 5):
        forged = Packet(PacketType.DATA, i_res.session_id, seq, 10, os.urandom(40)).encode()
        assert reasm.feed(forged) is False
    with pytest.raises(TransferError, match="tampering"):
        reasm.feed(Packet(PacketType.DATA, i_res.session_id, 6, 10, os.urandom(40)).encode())


def test_other_session_packets_ignored(session, alice_bob) -> None:
    """T7: packets of an old session are dropped by the new session's reassembler."""
    alice, _, i_res, _ = session
    from conftest import run_handshake

    _, new_r = run_handshake(*alice_bob)
    reasm = Reassembler(new_r)
    for raw in build_transfer_packets(i_res, alice.identity, "f", DATA):
        assert reasm.feed(raw) is False
    assert reasm.stats.rejected > 0 and reasm.stats.accepted == 0


def test_size_limit(session) -> None:
    alice, _, i_res, r_res = session
    packets = build_transfer_packets(i_res, alice.identity, "big", DATA)
    reasm = Reassembler(r_res, max_file_size=1000)
    with pytest.raises(TransferError, match="limit"):
        for raw in packets:
            reasm.feed(raw)


def test_no_partial_write(session, tmp_path: Path) -> None:
    """T17: a truncated transfer cannot be finalized, and the output dir stays empty."""
    alice, _, i_res, r_res = session
    packets = build_transfer_packets(i_res, alice.identity, "f.bin", DATA)
    reasm = Reassembler(r_res)
    for raw in packets[:-3]:  # the last 3 chunks never arrive
        reasm.feed(raw)
    assert not reasm.complete
    with pytest.raises(TransferError, match="incomplete"):
        reasm.finalize()
    out = tmp_path / "out"
    assert not out.exists() or list(out.iterdir()) == []


def test_atomic_write_never_overwrites(tmp_path: Path) -> None:
    first = write_file_atomic(tmp_path, "a.txt", b"1")
    second = write_file_atomic(tmp_path, "a.txt", b"2")
    assert first.read_bytes() == b"1" and second.name == "a (1).txt"
    assert not list(tmp_path.glob(".airlock-*"))  # no temp files left


def test_receipt(session) -> None:
    _, _, i_res, r_res = session
    sha = os.urandom(32)
    verify_receipt(i_res, build_receipt(r_res, sha), sha)
    with pytest.raises(TransferError, match="different file"):
        verify_receipt(i_res, build_receipt(r_res, sha), os.urandom(32))
    forged = Packet(PacketType.RECEIPT, i_res.session_id, 0, 1, os.urandom(48)).encode()
    with pytest.raises(TransferError, match="authentication"):
        verify_receipt(i_res, forged, sha)


def test_manifest_codec_strict() -> None:
    ident = Identity.generate()
    m = Manifest("name.txt", 10, b"\x01" * 32, 1).sign(ident, b"\x02" * 16)
    assert Manifest.decode(m.encode()) == m
    for bad in (m.encode()[:-1], m.encode() + b"x", b"", b"\xff\xff"):
        with pytest.raises(TransferError):
            Manifest.decode(bad)
