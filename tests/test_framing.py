"""Tests for airlock.core.framing (threats T16, T18)."""

from __future__ import annotations

import os
import random
import struct
import zlib

import pytest

from airlock.core.framing import (
    HEADER_SIZE,
    MAX_PACKET_SIZE,
    MAX_PAYLOAD,
    CrcError,
    FramingError,
    Packet,
    PacketType,
    VersionError,
    decode,
)

SID = bytes(range(16))


def _with_crc(body: bytes) -> bytes:
    return body + struct.pack(">I", zlib.crc32(body))


def test_roundtrip() -> None:
    pkt = Packet(PacketType.DATA, SID, 7, 9, b"hello")
    raw = pkt.encode()
    assert len(raw) == HEADER_SIZE + 5 + 4
    assert raw[:2] == b"AL"
    assert decode(raw) == pkt


def test_crc_detects_noise() -> None:
    raw = bytearray(Packet(PacketType.DATA, SID, 1, 2, b"payload").encode())
    raw[HEADER_SIZE] ^= 0x01
    with pytest.raises(CrcError):
        decode(bytes(raw))


def test_malformed_rejected() -> None:
    """T16: every malformed input raises FramingError, never anything else."""
    good = Packet(PacketType.DATA, SID, 1, 2, b"payload").encode()
    body = good[:-4]
    cases = [
        b"",
        b"AL",
        good[:-1],  # truncated
        _with_crc(b"XX" + body[2:]),  # bad magic
        _with_crc(body[:3] + b"\x63" + body[4:]),  # unknown type 99
        _with_crc(body[:28] + struct.pack(">H", 99) + body[30:]),  # length lies
        _with_crc(body + b"extra"),  # trailing bytes vs length
        b"\x00" * (MAX_PACKET_SIZE + 1),  # oversized
    ]
    for raw in cases:
        with pytest.raises(FramingError):
            decode(raw)


def test_version_mismatch_rejected() -> None:
    """T18: a packet with another version is refused, with no fallback."""
    raw = Packet(PacketType.HELLO, SID, 0, 0, b"x" * 32, version=2).encode()
    with pytest.raises(VersionError):
        decode(raw)


def test_payload_size_limit_enforced_on_encode() -> None:
    with pytest.raises(FramingError):
        Packet(PacketType.DATA, SID, 1, 2, b"x" * (MAX_PAYLOAD + 1)).encode()


def test_fuzz_random_bytes_only_raise_framing_error() -> None:
    """Random garbage (and garbage with a valid CRC) never crashes the parser."""
    rng = random.Random(1234)
    for _ in range(3000):
        blob = os.urandom(rng.randint(0, 200))
        if rng.random() < 0.5:
            blob = _with_crc(blob)
        try:
            decode(blob)
        except FramingError:
            pass
