"""Tests for airlock.core.crypto (threats T4, T7, T12)."""

from __future__ import annotations

import os

import pytest

from airlock.core.crypto import (
    DecryptError,
    NonceReuseError,
    PacketOpener,
    PacketSealer,
    Role,
    derive_session_keys,
    format_sas,
    compute_sas,
    make_nonce,
    transcript_hash,
)
from airlock.core.framing import Packet, PacketType, decode

SID = os.urandom(16)


def _keys(th: bytes = b"t" * 32, shared: bytes = b"s" * 32, sid: bytes = SID):
    return derive_session_keys(shared, sid, th)


def test_key_schedule_deterministic_and_transcript_bound() -> None:
    a, b = _keys(), _keys()
    assert a.k_ir == b.k_ir and a.iv_ri == b.iv_ri
    other = _keys(th=b"u" * 32)
    assert other.k_ir != a.k_ir and other.k_ri != a.k_ri and compute_sas(other) != compute_sas(a)
    assert _keys(sid=os.urandom(16)).k_ir != a.k_ir  # session_id (salt) matters too


def test_directional_keys_are_distinct() -> None:
    keys = _keys()
    values = {keys.k_ir, keys.k_ri, keys.k_sas}
    assert len(values) == 3 and keys.iv_ir != keys.iv_ri
    assert keys.outbound(Role.INITIATOR) == keys.inbound(Role.RESPONDER)
    assert keys.outbound(Role.RESPONDER) == keys.inbound(Role.INITIATOR)


def test_transcript_hash_is_unambiguous() -> None:
    assert transcript_hash(b"ab", b"c") != transcript_hash(b"a", b"bc")
    assert transcript_hash(b"abc") != transcript_hash(b"ab", b"c")


def test_nonce_unique() -> None:
    """T12: 100k consecutive seqs give 100k distinct nonces."""
    iv = os.urandom(12)
    nonces = {make_nonce(iv, seq) for seq in range(100_000)}
    assert len(nonces) == 100_000


def test_sealer_refuses_nonce_reuse() -> None:
    keys = _keys()
    sealer = PacketSealer(keys.k_ir, keys.iv_ir, SID)
    sealer.seal(PacketType.DATA, 1, 3, b"a")
    with pytest.raises(NonceReuseError):
        sealer.seal(PacketType.DATA, 1, 3, b"b")


def test_seal_open_roundtrip_through_wire_bytes() -> None:
    keys = _keys()
    raw = PacketSealer(keys.k_ir, keys.iv_ir, SID).seal(PacketType.DATA, 5, 9, b"secret").encode()
    assert b"secret" not in raw  # confidentiality (smoke check)
    assert PacketOpener(keys.k_ir, keys.iv_ir, SID).open(decode(raw)) == b"secret"


def test_tamper_detected() -> None:
    """T4: flipping any bit of the payload or any authenticated header field is detected."""
    keys = _keys()
    pkt = PacketSealer(keys.k_ir, keys.iv_ir, SID).seal(PacketType.DATA, 2, 4, b"chunk data")
    opener = PacketOpener(keys.k_ir, keys.iv_ir, SID)

    for i in range(len(pkt.payload)):
        for bit in (0x01, 0x80):
            payload = bytearray(pkt.payload)
            payload[i] ^= bit
            with pytest.raises(DecryptError):
                opener.open(Packet(pkt.ptype, pkt.session_id, pkt.seq, pkt.total, bytes(payload)))

    # Header fields are associated data: changing them breaks the tag as well.
    for forged in (
        Packet(pkt.ptype, pkt.session_id, 3, pkt.total, pkt.payload),  # seq
        Packet(pkt.ptype, pkt.session_id, pkt.seq, 5, pkt.payload),  # total
        Packet(PacketType.MANIFEST, pkt.session_id, pkt.seq, pkt.total, pkt.payload),  # type
    ):
        with pytest.raises(DecryptError):
            opener.open(forged)


def test_wrong_direction_key_fails() -> None:
    """A packet sealed I->R cannot be opened with the R->I key (no reflection)."""
    keys = _keys()
    pkt = PacketSealer(keys.k_ir, keys.iv_ir, SID).seal(PacketType.DATA, 1, 2, b"x")
    with pytest.raises(DecryptError):
        PacketOpener(keys.k_ri, keys.iv_ri, SID).open(pkt)


def test_other_session_rejected() -> None:
    """T7: a packet from another session is refused (different id and different key)."""
    keys = _keys()
    pkt = PacketSealer(keys.k_ir, keys.iv_ir, SID).seal(PacketType.DATA, 1, 2, b"x")
    new_sid = os.urandom(16)
    new_keys = _keys(sid=new_sid)
    with pytest.raises(DecryptError):
        PacketOpener(new_keys.k_ir, new_keys.iv_ir, new_sid).open(pkt)
    forged = Packet(pkt.ptype, new_sid, pkt.seq, pkt.total, pkt.payload)
    with pytest.raises(DecryptError):
        PacketOpener(new_keys.k_ir, new_keys.iv_ir, new_sid).open(forged)


def test_sas_format() -> None:
    assert format_sas(bytes.fromhex("9f3a01c7")) == "9F3A-01C7"
    assert len(compute_sas(_keys())) == 4


def test_keys_repr_redacted() -> None:
    keys = _keys()
    assert keys.k_ir.hex() not in repr(keys)
