"""Tests for the one-way mode: contact cards, SEAL, replay store (threats T1, T2, T7, T11, T19)."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from airlock.core.framing import Packet, PacketType, decode
from airlock.core.handshake import HandshakeError
from airlock.core.identity import Identity, IdentityError, TrustStore, load_peer_keys, parse_card
from airlock.core.oneway import (
    DEFAULT_MAX_AGE,
    SessionStore,
    create_seal,
    open_seal,
)
from airlock.core.session import (
    Reassembler,
    TransferError,
    build_oneway_transfer,
    build_transfer_packets,
    receive_file_oneway,
)
from airlock.transports.base import TransportClosed
from airlock.transports.loopback import make_loopback_pair


@pytest.fixture
def pair() -> tuple[Identity, TrustStore, Identity, TrustStore]:
    alice, bob = Identity.generate(), Identity.generate()
    a_trust, b_trust = TrustStore(), TrustStore()
    a_trust.add("bob", bob.public_key, bob.receive_public_key)
    b_trust.add("alice", alice.public_key, alice.receive_public_key)
    return alice, a_trust, bob, b_trust


# ------------------------------------------------------------ contact cards


def test_card_roundtrip_and_binding(tmp_path: Path) -> None:
    ident = Identity.generate()
    ident.save(tmp_path / "identity.key", None)
    sign_key, receive_key = load_peer_keys(tmp_path / "identity.card")
    assert sign_key == ident.public_key and receive_key == ident.receive_public_key
    loaded = Identity.load(tmp_path / "identity.key")
    assert loaded.receive_public_key == ident.receive_public_key


def test_card_with_swapped_receive_key_rejected() -> None:
    """An attacker who swaps the receiving key on a card breaks its signature."""
    doc = json.loads(Identity.generate().card())
    doc["receive_key"] = Identity.generate().receive_public_key.hex()  # type: ignore[union-attr]
    with pytest.raises(IdentityError, match="altered"):
        parse_card(json.dumps(doc).encode())


def test_receive_key_encrypted_with_passphrase(tmp_path: Path) -> None:
    Identity.generate().save(tmp_path / "identity.key", b"correct horse")
    assert b"ENCRYPTED" in (tmp_path / "identity-recv.key").read_bytes()
    assert Identity.load(tmp_path / "identity.key", b"correct horse").receive_public_key


# ------------------------------------------------------------ SEAL


def test_seal_agrees_on_keys_and_sas(pair) -> None:
    alice, a_trust, bob, b_trust = pair
    seal, s_res = create_seal(alice, a_trust, "bob")
    r_res = open_seal(bob, b_trust, seal, SessionStore())
    assert s_res.keys.k_ir == r_res.keys.k_ir and s_res.sas == r_res.sas
    assert r_res.peer_name == "alice" and s_res.peer_name == "bob"


def test_seal_from_untrusted_sender_rejected(pair) -> None:
    """T1: Mallory, who knows Bob's card, can encrypt to Bob but cannot pass as trusted."""
    _, _, bob, b_trust = pair
    mallory = Identity.generate()
    m_trust = TrustStore()
    m_trust.add("bob", bob.public_key, bob.receive_public_key)
    seal, _ = create_seal(mallory, m_trust, "bob")
    with pytest.raises(HandshakeError, match="not in the trust store"):
        open_seal(bob, b_trust, seal, SessionStore())


def test_seal_forged_sender_key_rejected(pair) -> None:
    """T2: putting Alice's public key into Mallory's SEAL fails the signature check."""
    alice, _, bob, b_trust = pair
    mallory = Identity.generate()
    m_trust = TrustStore()
    m_trust.add("bob", bob.public_key, bob.receive_public_key)
    seal, _ = create_seal(mallory, m_trust, "bob")
    pkt = decode(seal)
    payload = pkt.payload[:72] + alice.public_key + pkt.payload[104:]
    forged = Packet(PacketType.SEAL, pkt.session_id, 0, 0, payload).encode()
    with pytest.raises(HandshakeError, match="signature"):
        open_seal(bob, b_trust, forged, SessionStore())


def test_seal_tampered_ephemeral_rejected(pair) -> None:
    alice, a_trust, bob, b_trust = pair
    seal, _ = create_seal(alice, a_trust, "bob")
    pkt = decode(seal)
    payload = bytearray(pkt.payload)
    payload[45] ^= 0x01  # inside e_S.pub
    forged = Packet(PacketType.SEAL, pkt.session_id, 0, 0, bytes(payload)).encode()
    with pytest.raises(HandshakeError, match="signature"):
        open_seal(bob, b_trust, forged, SessionStore())


def test_seal_for_someone_else_rejected(pair) -> None:
    alice, a_trust, _, _ = pair
    carol = Identity.generate()
    c_trust = TrustStore({"alice": alice.public_key})
    seal, _ = create_seal(alice, a_trust, "bob")
    with pytest.raises(HandshakeError, match="addressed to someone else"):
        open_seal(carol, c_trust, seal, SessionStore())


def test_seal_expired_and_future_rejected(pair) -> None:
    """T7: a SEAL outside the timestamp window is rejected even though its signature is valid."""
    alice, a_trust, bob, b_trust = pair
    old, _ = create_seal(alice, a_trust, "bob", now=time.time() - DEFAULT_MAX_AGE - 60)
    with pytest.raises(HandshakeError, match="too old"):
        open_seal(bob, b_trust, old, SessionStore())
    future, _ = create_seal(alice, a_trust, "bob", now=time.time() + 3600)
    with pytest.raises(HandshakeError, match="future"):
        open_seal(bob, b_trust, future, SessionStore())


def test_seal_timestamp_is_signed(pair) -> None:
    """Changing the timestamp of an old SEAL to 'now' breaks the signature."""
    alice, a_trust, bob, b_trust = pair
    old, _ = create_seal(alice, a_trust, "bob", now=time.time() - DEFAULT_MAX_AGE - 60)
    pkt = decode(old)
    payload = int(time.time()).to_bytes(8, "big") + pkt.payload[8:]
    forged = Packet(PacketType.SEAL, pkt.session_id, 0, 0, payload).encode()
    with pytest.raises(HandshakeError, match="signature"):
        open_seal(bob, b_trust, forged, SessionStore())


def test_seal_version_mismatch_rejected(pair) -> None:
    """T18: a SEAL with another version byte is rejected, with no downgrade path."""
    alice, a_trust, bob, b_trust = pair
    seal, _ = create_seal(alice, a_trust, "bob")
    pkt = decode(seal)
    other = Packet(PacketType.SEAL, pkt.session_id, 0, 0, pkt.payload, version=2).encode()
    with pytest.raises(HandshakeError, match="version"):
        open_seal(bob, b_trust, other, SessionStore())


def test_seal_requires_pinned_receive_key() -> None:
    alice, bob = Identity.generate(), Identity.generate()
    trust = TrustStore({"bob": bob.public_key})  # signing key only, no card
    with pytest.raises(HandshakeError, match="no receiving key"):
        create_seal(alice, trust, "bob")


def test_session_store_persists_and_prunes(tmp_path: Path) -> None:
    store = SessionStore(tmp_path / "s.json")
    sid_new, sid_old = os.urandom(16), os.urandom(16)
    now = time.time()
    store.mark_used(sid_new, int(now))
    store.mark_used(sid_old, int(now - 10 * DEFAULT_MAX_AGE))
    store.prune(now)
    store.save()
    again = SessionStore.load(tmp_path / "s.json")
    assert again.is_used(sid_new) and not again.is_used(sid_old) and len(again) == 1


def test_corrupt_session_store_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "s.json").write_text("garbage", encoding="utf-8")
    with pytest.raises(IdentityError):
        SessionStore.load(tmp_path / "s.json")


def test_receiver_key_compromise_breaks_old_sessions(pair) -> None:
    """T19 (documented weakness): whoever steals Bob's receiving key reads recorded SEAL sessions.

    This test passing means the weakness is real, as documented. The
    interactive mode does not have it (test_forward_secrecy_keys_ephemeral).
    """
    alice, a_trust, bob, b_trust = pair
    packets_seal, s_res = create_seal(alice, a_trust, "bob")
    recorded = [packets_seal, *build_transfer_packets(s_res, alice, "f", b"recorded secret")]
    thief_result = open_seal(bob, b_trust, recorded[0], SessionStore())  # thief holds Bob's keys
    reasm = Reassembler(thief_result)
    for raw in recorded[1:]:
        reasm.feed(raw)
    assert reasm.finalize()[1] == b"recorded secret"


# ------------------------------------------------------------ whole one-way sessions


def _play(sender_end, packets: list[bytes], loops: int = 1) -> None:
    for _ in range(loops):
        for p in packets:
            sender_end.send(p)
    sender_end.close()


def test_oneway_transfer_with_seal_arriving_late(pair, tmp_path: Path) -> None:
    """Frames that arrive before the SEAL are buffered and used once it arrives."""
    alice, a_trust, bob, b_trust = pair
    src = tmp_path / "doc.txt"
    src.write_bytes(os.urandom(3000))
    packets, s_res = build_oneway_transfer(alice, a_trust, "bob", src)
    tx, rx = make_loopback_pair()
    _play(tx, packets[5:] + packets[:5])  # the camera started mid-loop
    store = SessionStore(tmp_path / "used.json")
    report = receive_file_oneway(rx, bob, b_trust, tmp_path / "out", store, timeout=5,
                                 confirm_sas=lambda _p, sas: sas == s_res.sas_text)
    assert report.path.read_bytes() == src.read_bytes()
    assert SessionStore.load(tmp_path / "used.json").is_used(s_res.session_id)


def test_oneway_replay_rejected(pair, tmp_path: Path) -> None:
    """T7: playing the same recording a second time is refused, and nothing new is written."""
    alice, a_trust, bob, b_trust = pair
    src = tmp_path / "doc.txt"
    src.write_bytes(b"pay 100 to bob")
    packets, _ = build_oneway_transfer(alice, a_trust, "bob", src)
    store = SessionStore(tmp_path / "used.json")
    for attempt in range(2):
        tx, rx = make_loopback_pair()
        _play(tx, packets)
        if attempt == 0:
            receive_file_oneway(rx, bob, b_trust, tmp_path / "out", store, timeout=5)
        else:
            with pytest.raises(HandshakeError, match="replay"):
                receive_file_oneway(rx, bob, b_trust, tmp_path / "out", store, timeout=5)
    assert [p.name for p in (tmp_path / "out").iterdir()] == ["doc.txt"]


def test_oneway_truncated_writes_nothing(pair, tmp_path: Path) -> None:
    """T17: the video ends before every chunk was seen, so there is no file and the session stays unused."""
    alice, a_trust, bob, b_trust = pair
    src = tmp_path / "doc.txt"
    src.write_bytes(os.urandom(3000))
    packets, s_res = build_oneway_transfer(alice, a_trust, "bob", src)
    tx, rx = make_loopback_pair()
    _play(tx, packets[:-4])
    store = SessionStore(tmp_path / "used.json")
    with pytest.raises(TransportClosed):
        receive_file_oneway(rx, bob, b_trust, tmp_path / "out", store, timeout=5)
    assert not (tmp_path / "out").exists()
    assert not store.is_used(s_res.session_id)  # a clean retry is still possible


def test_oneway_sas_rejected_writes_nothing(pair, tmp_path: Path) -> None:
    alice, a_trust, bob, b_trust = pair
    src = tmp_path / "doc.txt"
    src.write_bytes(b"x")
    packets, _ = build_oneway_transfer(alice, a_trust, "bob", src)
    tx, rx = make_loopback_pair()
    _play(tx, packets)
    with pytest.raises(TransferError, match="verification code"):
        receive_file_oneway(rx, bob, b_trust, tmp_path / "out", SessionStore(), timeout=5,
                            confirm_sas=lambda _p, _s: False)
    assert not (tmp_path / "out").exists()


def test_oneway_ciphertext_only_on_the_wire(pair, tmp_path: Path) -> None:
    """T10: nothing a camera can film contains the plaintext or the filename."""
    alice, a_trust, _, _ = pair
    src = tmp_path / "salaries.csv"
    src.write_bytes(b"CONFIDENTIAL-MARKER " * 50)
    packets, _ = build_oneway_transfer(alice, a_trust, "bob", src)
    wire = b"".join(packets)
    assert b"CONFIDENTIAL" not in wire and b"salaries" not in wire
