"""Tests for airlock.core.handshake (threats T1, T2, T3, T7, T11, T18)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from airlock.core.framing import Packet, PacketType, decode
from airlock.core.handshake import (
    HandshakeError,
    Initiator,
    ReplayCache,
    Responder,
    commitment,
)
from airlock.core.identity import Identity, TrustStore

from conftest import Peer, run_handshake


def _flip(raw: bytes, index: int) -> bytes:
    """Flip one payload byte and re-encode, so the CRC is valid (as an attacker would do)."""
    pkt = decode(raw)
    payload = bytearray(pkt.payload)
    payload[index] ^= 0x01
    return Packet(pkt.ptype, pkt.session_id, pkt.seq, pkt.total, bytes(payload)).encode()


def test_honest_handshake_agrees(alice_bob: tuple[Peer, Peer]) -> None:
    i_res, r_res = run_handshake(*alice_bob)
    assert i_res.session_id == r_res.session_id
    assert i_res.keys.k_ir == r_res.keys.k_ir and i_res.keys.k_ri == r_res.keys.k_ri
    assert i_res.transcript_hash == r_res.transcript_hash
    assert i_res.sas == r_res.sas
    assert i_res.peer_name == "bob" and r_res.peer_name == "alice"


def test_untrusted_identity_rejected(alice_bob: tuple[Peer, Peer]) -> None:
    """T1: a peer whose key is not pinned cannot complete the handshake, in either role."""
    alice, bob = alice_bob
    mallory = Identity.generate()

    # Mallory as responder: Alice refuses M2.
    init = Initiator(alice.identity, alice.trust)
    m2 = Responder(mallory, TrustStore({"alice": alice.identity.public_key})).on_hello(init.start())
    with pytest.raises(HandshakeError, match="not in the trust store"):
        init.on_reply(m2)

    # Mallory as initiator: Bob refuses M3.
    init = Initiator(mallory, TrustStore({"bob": bob.identity.public_key}))
    resp = Responder(bob.identity, bob.trust)
    m3 = init.on_reply(resp.on_hello(init.start()))
    with pytest.raises(HandshakeError, match="not in the trust store"):
        resp.on_finish(m3)


def test_tampered_m2_rejected(alice_bob: tuple[Peer, Peer]) -> None:
    """T2: changing e_R (bytes 0..31) or the signature in M2 is detected."""
    alice, bob = alice_bob
    for index in (0, 100):
        init = Initiator(alice.identity, alice.trust)
        m2 = Responder(bob.identity, bob.trust).on_hello(init.start())
        with pytest.raises(HandshakeError, match="signature"):
            init.on_reply(_flip(m2, index))


def test_tampered_m3_rejected(alice_bob: tuple[Peer, Peer]) -> None:
    """Changing the revealed e_I breaks the commitment; changing the signature breaks verification."""
    alice, bob = alice_bob
    for index, reason in ((0, "commitment"), (100, "signature")):
        init = Initiator(alice.identity, alice.trust)
        resp = Responder(bob.identity, bob.trust)
        m3 = init.on_reply(resp.on_hello(init.start()))
        with pytest.raises(HandshakeError, match=reason):
            resp.on_finish(_flip(m3, index))


def test_mitm_key_substitution_fails(alice_bob: tuple[Peer, Peer]) -> None:
    """T2: Mallory swaps in her own ephemeral key but cannot re-sign as Bob."""
    alice, bob = alice_bob
    init = Initiator(alice.identity, alice.trust)
    m2 = decode(Responder(bob.identity, bob.trust).on_hello(init.start()))
    mallory_eph = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    forged = Packet(m2.ptype, m2.session_id, 0, 0, mallory_eph + m2.payload[32:]).encode()
    with pytest.raises(HandshakeError, match="signature"):
        init.on_reply(forged)


def test_commitment_binds_initiator_key(alice_bob: tuple[Peer, Peer]) -> None:
    """T3: an initiator cannot reveal a key other than the one it committed to."""
    alice, bob = alice_bob
    init = Initiator(alice.identity, alice.trust)
    resp = Responder(bob.identity, bob.trust)
    m1 = init.start()
    assert decode(m1).payload == commitment(init._ephemeral_public)
    m3 = decode(init.on_reply(resp.on_hello(m1)))
    other = X25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    swapped = Packet(m3.ptype, m3.session_id, 0, 0, other + m3.payload[32:]).encode()
    with pytest.raises(HandshakeError, match="commitment"):
        resp.on_finish(swapped)


def test_replayed_hello_rejected(alice_bob: tuple[Peer, Peer]) -> None:
    """T7: a responder will not run two handshakes with the same session_id."""
    alice, bob = alice_bob
    cache = ReplayCache()
    init = Initiator(alice.identity, alice.trust)
    m1 = init.start()
    resp1 = Responder(bob.identity, bob.trust, cache)
    resp1.on_finish(init.on_reply(resp1.on_hello(m1)))
    with pytest.raises(HandshakeError, match="replay"):
        Responder(bob.identity, bob.trust, cache).on_hello(m1)


def test_replayed_old_finish_fails_in_new_session(alice_bob: tuple[Peer, Peer]) -> None:
    """T7: an old M3 recorded by an attacker cannot complete a new session."""
    alice, bob = alice_bob
    init = Initiator(alice.identity, alice.trust)
    resp = Responder(bob.identity, bob.trust)
    old_m1 = init.start()
    old_m3 = init.on_reply(resp.on_hello(old_m1))
    resp.on_finish(old_m3)

    # The attacker replays old M1 to a fresh responder (no shared cache, the
    # worst case), then replays old M3. R's new e_R means the old signature
    # covers the wrong transcript.
    fresh = Responder(bob.identity, bob.trust)
    fresh.on_hello(old_m1)
    with pytest.raises(HandshakeError, match="signature"):
        fresh.on_finish(old_m3)


def test_version_mismatch_rejected(alice_bob: tuple[Peer, Peer]) -> None:
    """T18: a HELLO with an unknown version is rejected, with no downgrade path."""
    _, bob = alice_bob
    m1 = Packet(PacketType.HELLO, b"\x01" * 16, 0, 0, b"\x00" * 32, version=2).encode()
    with pytest.raises(HandshakeError, match="version"):
        Responder(bob.identity, bob.trust).on_hello(m1)


def test_low_order_point_rejected(alice_bob: tuple[Peer, Peer]) -> None:
    """A responder sending the all-zero point (forcing a known secret) is rejected."""
    alice, bob = alice_bob
    init = Initiator(alice.identity, alice.trust)
    m1 = init.start()
    # Bob is honest but the e_R he signs is a low-order point (simulates a
    # buggy or malicious peer). The signature is valid, so the X25519 check
    # is the one that has to catch it.
    from airlock.core.crypto import transcript_hash
    from airlock.core.handshake import SIG_LABEL_RESPONDER

    zero = b"\x00" * 32
    sig = bob.identity.sign(SIG_LABEL_RESPONDER + transcript_hash(m1, zero, bob.identity.public_key))
    m2 = Packet(PacketType.REPLY, init.session_id, 0, 0, zero + bob.identity.public_key + sig).encode()
    with pytest.raises(HandshakeError, match="low-order|all-zero"):
        init.on_reply(m2)


def test_forward_secrecy_keys_ephemeral(alice_bob: tuple[Peer, Peer]) -> None:
    """T11: each session has fresh keys, and ephemeral private keys are dropped afterwards."""
    alice, bob = alice_bob
    init = Initiator(alice.identity, alice.trust)
    resp = Responder(bob.identity, bob.trust)
    resp.on_finish(init.on_reply(resp.on_hello(init.start())))
    assert not init.ephemeral_key_held and not resp.ephemeral_key_held

    first, _ = run_handshake(alice, bob)
    second, _ = run_handshake(alice, bob)
    assert first.keys.k_ir != second.keys.k_ir and first.keys.k_ri != second.keys.k_ri
    assert first.session_id != second.session_id


def test_role_reflection_rejected(alice_bob: tuple[Peer, Peer]) -> None:
    """A REPLY cannot be fed back where a FINISH is expected (packet types and labels differ)."""
    alice, bob = alice_bob
    init = Initiator(alice.identity, alice.trust)
    resp = Responder(bob.identity, bob.trust)
    m2 = resp.on_hello(init.start())
    with pytest.raises(HandshakeError, match="expected FINISH"):
        resp.on_finish(m2)


def test_duplicate_messages_are_idempotent(alice_bob: tuple[Peer, Peer]) -> None:
    """On lossy channels a resent M1/M2 gets the same answer, not a new handshake."""
    alice, bob = alice_bob
    init = Initiator(alice.identity, alice.trust)
    resp = Responder(bob.identity, bob.trust)
    m1 = init.start()
    m2 = resp.on_hello(m1)
    assert resp.on_hello(m1) == m2
    m3 = init.on_reply(m2)
    assert init.on_reply(m2) == m3
    resp.on_finish(m3)
