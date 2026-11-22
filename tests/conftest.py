"""Shared fixtures: two identities that trust each other, plus a handshake helper."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from airlock.core.handshake import HandshakeResult, Initiator, Responder
from airlock.core.identity import Identity, TrustStore


@dataclass
class Peer:
    identity: Identity
    trust: TrustStore


@pytest.fixture
def alice_bob() -> tuple[Peer, Peer]:
    """Alice (sender) and Bob (receiver), each pinning the other's key."""
    alice_id, bob_id = Identity.generate(), Identity.generate()
    alice = Peer(alice_id, TrustStore({"bob": bob_id.public_key}))
    bob = Peer(bob_id, TrustStore({"alice": alice_id.public_key}))
    return alice, bob


def run_handshake(alice: Peer, bob: Peer) -> tuple[HandshakeResult, HandshakeResult]:
    """Complete an honest in-memory handshake. Returns (initiator, responder) results."""
    initiator = Initiator(alice.identity, alice.trust)
    responder = Responder(bob.identity, bob.trust)
    m2 = responder.on_hello(initiator.start())
    m3 = initiator.on_reply(m2)
    r_result = responder.on_finish(m3)
    assert initiator.result is not None
    return initiator.result, r_result


@pytest.fixture
def session(alice_bob: tuple[Peer, Peer]) -> tuple[Peer, Peer, HandshakeResult, HandshakeResult]:
    alice, bob = alice_bob
    i_result, r_result = run_handshake(alice, bob)
    return alice, bob, i_result, r_result
