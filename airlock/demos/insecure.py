"""airlock-insecure: a DELIBERATELY BROKEN variant, used only as the baseline in demo 2.

It has the same X25519 + HKDF + AES-256-GCM as AirLock, but it does **no
authentication**: no identity keys, no signatures, no trust store and no
verification code. Its purpose is to show that encryption alone does not
stop a man-in-the-middle. The authentication layer is what does.

Never use this for anything except the demo.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from airlock.core.crypto import (
    PacketOpener,
    PacketSealer,
    Role,
    SessionKeys,
    derive_session_keys,
    transcript_hash,
)
from airlock.core.framing import PacketType, decode

CHUNK = 64


class InsecurePeer:
    """One side of an unauthenticated ephemeral Diffie-Hellman exchange."""

    def __init__(self, role: Role) -> None:
        self.role = role
        self._private = X25519PrivateKey.generate()
        self.public = self._private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.keys: SessionKeys | None = None
        self.session_id = b""

    def hello(self) -> bytes:
        """Initiator's first message: session_id || public key. Anyone can forge it."""
        self.session_id = os.urandom(16)
        return self.session_id + self.public

    def on_hello(self, message: bytes) -> bytes:
        """Responder: accept ANY public key. This is the bug."""
        self.session_id, peer = message[:16], message[16:]
        self._derive(peer_initiator=peer, peer_responder=self.public, peer_public=peer)
        return self.public

    def on_reply(self, peer: bytes) -> None:
        self._derive(peer_initiator=self.public, peer_responder=peer, peer_public=peer)

    def _derive(self, peer_initiator: bytes, peer_responder: bytes, peer_public: bytes) -> None:
        shared = self._private.exchange(X25519PublicKey.from_public_bytes(peer_public))
        self.keys = derive_session_keys(
            shared, self.session_id, transcript_hash(peer_initiator, peer_responder)
        )

    def encrypt_message(self, message: bytes) -> list[bytes]:
        assert self.keys is not None
        key, iv = self.keys.outbound(self.role)
        sealer = PacketSealer(key, iv, self.session_id)
        chunks = [message[i : i + CHUNK] for i in range(0, len(message), CHUNK)]
        return [
            sealer.seal(PacketType.DATA, i, len(chunks), c).encode() for i, c in enumerate(chunks)
        ]

    def decrypt_message(self, packets: list[bytes]) -> bytes:
        assert self.keys is not None
        key, iv = self.keys.inbound(self.role)
        opener = PacketOpener(key, iv, self.session_id)
        return b"".join(opener.open(decode(p)) for p in packets)
