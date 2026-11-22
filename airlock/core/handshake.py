"""Three-message authenticated key exchange (docs/design.md section 5).

::

    M1  I -> R : HELLO   session_id, commit_I = H("airlock-commit" || e_I.pub)
    M2  R -> I : REPLY   e_R.pub, s_R.pub, Sign_R("airlock-R" || TH(M1, e_R.pub, s_R.pub))
    M3  I -> R : FINISH  e_I.pub, s_I.pub, Sign_I("airlock-I" || TH(M1, M2, e_I.pub, s_I.pub))

The classes are "sans-IO" state machines. They take bytes in and give bytes
out, and never touch a transport. The same code therefore runs over TCP,
QR, audio or a unit test, and attack demos can intercept every byte.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from collections import OrderedDict
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from airlock.core.crypto import (
    Role,
    SessionKeys,
    compute_sas,
    derive_session_keys,
    format_sas,
    transcript_hash,
)
from airlock.core.framing import (
    SESSION_ID_SIZE,
    FramingError,
    Packet,
    PacketType,
    decode,
)
from airlock.core.identity import (
    PUBLIC_KEY_SIZE,
    SIGNATURE_SIZE,
    Identity,
    TrustStore,
    verify_signature,
)

COMMIT_LABEL = b"airlock-commit"
#: Role labels: a responder signature can never be replayed as an initiator one.
SIG_LABEL_RESPONDER = b"airlock-R"
SIG_LABEL_INITIATOR = b"airlock-I"
_KEY_MSG_SIZE = PUBLIC_KEY_SIZE + PUBLIC_KEY_SIZE + SIGNATURE_SIZE  # 128 bytes


class HandshakeError(Exception):
    """The handshake failed. The session must be abandoned (fail closed)."""


@dataclass(frozen=True)
class HandshakeResult:
    """What a completed handshake gives the session layer."""

    role: Role
    session_id: bytes
    keys: SessionKeys
    peer_public_key: bytes
    peer_name: str
    transcript_hash: bytes
    sas: bytes

    @property
    def sas_text(self) -> str:
        return format_sas(self.sas)


def commitment(ephemeral_public: bytes) -> bytes:
    """Hash commitment to the initiator's ephemeral key (sent before the key itself)."""
    return hashlib.sha256(COMMIT_LABEL + ephemeral_public).digest()


def _raw_public(private_key: X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _x25519(private_key: X25519PrivateKey, peer_public: bytes) -> bytes:
    """X25519 with an explicit check against low-order (all-zero result) points.

    OpenSSL already refuses an all-zero shared secret. The extra check makes
    the property independent of the library version.
    """
    try:
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(peer_public))
    except ValueError as exc:
        raise HandshakeError("peer ephemeral key is invalid (low-order point)") from exc
    if not any(shared):
        raise HandshakeError("all-zero shared secret")
    return shared


def _parse(data: bytes, expected: PacketType, session_id: bytes | None) -> Packet:
    """Decode a handshake packet and check its type, session and fixed fields."""
    try:
        packet = decode(data)
    except FramingError as exc:
        raise HandshakeError(f"malformed handshake packet: {exc}") from exc
    if packet.ptype is not expected:
        raise HandshakeError(f"expected {expected.name}, got {packet.ptype.name}")
    if session_id is not None and not hmac.compare_digest(packet.session_id, session_id):
        raise HandshakeError("session_id mismatch")
    if packet.seq != 0 or packet.total != 0:
        raise HandshakeError("handshake packets must have seq = total = 0")
    return packet


def _split_key_message(payload: bytes) -> tuple[bytes, bytes, bytes]:
    if len(payload) != _KEY_MSG_SIZE:
        raise HandshakeError("handshake key message has the wrong length")
    return payload[:32], payload[32:64], payload[64:]


def _check_signature(public_key: bytes, signature: bytes, message: bytes, who: str) -> None:
    try:
        verify_signature(public_key, signature, message)
    except InvalidSignature as exc:
        raise HandshakeError(f"{who} signature is invalid") from exc


class ReplayCache:
    """Recently seen session_ids. A reused one is rejected (threat T7).

    Bounded, so a flood of HELLOs cannot exhaust memory. It is held in memory
    only. Replays across process restarts still fail, because every session
    derives fresh keys from the responder's new ephemeral key.
    """

    def __init__(self, max_entries: int = 10_000) -> None:
        self._seen: OrderedDict[bytes, None] = OrderedDict()
        self._max = max_entries

    def check_and_add(self, session_id: bytes) -> bool:
        """Return True if ``session_id`` is new. Record it either way."""
        if session_id in self._seen:
            return False
        self._seen[session_id] = None
        if len(self._seen) > self._max:
            self._seen.popitem(last=False)
        return True


class Initiator:
    """The sender's side of the handshake."""

    def __init__(
        self, identity: Identity, trust: TrustStore, session_id: bytes | None = None
    ) -> None:
        self._identity = identity
        self._trust = trust
        # 128-bit random session id from the OS CSPRNG.
        self.session_id = session_id if session_id is not None else os.urandom(SESSION_ID_SIZE)
        if len(self.session_id) != SESSION_ID_SIZE:
            raise ValueError("session_id must be 16 bytes")
        self._ephemeral: X25519PrivateKey | None = None
        self._ephemeral_public = b""
        self._m1 = b""
        self._m2 = b""
        self._m3 = b""
        self.result: HandshakeResult | None = None

    @property
    def ephemeral_key_held(self) -> bool:
        """True while the ephemeral private key is still in this object (test hook for T11)."""
        return self._ephemeral is not None

    def start(self) -> bytes:
        """Create M1. It commits to e_I without revealing it."""
        if self._m1:
            return self._m1  # idempotent: lets a lossy transport resend M1
        self._ephemeral = X25519PrivateKey.generate()
        self._ephemeral_public = _raw_public(self._ephemeral)
        self._m1 = Packet(
            PacketType.HELLO, self.session_id, 0, 0, commitment(self._ephemeral_public)
        ).encode()
        return self._m1

    def on_reply(self, data: bytes) -> bytes:
        """Verify M2 and return M3. On success ``self.result`` is set."""
        if not self._m1:
            raise HandshakeError("start() has not been called")
        if self.result is not None:
            if data == self._m2:
                return self._m3  # duplicate M2 on a lossy channel: resend M3
            raise HandshakeError("handshake already completed")

        packet = _parse(data, PacketType.REPLY, self.session_id)
        e_r, s_r, sig_r = _split_key_message(packet.payload)

        # T1/T2: the responder must be a pinned peer, and must have signed
        # everything we sent plus its own ephemeral and identity keys.
        peer_name = self._trust.name_for(s_r)
        if peer_name is None:
            raise HandshakeError("responder identity is not in the trust store")
        _check_signature(
            s_r, sig_r, SIG_LABEL_RESPONDER + transcript_hash(self._m1, e_r, s_r), "responder"
        )

        assert self._ephemeral is not None
        shared = _x25519(self._ephemeral, e_r)

        s_i = self._identity.public_key
        sig_i = self._identity.sign(
            SIG_LABEL_INITIATOR + transcript_hash(self._m1, data, self._ephemeral_public, s_i)
        )
        m3 = Packet(
            PacketType.FINISH, self.session_id, 0, 0, self._ephemeral_public + s_i + sig_i
        ).encode()

        th = transcript_hash(self._m1, data, m3)
        keys = derive_session_keys(shared, self.session_id, th)
        # T11 (forward secrecy): drop the ephemeral private key now. It is
        # never written to disk. (Python cannot zero memory; see limitations.md.)
        self._ephemeral = None
        self._m2, self._m3 = data, m3
        self.result = HandshakeResult(
            Role.INITIATOR, self.session_id, keys, s_r, peer_name, th, compute_sas(keys)
        )
        return m3


class Responder:
    """The receiver's side of the handshake."""

    def __init__(
        self, identity: Identity, trust: TrustStore, replay_cache: ReplayCache | None = None
    ) -> None:
        self._identity = identity
        self._trust = trust
        self._replay = replay_cache if replay_cache is not None else ReplayCache()
        self._ephemeral: X25519PrivateKey | None = None
        self.session_id = b""
        self._commit = b""
        self._m1 = b""
        self._m2 = b""
        self.result: HandshakeResult | None = None

    @property
    def ephemeral_key_held(self) -> bool:
        return self._ephemeral is not None

    def on_hello(self, data: bytes) -> bytes:
        """Accept M1 and return M2 (signed)."""
        if self._m1:
            if data == self._m1:
                return self._m2  # duplicate M1 on a lossy channel: resend M2
            raise HandshakeError("a handshake is already in progress")

        packet = _parse(data, PacketType.HELLO, None)
        if len(packet.payload) != 32:
            raise HandshakeError("HELLO must carry a 32-byte commitment")
        if not self._replay.check_and_add(packet.session_id):
            raise HandshakeError("session_id was already used (replay)")

        self.session_id = packet.session_id
        self._commit = packet.payload
        self._ephemeral = X25519PrivateKey.generate()  # fresh: this is R's freshness
        e_r = _raw_public(self._ephemeral)
        s_r = self._identity.public_key
        sig_r = self._identity.sign(SIG_LABEL_RESPONDER + transcript_hash(data, e_r, s_r))
        self._m1 = data
        self._m2 = Packet(PacketType.REPLY, self.session_id, 0, 0, e_r + s_r + sig_r).encode()
        return self._m2

    def on_finish(self, data: bytes) -> HandshakeResult:
        """Verify M3 and derive the session keys."""
        if not self._m2:
            raise HandshakeError("on_hello() has not succeeded")
        if self.result is not None:
            raise HandshakeError("handshake already completed")

        packet = _parse(data, PacketType.FINISH, self.session_id)
        e_i, s_i, sig_i = _split_key_message(packet.payload)

        # T3: e_I must be the key committed to in M1, before e_R was revealed.
        if not hmac.compare_digest(commitment(e_i), self._commit):
            raise HandshakeError("ephemeral key does not match the M1 commitment")

        peer_name = self._trust.name_for(s_i)
        if peer_name is None:
            raise HandshakeError("initiator identity is not in the trust store")
        _check_signature(
            s_i,
            sig_i,
            SIG_LABEL_INITIATOR + transcript_hash(self._m1, self._m2, e_i, s_i),
            "initiator",
        )

        assert self._ephemeral is not None
        shared = _x25519(self._ephemeral, e_i)
        th = transcript_hash(self._m1, self._m2, data)
        keys = derive_session_keys(shared, self.session_id, th)
        self._ephemeral = None  # T11
        self.result = HandshakeResult(
            Role.RESPONDER, self.session_id, keys, s_i, peer_name, th, compute_sas(keys)
        )
        return self.result
