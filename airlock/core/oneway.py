"""One-way mode: the whole key exchange in a single signed packet (design section 10).

Physical channels like "phone screen -> laptop webcam" carry data in one
direction only, so an interactive handshake is impossible there. Instead the
sender encrypts to the receiver's pinned X25519 *receiving key*::

    SEAL (seq 0, total 0), payload:
        timestamp(8) | recipient_receive_key(32) | e_S.pub(32) | s_S.pub(32) |
        sig = Sign(s_S, "airlock-seal" || TH(version, session_id, all fields above))

    shared = X25519(e_S, R_recv)            (receiver: X25519(R_recv, e_S))
    keys   = HKDF(shared, salt=session_id, info="airlock v1 keys" || TH(SEAL))

The manifest and chunks that follow are exactly the interactive-mode packets,
so the same Reassembler, AEAD and fail-closed logic is reused unchanged.

Trade-offs compared with the interactive handshake (see threat_model.md):

- Forward secrecy holds against later theft of the *sender's* keys, but NOT
  against theft of the *receiver's* receiving key. Whoever steals it can
  decrypt every recorded SEAL video addressed to it.
- The receiver contributes no fresh randomness. Replays are therefore
  stopped by a signed timestamp window plus a persistent store of used
  session ids (:class:`SessionStore`).
"""

from __future__ import annotations

import json
import os
import struct
import tempfile
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from airlock import PROTOCOL_VERSION
from airlock.core.crypto import Role, compute_sas, derive_session_keys, transcript_hash
from airlock.core.framing import SESSION_ID_SIZE, FramingError, Packet, PacketType, decode
from airlock.core.handshake import HandshakeError, HandshakeResult
from airlock.core.identity import (
    PUBLIC_KEY_SIZE,
    SIGNATURE_SIZE,
    Identity,
    IdentityError,
    TrustStore,
    verify_signature,
)

SEAL_LABEL = b"airlock-seal"
SEAL_PAYLOAD_SIZE = 8 + 3 * PUBLIC_KEY_SIZE + SIGNATURE_SIZE  # 168 bytes
DEFAULT_MAX_AGE = 24 * 3600  # seconds a SEAL stays acceptable
DEFAULT_MAX_FUTURE_SKEW = 10 * 60  # tolerate clocks up to 10 min apart
SESSION_STORE_FORMAT = 1


def _signed_input(session_id: bytes, unsigned_payload: bytes) -> bytes:
    """What the sender signs. Covers the version, so there is no downgrade (T18)."""
    return SEAL_LABEL + transcript_hash(bytes([PROTOCOL_VERSION]), session_id, unsigned_payload)


def create_seal(
    identity: Identity,
    trust: TrustStore,
    recipient: str,
    *,
    now: float | None = None,
    session_id: bytes | None = None,
) -> tuple[bytes, HandshakeResult]:
    """Sender side. Returns (encoded SEAL packet, initiator-role HandshakeResult)."""
    recipient_key = trust.receive_key_for(recipient)
    recipient_sign_key = dict(trust.items()).get(recipient)
    if recipient_key is None or recipient_sign_key is None:
        raise HandshakeError(
            f"no receiving key pinned for '{recipient}': add their identity.card with 'trust add'"
        )
    sid = session_id if session_id is not None else os.urandom(SESSION_ID_SIZE)
    timestamp = int(now if now is not None else time.time())

    ephemeral = X25519PrivateKey.generate()  # fresh per transfer, never stored
    e_pub = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    unsigned = struct.pack(">Q", timestamp) + recipient_key + e_pub + identity.public_key
    signature = identity.sign(_signed_input(sid, unsigned))
    seal = Packet(PacketType.SEAL, sid, 0, 0, unsigned + signature).encode()

    try:
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_key))
    except ValueError as exc:
        raise HandshakeError("pinned receiving key is invalid") from exc
    # Binding the keys to the full SEAL packet (signature included) means any
    # change to it gives unrelated keys.
    th = transcript_hash(seal)
    keys = derive_session_keys(shared, sid, th)
    del ephemeral  # forward secrecy for the sender side (memory wiping: see limitations.md)
    result = HandshakeResult(
        Role.INITIATOR, sid, keys, recipient_sign_key, recipient, th, compute_sas(keys)
    )
    return seal, result


class SessionStore:
    """Persistent set of session ids already received (one-way replay protection, T7).

    Entries older than the timestamp window are pruned. Those SEALs are
    rejected by the timestamp check anyway, so the file stays small without
    weakening anything.
    """

    def __init__(self, path: Path | None = None, sessions: dict[str, int] | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self._sessions: dict[str, int] = dict(sessions or {})

    @classmethod
    def load(cls, path: Path) -> SessionStore:
        path = Path(path)
        if not path.exists():
            return cls(path)
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if doc.get("format") != SESSION_STORE_FORMAT:
                raise IdentityError(f"unsupported session store format in {path}")
            sessions = {str(k): int(v) for k, v in doc["sessions"].items()}
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            # Fail closed: a corrupt store must not silently become "nothing seen".
            raise IdentityError(f"corrupt session store {path}: {exc}") from exc
        return cls(path, sessions)

    def is_used(self, session_id: bytes) -> bool:
        return session_id.hex() in self._sessions

    def mark_used(self, session_id: bytes, timestamp: int) -> None:
        self._sessions[session_id.hex()] = int(timestamp)

    def prune(self, now: float, max_age: int = DEFAULT_MAX_AGE) -> None:
        cutoff = now - max_age - DEFAULT_MAX_FUTURE_SKEW
        self._sessions = {k: v for k, v in self._sessions.items() if v >= cutoff}

    def save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".sessions-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"format": SESSION_STORE_FORMAT, "sessions": self._sessions}, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def __len__(self) -> int:
        return len(self._sessions)


def seal_timestamp(seal: bytes) -> int:
    """Timestamp field of an already-verified SEAL (for SessionStore.mark_used)."""
    return struct.unpack_from(">Q", decode(seal).payload)[0]


def open_seal(
    identity: Identity,
    trust: TrustStore,
    data: bytes,
    store: SessionStore,
    *,
    now: float | None = None,
    max_age: int = DEFAULT_MAX_AGE,
) -> HandshakeResult:
    """Receiver side. Verify a SEAL and derive the session keys. Raises HandshakeError.

    Checks, in order: format, addressed to us, sender trusted (T1), signature
    (T2), timestamp window and unused session id (T7), then key agreement.
    """
    try:
        packet = decode(data)
    except FramingError as exc:
        raise HandshakeError(f"malformed SEAL: {exc}") from exc
    if packet.ptype is not PacketType.SEAL or packet.seq != 0 or packet.total != 0:
        raise HandshakeError("not a SEAL packet")
    if len(packet.payload) != SEAL_PAYLOAD_SIZE:
        raise HandshakeError("SEAL has the wrong length")

    payload = packet.payload
    (timestamp,) = struct.unpack_from(">Q", payload, 0)
    recipient_key = payload[8:40]
    e_pub = payload[40:72]
    sender_key = payload[72:104]
    signature = payload[104:]
    unsigned = payload[:104]

    own_key = identity.receive_public_key
    if own_key is None:
        raise HandshakeError("this identity has no receiving key (run keygen again)")
    if recipient_key != own_key:
        raise HandshakeError("this transfer is addressed to someone else")

    peer_name = trust.name_for(sender_key)
    if peer_name is None:
        raise HandshakeError("sender identity is not in the trust store")
    try:
        verify_signature(sender_key, signature, _signed_input(packet.session_id, unsigned))
    except InvalidSignature as exc:
        raise HandshakeError("sender signature is invalid") from exc

    current = now if now is not None else time.time()
    if timestamp > current + DEFAULT_MAX_FUTURE_SKEW:
        raise HandshakeError("SEAL timestamp is in the future (check the clocks)")
    if current - timestamp > max_age:
        hours = (current - timestamp) / 3600
        raise HandshakeError(f"SEAL is too old ({hours:.1f} h): possible replay")
    if store.is_used(packet.session_id):
        raise HandshakeError("this session was already received (replay)")

    try:
        shared = identity.receive_exchange(e_pub)
    except IdentityError as exc:
        raise HandshakeError(str(exc)) from exc
    th = transcript_hash(bytes(data))
    keys = derive_session_keys(shared, packet.session_id, th)
    return HandshakeResult(
        Role.RESPONDER, packet.session_id, keys, sender_key, peer_name, th, compute_sas(keys)
    )
