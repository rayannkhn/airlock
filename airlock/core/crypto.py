"""Key schedule, short authentication string, and per-packet AES-256-GCM.

Implements docs/design.md sections 6, 7 and 8.2. Every primitive comes from
pyca/cryptography (OpenSSL). This module only *composes* them.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import Enum

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

from airlock.core.framing import MAX_PAYLOAD, Packet, PacketType, header_bytes

KEY_SIZE = 32  # AES-256
IV_SIZE = 12  # 96-bit GCM nonce
TAG_SIZE = 16  # 128-bit GCM tag
SAS_SIZE = 4  # 32-bit short authentication string
_OKM_LENGTH = 2 * KEY_SIZE + 2 * IV_SIZE + KEY_SIZE  # 120 bytes

KEYS_INFO = b"airlock v1 keys"
SAS_INFO = b"airlock sas"


class Role(Enum):
    """Initiator = the sender of the file; responder = the receiver."""

    INITIATOR = "initiator"
    RESPONDER = "responder"


class DecryptError(Exception):
    """AEAD authentication failed: wrong key, wrong session, or tampering."""


class NonceReuseError(Exception):
    """Tried to encrypt two packets with the same seq under the same key.

    This is a programming error. It is refused because nonce reuse in GCM
    leaks the XOR of the plaintexts and allows tag forgery (threat T12).
    """


def transcript_hash(*parts: bytes) -> bytes:
    """SHA-256 over length-prefixed parts.

    Each part is prefixed with its 4-byte length, so the encoding is
    unambiguous: ("ab", "c") and ("a", "bc") hash differently. That rules out
    a whole class of splicing attacks.
    """
    h = hashlib.sha256()
    for part in parts:
        h.update(struct.pack(">I", len(part)))
        h.update(part)
    return h.digest()


@dataclass(frozen=True, repr=False)
class SessionKeys:
    """Per-session secrets, one key and IV per direction (design section 6)."""

    k_ir: bytes  # initiator -> responder encryption key
    k_ri: bytes  # responder -> initiator encryption key
    iv_ir: bytes
    iv_ri: bytes
    k_sas: bytes  # used only to derive the short authentication string

    def outbound(self, role: Role) -> tuple[bytes, bytes]:
        """(key, iv) this role uses to *encrypt*."""
        return (self.k_ir, self.iv_ir) if role is Role.INITIATOR else (self.k_ri, self.iv_ri)

    def inbound(self, role: Role) -> tuple[bytes, bytes]:
        """(key, iv) this role uses to *decrypt* what the peer sends."""
        return (self.k_ri, self.iv_ri) if role is Role.INITIATOR else (self.k_ir, self.iv_ir)

    def __repr__(self) -> str:  # never let keys reach logs or tracebacks
        return "SessionKeys(<redacted>)"


def derive_session_keys(shared_secret: bytes, session_id: bytes, th: bytes) -> SessionKeys:
    """HKDF-SHA256(ikm=shared, salt=session_id, info=label || transcript_hash).

    Putting the transcript hash in ``info`` binds the keys to every handshake
    byte. A handshake that was changed in any way gives unrelated keys.
    """
    if len(shared_secret) != 32 or len(th) != 32:
        raise ValueError("shared secret and transcript hash must be 32 bytes")
    okm = HKDF(
        algorithm=hashes.SHA256(), length=_OKM_LENGTH, salt=session_id, info=KEYS_INFO + th
    ).derive(shared_secret)
    k_ir, k_ri = okm[0:32], okm[32:64]
    iv_ir, iv_ri = okm[64:76], okm[76:88]
    k_sas = okm[88:120]
    return SessionKeys(k_ir, k_ri, iv_ir, iv_ri, k_sas)


def compute_sas(keys: SessionKeys) -> bytes:
    """32-bit short authentication string, compared over a second channel (section 7)."""
    return HKDFExpand(algorithm=hashes.SHA256(), length=SAS_SIZE, info=SAS_INFO).derive(keys.k_sas)


def format_sas(sas: bytes) -> str:
    """Human form, for example ``"9F3A-01C7"``."""
    text = sas.hex().upper()
    return f"{text[:4]}-{text[4:]}"


def make_nonce(iv: bytes, seq: int) -> bytes:
    """nonce = iv XOR seq (the TLS 1.3 construction).

    It is unique for every seq under one key. Each direction and each session
    has its own key and IV, so no (key, nonce) pair repeats anywhere.
    """
    if len(iv) != IV_SIZE:
        raise ValueError("iv must be 12 bytes")
    return (int.from_bytes(iv, "big") ^ seq).to_bytes(IV_SIZE, "big")


class PacketSealer:
    """Encrypt packets in one direction of one session."""

    def __init__(self, key: bytes, iv: bytes, session_id: bytes) -> None:
        self._aead = AESGCM(key)
        self._iv = iv
        self._session_id = session_id
        self._used_seqs: set[int] = set()  # guard against nonce reuse

    def seal(self, ptype: PacketType, seq: int, total: int, plaintext: bytes) -> Packet:
        if seq in self._used_seqs:
            raise NonceReuseError(f"seq {seq} already used in this session")
        if len(plaintext) + TAG_SIZE > MAX_PAYLOAD:
            raise ValueError("plaintext too large for one packet")
        # The header, including the final ciphertext length, is the associated
        # data, so seq/total/type/session_id are all authenticated (T4, T7, T8).
        aad = header_bytes(ptype, self._session_id, seq, total, len(plaintext) + TAG_SIZE)
        ciphertext = self._aead.encrypt(make_nonce(self._iv, seq), plaintext, aad)
        self._used_seqs.add(seq)
        return Packet(ptype, self._session_id, seq, total, ciphertext)


class PacketOpener:
    """Decrypt and authenticate packets in one direction of one session."""

    def __init__(self, key: bytes, iv: bytes, session_id: bytes) -> None:
        self._aead = AESGCM(key)
        self._iv = iv
        self._session_id = session_id

    def open(self, packet: Packet) -> bytes:
        """Return the plaintext, or raise DecryptError. Never returns unauthenticated data."""
        if packet.session_id != self._session_id:
            raise DecryptError("packet belongs to a different session")
        if len(packet.payload) < TAG_SIZE:
            raise DecryptError("ciphertext shorter than the GCM tag")
        try:
            return self._aead.decrypt(
                make_nonce(self._iv, packet.seq), packet.payload, packet.header()
            )
        except InvalidTag as exc:
            raise DecryptError("authentication tag mismatch") from exc
