"""Wire format: packet encode/decode and the CRC32 noise check.

Implements docs/design.md section 8.1. Every byte that crosses a transport,
handshake or data, is one of these packets::

    magic(2) | version(1) | type(1) | session_id(16) | seq(4) | total(4) |
    length(2) | payload(length) | crc32(4)

Security note: CRC32 is NOT an integrity mechanism. Anyone can recompute it.
It only lets the receiver drop noise-damaged packets cheaply, before any
crypto runs. Integrity comes from AES-GCM (data) and Ed25519 (handshake).
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass
from enum import IntEnum

from airlock import PROTOCOL_VERSION

MAGIC = 0x414C  # "AL"
HEADER_FORMAT = ">HBB16sIIH"  # big-endian, no padding
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 30 bytes
CRC_SIZE = 4
SESSION_ID_SIZE = 16
#: Hard cap on payload size. It bounds memory per packet and stops a forged
#: length field from causing a huge allocation (threat T16).
MAX_PAYLOAD = 4096
MAX_PACKET_SIZE = HEADER_SIZE + MAX_PAYLOAD + CRC_SIZE
MAX_U32 = 0xFFFFFFFF


class PacketType(IntEnum):
    """Packet kinds. Covered by the transcript hash or the AEAD associated data."""

    HELLO = 1  # handshake M1
    REPLY = 2  # handshake M2
    FINISH = 3  # handshake M3
    MANIFEST = 4  # encrypted, seq 0
    DATA = 5  # encrypted, seq 1..N
    RECEIPT = 6  # encrypted acknowledgement, receiver -> sender
    SEAL = 7  # one-way mode: the whole handshake in one signed packet


class FramingError(ValueError):
    """The bytes are not a well-formed AirLock packet."""


class CrcError(FramingError):
    """The checksum does not match. Almost always channel noise, not an attack."""


class VersionError(FramingError):
    """Unsupported protocol version. There is no fallback (threat T18)."""


def header_bytes(
    ptype: PacketType,
    session_id: bytes,
    seq: int,
    total: int,
    payload_length: int,
    version: int = PROTOCOL_VERSION,
) -> bytes:
    """Serialize a header.

    The sealer calls this *before* encrypting, because the header is the AEAD
    associated data, and its length field must already hold the length of
    the ciphertext plus the tag.
    """
    if len(session_id) != SESSION_ID_SIZE:
        raise FramingError("session_id must be 16 bytes")
    if not (0 <= seq <= MAX_U32 and 0 <= total <= MAX_U32):
        raise FramingError("seq/total out of range")
    if not 0 <= payload_length <= MAX_PAYLOAD:
        raise FramingError(f"payload too large ({payload_length} > {MAX_PAYLOAD})")
    return struct.pack(
        HEADER_FORMAT, MAGIC, version, int(ptype), bytes(session_id), seq, total, payload_length
    )


@dataclass(frozen=True)
class Packet:
    """One decoded packet. ``payload`` is ciphertext for MANIFEST/DATA/RECEIPT."""

    ptype: PacketType
    session_id: bytes
    seq: int
    total: int
    payload: bytes
    version: int = PROTOCOL_VERSION

    def header(self) -> bytes:
        """The 30 header bytes, also used as the AEAD associated data."""
        return header_bytes(
            self.ptype, self.session_id, self.seq, self.total, len(self.payload), self.version
        )

    def encode(self) -> bytes:
        """Serialize, appending CRC32 over header and payload."""
        body = self.header() + bytes(self.payload)
        return body + struct.pack(">I", zlib.crc32(body))


def decode(data: bytes) -> Packet:
    """Parse and validate one packet. Strict: any anomaly raises FramingError.

    The order of checks matters: size limits come first (cheap, and they
    bound work), then the CRC (classify noise), then the structural fields.
    """
    data = bytes(data)
    if len(data) < HEADER_SIZE + CRC_SIZE:
        raise FramingError(f"packet too short ({len(data)} bytes)")
    if len(data) > MAX_PACKET_SIZE:
        raise FramingError(f"packet too large ({len(data)} bytes)")

    body, crc_field = data[:-CRC_SIZE], data[-CRC_SIZE:]
    if zlib.crc32(body) != struct.unpack(">I", crc_field)[0]:
        raise CrcError("CRC mismatch")

    magic, version, ptype_raw, session_id, seq, total, length = struct.unpack_from(
        HEADER_FORMAT, body
    )
    if magic != MAGIC:
        raise FramingError("bad magic")
    if version != PROTOCOL_VERSION:
        raise VersionError(f"unsupported protocol version {version}")
    try:
        ptype = PacketType(ptype_raw)
    except ValueError as exc:
        raise FramingError(f"unknown packet type {ptype_raw}") from exc

    payload = body[HEADER_SIZE:]
    # The declared length must equal the real length. This rejects
    # truncated and padded packets.
    if length != len(payload):
        raise FramingError(f"length field {length} != actual {len(payload)}")
    return Packet(ptype, session_id, seq, total, payload, version)
