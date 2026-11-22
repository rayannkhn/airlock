"""File transfer on top of a completed handshake (docs/design.md sections 8.3-8.5).

Sender: ``build_transfer_packets`` turns a file into an encrypted, signed
manifest (seq 0) followed by encrypted chunks (seq 1..N).

Receiver: ``Reassembler`` accepts packets in any order, possibly duplicated
or corrupted. ``finalize`` releases the plaintext only after every check
passes, and ``write_file_atomic`` puts it on disk in one atomic step.

``send_file`` / ``receive_file`` drive a whole session over any Transport.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import tempfile
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from cryptography.exceptions import InvalidSignature

from airlock.core.crypto import (
    TAG_SIZE,
    DecryptError,
    PacketOpener,
    PacketSealer,
    Role,
)
from airlock.core.framing import (
    MAX_PAYLOAD,
    MAX_U32,
    CrcError,
    FramingError,
    PacketType,
    decode,
)
from airlock.core.handshake import HandshakeResult, Initiator, ReplayCache, Responder
from airlock.core.identity import SIGNATURE_SIZE, Identity, TrustStore, verify_signature
from airlock.core.oneway import (
    DEFAULT_MAX_AGE,
    SessionStore,
    create_seal,
    open_seal,
    seal_timestamp,
)

if TYPE_CHECKING:  # type hints only: the core never depends on a concrete transport
    from airlock.transports.base import Transport

DEFAULT_CHUNK_SIZE = 200
MAX_CHUNK_SIZE = MAX_PAYLOAD - TAG_SIZE
DEFAULT_MAX_FILE_SIZE = 16 * 1024 * 1024  # receiver keeps everything in RAM
DEFAULT_MAX_AEAD_FAILURES = 32
MAX_FILENAME_BYTES = 255
MANIFEST_LABEL = b"airlock-manifest"

_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10)}
_FORBIDDEN_CHARS = set('<>:"/\\|?*')


class TransferError(Exception):
    """The transfer must be aborted. Nothing is written to disk."""


def sanitize_filename(name: str) -> str:
    """Reduce an untrusted filename to a safe basename on every OS (threat T6).

    - Removes every directory component (both ``/`` and ``\\``), so
      ``../../.bashrc`` becomes ``bashrc``.
    - Drops control characters and characters that Windows forbids.
    - Strips leading and trailing dots and spaces (no hidden files, no
      ``..``, and Windows silently drops trailing dots).
    - Prefixes Windows reserved device names (CON, NUL, COM1, ...).
    - Truncates to 255 UTF-8 bytes and keeps the extension where possible.
    """
    base = name.replace("\\", "/").split("/")[-1]
    base = "".join(ch for ch in base if ch.isprintable() and ch not in _FORBIDDEN_CHARS)
    base = base.strip(" .")
    if not base:
        base = "received.bin"
    if base.split(".")[0].upper() in _WINDOWS_RESERVED:
        base = "_" + base
    if len(base.encode("utf-8")) > MAX_FILENAME_BYTES:
        stem, dot, ext = base.rpartition(".")
        suffix = (dot + ext) if stem and len((dot + ext).encode("utf-8")) <= 16 else ""
        head = base[: len(base) - len(suffix)]
        while len((head + suffix).encode("utf-8")) > MAX_FILENAME_BYTES:
            head = head[:-1]
        base = head + suffix
    return base


@dataclass(frozen=True)
class Manifest:
    """File metadata, signed by the sender and bound to the session id."""

    filename: str
    size: int
    sha256: bytes
    chunk_count: int
    signature: bytes = b""

    def _fields(self) -> bytes:
        name = self.filename.encode("utf-8")
        if len(name) > MAX_FILENAME_BYTES:
            raise TransferError("filename too long")
        return (
            struct.pack(">H", len(name))
            + name
            + struct.pack(">Q", self.size)
            + self.sha256
            + struct.pack(">I", self.chunk_count)
        )

    def signing_input(self, session_id: bytes) -> bytes:
        # The session id is signed too, so a manifest cannot be replayed into another session.
        return MANIFEST_LABEL + session_id + self._fields()

    def sign(self, identity: Identity, session_id: bytes) -> Manifest:
        return replace(self, signature=identity.sign(self.signing_input(session_id)))

    def verify(self, public_key: bytes, session_id: bytes) -> None:
        try:
            verify_signature(public_key, self.signature, self.signing_input(session_id))
        except InvalidSignature as exc:
            raise TransferError("manifest signature is invalid") from exc

    def encode(self) -> bytes:
        return self._fields() + self.signature

    @classmethod
    def decode(cls, data: bytes) -> Manifest:
        """Strict parser. Any trailing or missing byte is an error."""
        try:
            (name_len,) = struct.unpack_from(">H", data, 0)
            offset = 2
            if name_len > MAX_FILENAME_BYTES:
                raise TransferError("filename too long")
            filename = data[offset : offset + name_len].decode("utf-8")
            offset += name_len
            (size,) = struct.unpack_from(">Q", data, offset)
            offset += 8
            sha = data[offset : offset + 32]
            offset += 32
            (chunk_count,) = struct.unpack_from(">I", data, offset)
            offset += 4
            signature = data[offset:]
        except (struct.error, UnicodeDecodeError) as exc:
            raise TransferError("malformed manifest") from exc
        if len(sha) != 32 or len(signature) != SIGNATURE_SIZE:
            raise TransferError("malformed manifest")
        return cls(filename, size, sha, chunk_count, signature)


def build_transfer_packets(
    result: HandshakeResult,
    identity: Identity,
    filename: str,
    data: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> list[bytes]:
    """Encrypt a file into wire packets: [manifest, chunk_1, ..., chunk_N]."""
    if result.role is not Role.INITIATOR:
        raise TransferError("only the initiator sends files")
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise TransferError(f"chunk size must be 1..{MAX_CHUNK_SIZE}")
    chunks = [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]
    total = len(chunks) + 1
    if total > MAX_U32:
        raise TransferError("file too large for this chunk size")

    manifest = Manifest(
        sanitize_filename(filename), len(data), hashlib.sha256(data).digest(), len(chunks)
    ).sign(identity, result.session_id)

    key, iv = result.keys.outbound(result.role)
    sealer = PacketSealer(key, iv, result.session_id)
    packets = [sealer.seal(PacketType.MANIFEST, 0, total, manifest.encode()).encode()]
    for index, chunk in enumerate(chunks, start=1):
        packets.append(sealer.seal(PacketType.DATA, index, total, chunk).encode())
    return packets


def build_receipt(result: HandshakeResult, file_sha256: bytes) -> bytes:
    """Encrypted acknowledgement from receiver to sender: "I got exactly this file"."""
    if result.role is not Role.RESPONDER:
        raise TransferError("only the responder sends receipts")
    key, iv = result.keys.outbound(result.role)
    return PacketSealer(key, iv, result.session_id).seal(
        PacketType.RECEIPT, 0, 1, file_sha256
    ).encode()


def verify_receipt(result: HandshakeResult, data: bytes, expected_sha256: bytes) -> None:
    """Check that the receipt is authentic and names the file that was sent."""
    try:
        packet = decode(data)
    except FramingError as exc:
        raise TransferError(f"malformed receipt: {exc}") from exc
    if packet.ptype is not PacketType.RECEIPT or packet.seq != 0 or packet.total != 1:
        raise TransferError("not a receipt packet")
    key, iv = result.keys.inbound(result.role)
    try:
        acknowledged = PacketOpener(key, iv, result.session_id).open(packet)
    except DecryptError as exc:
        raise TransferError("receipt failed authentication") from exc
    if not hmac.compare_digest(acknowledged, expected_sha256):
        raise TransferError("receiver acknowledged a different file")


@dataclass
class ReceiveStats:
    accepted: int = 0
    duplicates: int = 0
    crc_errors: int = 0
    rejected: int = 0
    aead_failures: int = 0


class Reassembler:
    """Collects authenticated chunks in memory. It never writes to disk."""

    def __init__(
        self,
        result: HandshakeResult,
        *,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_aead_failures: int = DEFAULT_MAX_AEAD_FAILURES,
    ) -> None:
        if result.role is not Role.RESPONDER:
            raise TransferError("only the responder reassembles files")
        self._result = result
        key, iv = result.keys.inbound(result.role)
        self._opener = PacketOpener(key, iv, result.session_id)
        self._max_file_size = max_file_size
        self._max_aead_failures = max_aead_failures
        self._total: int | None = None
        self._manifest: Manifest | None = None
        self._chunks: dict[int, bytes] = {}
        self._buffered = 0
        self.stats = ReceiveStats()

    @property
    def total(self) -> int | None:
        return self._total

    @property
    def received(self) -> int:
        return len(self._chunks) + (1 if self._manifest is not None else 0)

    @property
    def complete(self) -> bool:
        return self._total is not None and self.received == self._total

    def feed(self, raw: bytes) -> bool:
        """Process one datagram. Returns True if it was new and authentic.

        Noise and forgeries are dropped silently and counted. A TransferError
        is raised only when the transfer can no longer succeed safely.
        """
        try:
            packet = decode(raw)
        except CrcError:
            self.stats.crc_errors += 1  # noise: wait for a retransmission
            return False
        except FramingError:
            self.stats.rejected += 1
            return False

        sid = self._result.session_id
        if packet.ptype not in (PacketType.MANIFEST, PacketType.DATA):
            self.stats.rejected += 1
            return False
        if not hmac.compare_digest(packet.session_id, sid):
            self.stats.rejected += 1  # T7: packet from another (old) session
            return False
        if packet.total < 1 or packet.seq >= packet.total:
            self.stats.rejected += 1
            return False
        if (packet.seq == 0) != (packet.ptype is PacketType.MANIFEST):
            self.stats.rejected += 1
            return False
        if self._total is not None and packet.total != self._total:
            self.stats.rejected += 1
            return False
        if packet.seq in self._chunks or (packet.seq == 0 and self._manifest is not None):
            self.stats.duplicates += 1  # T8: normal when a QR loop repeats frames
            return False

        try:
            plaintext = self._opener.open(packet)
        except DecryptError:
            # T4/T15: count forgeries. Many in one session means active injection.
            self.stats.aead_failures += 1
            if self.stats.aead_failures >= self._max_aead_failures:
                raise TransferError(
                    f"{self.stats.aead_failures} packets failed authentication: "
                    "active tampering suspected, aborting"
                ) from None
            return False

        # From here on, the packet is authentic: only the session peer has the key.
        if self._total is None:
            self._total = packet.total

        if packet.seq == 0:
            manifest = Manifest.decode(plaintext)
            manifest.verify(self._result.peer_public_key, sid)  # T5
            if manifest.chunk_count + 1 != packet.total:
                raise TransferError("manifest chunk count disagrees with packet total")
            if manifest.size > self._max_file_size:
                raise TransferError(
                    f"file is {manifest.size} bytes; limit is {self._max_file_size}"
                )
            self._manifest = manifest
        else:
            self._buffered += len(plaintext)
            if self._buffered > self._max_file_size:
                raise TransferError("received data exceeds the size limit")
            self._chunks[packet.seq] = plaintext
        self.stats.accepted += 1
        return True

    def finalize(self) -> tuple[Manifest, bytes]:
        """Return (manifest, plaintext) after the end-to-end checks. Raises if incomplete."""
        if not self.complete or self._manifest is None or self._total is None:
            raise TransferError(
                f"incomplete transfer: {self.received} of {self._total or '?'} packets"
            )
        data = b"".join(self._chunks[i] for i in range(1, self._total))
        if len(data) != self._manifest.size:
            raise TransferError("size does not match the manifest")
        if not hmac.compare_digest(hashlib.sha256(data).digest(), self._manifest.sha256):
            raise TransferError("SHA-256 does not match the manifest")
        return self._manifest, data

    def discard(self) -> None:
        """Drop every buffered chunk (on abort or after writing)."""
        self._chunks.clear()
        self._buffered = 0


def _unique_path(path: Path) -> Path:
    """Never overwrite an existing file: append ' (1)', ' (2)', ..."""
    if not path.exists():
        return path
    for n in range(1, 10_000):
        candidate = path.with_name(f"{path.stem} ({n}){path.suffix}")
        if not candidate.exists():
            return candidate
    raise TransferError("could not find a free filename")


def write_file_atomic(out_dir: Path, filename: str, data: bytes) -> Path:
    """Write verified plaintext so that the final name appears only when the file is complete.

    Steps: temp file in the same directory, fsync, then os.replace(), which
    is atomic on POSIX and on Windows (same volume). A crash leaves at most
    a ``.airlock-*.part`` temp file. The final name never refers to a
    partial file (threat T17).
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = _unique_path(out_dir / sanitize_filename(filename))
    fd, tmp = tempfile.mkstemp(dir=out_dir, prefix=".airlock-", suffix=".part")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


# --------------------------------------------------------------------------
# Whole-session drivers (used by the CLI, the tests and later the demos)
# --------------------------------------------------------------------------


@dataclass
class SendReport:
    peer_name: str
    sas: str
    packets: int
    bytes_sent: int
    receipt_verified: bool


@dataclass
class ReceiveReport:
    peer_name: str
    sas: str
    path: Path
    size: int
    stats: ReceiveStats = field(default_factory=ReceiveStats)


def send_file(
    transport: Transport,
    identity: Identity,
    trust: TrustStore,
    path: Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    timeout: float = 30.0,
    wait_for_receipt: bool = True,
    receipt_timeout: float = 600.0,
    on_sas: Callable[[str, str], None] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> SendReport:
    """Run handshake + transfer as the initiator. Raises on any failure."""
    path = Path(path)
    data = path.read_bytes()  # read first so a bad path fails before the handshake

    initiator = Initiator(identity, trust)
    transport.send(initiator.start())
    transport.send(initiator.on_reply(transport.receive(timeout)))
    result = initiator.result
    assert result is not None
    if on_sas:
        on_sas(result.peer_name, result.sas_text)

    packets = build_transfer_packets(result, identity, path.name, data, chunk_size)
    for index, packet in enumerate(packets, start=1):
        transport.send(packet)
        if on_progress:
            on_progress(index, len(packets))

    verified = False
    if wait_for_receipt:
        verify_receipt(result, transport.receive(receipt_timeout), hashlib.sha256(data).digest())
        verified = True
    return SendReport(result.peer_name, result.sas_text, len(packets), len(data), verified)


def receive_file(
    transport: Transport,
    identity: Identity,
    trust: TrustStore,
    out_dir: Path,
    *,
    timeout: float = 30.0,
    first_timeout: float | None = None,
    confirm_sas: Callable[[str, str], bool] | None = None,
    send_receipt: bool = True,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_aead_failures: int = DEFAULT_MAX_AEAD_FAILURES,
    replay_cache: ReplayCache | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> ReceiveReport:
    """Run handshake + transfer as the responder. Writes the file only if everything verifies.

    ``confirm_sas(peer_name, code)`` is called after the data has been fully
    verified and *before* anything is written. Returning False aborts.
    ``first_timeout`` applies to the first packet (None = wait forever).
    """
    responder = Responder(identity, trust, replay_cache)
    transport.send(responder.on_hello(transport.receive(first_timeout)))
    result = responder.on_finish(transport.receive(timeout))

    reassembler = Reassembler(
        result, max_file_size=max_file_size, max_aead_failures=max_aead_failures
    )
    try:
        while not reassembler.complete:
            if reassembler.feed(transport.receive(timeout)) and on_progress:
                on_progress(reassembler.received, reassembler.total or 0)
        manifest, data = reassembler.finalize()
        if confirm_sas is not None and not confirm_sas(result.peer_name, result.sas_text):
            raise TransferError("verification code rejected; file discarded")
        written = write_file_atomic(Path(out_dir), manifest.filename, data)
    finally:
        # Fail closed: on any exception (including a transport timeout or
        # Ctrl-C) the buffered plaintext is dropped and nothing was written.
        reassembler.discard()

    if send_receipt:
        transport.send(build_receipt(result, manifest.sha256))
    return ReceiveReport(result.peer_name, result.sas_text, written, manifest.size, reassembler.stats)


# --------------------------------------------------------------------------
# One-way mode driver (design section 10): no return channel at all
# --------------------------------------------------------------------------

#: Frames that arrive before the SEAL are buffered (still encrypted). The cap
#: stops an attacker from filling memory with frames that never get a SEAL.
MAX_PENDING_FRAMES = 4096


def build_oneway_transfer(
    identity: Identity,
    trust: TrustStore,
    recipient: str,
    path: Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[list[bytes], HandshakeResult]:
    """Return ([SEAL, manifest, chunk_1..N], sender result) for a file."""
    path = Path(path)
    data = path.read_bytes()
    seal, result = create_seal(identity, trust, recipient)
    packets = build_transfer_packets(result, identity, path.name, data, chunk_size)
    return [seal, *packets], result


def receive_file_oneway(
    transport: Transport,
    identity: Identity,
    trust: TrustStore,
    out_dir: Path,
    store: SessionStore,
    *,
    timeout: float = 60.0,
    confirm_sas: Callable[[str, str], bool] | None = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_aead_failures: int = DEFAULT_MAX_AEAD_FAILURES,
    max_age: int | None = None,
    on_authenticated: Callable[[str], None] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> ReceiveReport:
    """Receive a one-way transfer (for example QR frames from a video).

    Every frame comes from the untrusted transport. Nothing is decrypted until
    a valid SEAL from a trusted sender arrives, and nothing is written until
    every check, including the user's verification-code comparison, passes.
    """
    pending: list[bytes] = []
    result: HandshakeResult | None = None
    reassembler: Reassembler | None = None
    seal_bytes = b""
    try:
        while reassembler is None or not reassembler.complete:
            raw = transport.receive(timeout)
            if reassembler is None:
                try:
                    is_seal = decode(raw).ptype is PacketType.SEAL
                except FramingError:
                    continue  # noise before the SEAL: drop
                if not is_seal:
                    if len(pending) < MAX_PENDING_FRAMES:
                        pending.append(raw)
                    continue
                # Fail closed: an untrusted, forged, expired or replayed SEAL
                # aborts the whole session (HandshakeError propagates).
                result = open_seal(
                    identity, trust, raw, store,
                    max_age=max_age if max_age is not None else DEFAULT_MAX_AGE,
                )
                seal_bytes = raw
                reassembler = Reassembler(
                    result, max_file_size=max_file_size, max_aead_failures=max_aead_failures
                )
                if on_authenticated:
                    on_authenticated(result.peer_name)
                for early in pending:
                    reassembler.feed(early)
                pending.clear()
            elif reassembler.feed(raw) and on_progress:
                on_progress(reassembler.received, reassembler.total or 0)

        assert result is not None
        manifest, data = reassembler.finalize()
        if confirm_sas is not None and not confirm_sas(result.peer_name, result.sas_text):
            raise TransferError("verification code rejected; file discarded")
        written = write_file_atomic(Path(out_dir), manifest.filename, data)
        # Record the session only after success. A failed attempt (camera
        # moved away, user said "no") can be retried with the same video,
        # and nothing was written by it.
        store.mark_used(result.session_id, seal_timestamp(seal_bytes))
        store.prune(time.time())
        store.save()
    finally:
        pending.clear()
        if reassembler is not None:
            reassembler.discard()
    return ReceiveReport(result.peer_name, result.sas_text, written, manifest.size, reassembler.stats)
