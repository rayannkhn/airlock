"""Long-term identities, fingerprints, contact cards and the trust store.

Implements docs/design.md section 4. Each user has two long-term keys:

- an **Ed25519 signing key**: the identity itself. Its fingerprint is what
  people compare in person.
- an **X25519 receiving key**: used only by the one-way mode (design
  section 10), where a sender encrypts to the receiver without any reply.
  It is never used for signing, and the Ed25519 key is never used for key
  agreement. Mixing the two is a known anti-pattern.

The receiving key is bound to the identity by a self-signed **contact card**
(``identity.card``). The card is signed by the Ed25519 key, so once the
fingerprint has been checked in person, the receiving key is authentic too.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import Iterator

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64
#: 160 bits of SHA-256 are shown to humans. A second-preimage attack on a
#: specific fingerprint would need about 2^160 work.
FINGERPRINT_BYTES = 20
MAX_PEER_NAME = 64
TRUST_STORE_FORMAT = 1
CARD_FORMAT = 1
CARD_LABEL = b"airlock-card"


class IdentityError(Exception):
    """A key file or trust store could not be used. The caller must not continue."""


class PassphraseRequired(IdentityError):
    """The private key file is encrypted and no passphrase was given."""


def _check_public_key(public_key: bytes) -> None:
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_SIZE:
        raise IdentityError("a public key must be exactly 32 bytes")


def fingerprint(public_key: bytes) -> str:
    """Return the human-comparable fingerprint of a raw Ed25519 public key.

    Format: SHA-256 of the 32 raw key bytes, truncated to 160 bits, shown as
    10 upper-case hex groups of 4 characters, for example ``3F2A 9C1D ...``.
    """
    _check_public_key(public_key)
    hex_digest = hashlib.sha256(bytes(public_key)).digest()[:FINGERPRINT_BYTES].hex().upper()
    return " ".join(hex_digest[i : i + 4] for i in range(0, len(hex_digest), 4))


def verify_signature(public_key: bytes, signature: bytes, message: bytes) -> None:
    """Verify an Ed25519 signature. Raises InvalidSignature on any failure.

    Malformed keys and signatures are reported as InvalidSignature too, so
    callers have one failure path. That keeps the "fail closed" logic simple.
    """
    _check_public_key(public_key)
    if len(signature) != SIGNATURE_SIZE:
        raise InvalidSignature("signature must be 64 bytes")
    try:
        key = Ed25519PublicKey.from_public_bytes(bytes(public_key))
    except ValueError as exc:  # not a valid curve point encoding
        raise InvalidSignature("invalid public key") from exc
    key.verify(signature, message)  # raises InvalidSignature


def _write_new_file(path: Path, data: bytes, mode: int, overwrite: bool) -> None:
    """Write ``data`` to ``path`` with permission ``mode``.

    Unless ``overwrite`` is set, the file is opened with O_EXCL. This makes it
    impossible to replace an existing identity key by accident, which would
    lock the user out of every peer that pinned the old key.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    flags |= getattr(os, "O_BINARY", 0)  # Windows: no newline translation
    try:
        fd = os.open(path, flags, mode)
    except FileExistsError as exc:
        raise IdentityError(f"{path} already exists (use --force to overwrite)") from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    # O_TRUNC keeps the old mode of an existing file, so set it explicitly.
    # On Windows chmod only toggles read-only; NTFS ACLs of the user's home
    # directory are relied on instead (documented in limitations.md).
    os.chmod(path, mode)


def public_path_for(key_path: Path) -> Path:
    """The public signing key file that belongs to a private key file."""
    return Path(key_path).with_suffix(".pub")


def receive_key_path_for(key_path: Path) -> Path:
    """The private X25519 receiving key file (``identity-recv.key``)."""
    key_path = Path(key_path)
    return key_path.with_name(key_path.stem + "-recv.key")


def card_path_for(key_path: Path) -> Path:
    """The contact card file (``identity.card``) to hand to peers."""
    return Path(key_path).with_suffix(".card")


def _private_pem(key: Ed25519PrivateKey | X25519PrivateKey, passphrase: bytes | None) -> bytes:
    encryption: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption
    )


def _load_private_pem(path: Path, passphrase: bytes | None) -> object:
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise IdentityError(f"cannot read key file {path}: {exc.strerror}") from exc
    try:
        return serialization.load_pem_private_key(data, password=passphrase)
    except TypeError as exc:
        # pyca raises TypeError when encryption and password presence disagree.
        if passphrase is None:
            raise PassphraseRequired(f"{path} is passphrase-protected") from exc
        raise IdentityError(f"{path} is not encrypted; omit the passphrase") from exc
    except ValueError as exc:
        raise IdentityError("wrong passphrase or corrupt key file") from exc


class Identity:
    """A user's long-term keys: Ed25519 (signing) and, optionally, X25519 (receiving)."""

    __slots__ = ("_private_key", "_receive_key")

    def __init__(
        self, private_key: Ed25519PrivateKey, receive_key: X25519PrivateKey | None = None
    ) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise IdentityError("identity keys must be Ed25519")
        if receive_key is not None and not isinstance(receive_key, X25519PrivateKey):
            raise IdentityError("receiving keys must be X25519")
        self._private_key = private_key
        self._receive_key = receive_key

    @classmethod
    def generate(cls) -> Identity:
        """Create both keys from the OS CSPRNG (via OpenSSL)."""
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @property
    def public_key(self) -> bytes:
        """The raw 32-byte Ed25519 public key (the identity)."""
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def receive_public_key(self) -> bytes | None:
        """The raw 32-byte X25519 receiving public key, or None for older identities."""
        if self._receive_key is None:
            return None
        return self._receive_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.public_key)

    def sign(self, message: bytes) -> bytes:
        """Sign ``message``. Ed25519 is deterministic, so there is no nonce to get wrong."""
        return self._private_key.sign(message)

    def receive_exchange(self, peer_ephemeral: bytes) -> bytes:
        """X25519(receiving key, sender's ephemeral key). Used by the one-way mode only.

        Raises IdentityError for a low-order point (all-zero shared secret).
        """
        if self._receive_key is None:
            raise IdentityError("this identity has no receiving key (run keygen again)")
        try:
            shared = self._receive_key.exchange(X25519PublicKey.from_public_bytes(peer_ephemeral))
        except ValueError as exc:
            raise IdentityError("sender ephemeral key is invalid (low-order point)") from exc
        if not any(shared):
            raise IdentityError("all-zero shared secret")
        return shared

    def private_pem(self, passphrase: bytes | None) -> bytes:
        """PKCS#8 PEM of the signing key, encrypted with ``passphrase`` when given."""
        return _private_pem(self._private_key, passphrase)

    def public_pem(self) -> bytes:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def card(self) -> bytes:
        """A contact card: both public keys, the receiving key signed by the identity key."""
        receive = self.receive_public_key
        if receive is None:
            raise IdentityError("this identity has no receiving key")
        doc = {
            "format": CARD_FORMAT,
            "sign_key": self.public_key.hex(),
            "receive_key": receive.hex(),
            # Binds the X25519 key to the Ed25519 identity whose fingerprint
            # is checked in person. Without this, a swapped receiving key on
            # the card would go unnoticed.
            "signature": self.sign(CARD_LABEL + receive).hex(),
            "fingerprint": self.fingerprint,
        }
        return (json.dumps(doc, indent=2) + "\n").encode("utf-8")

    def save(self, key_path: Path, passphrase: bytes | None, overwrite: bool = False) -> Path:
        """Write the private keys (mode 0600), the public key and the card. Returns the .pub path."""
        key_path = Path(key_path)
        pub_path = public_path_for(key_path)
        outputs = [pub_path, receive_key_path_for(key_path), card_path_for(key_path)]
        if not overwrite:
            for path in outputs:
                if path.exists():
                    raise IdentityError(f"{path} already exists (use --force to overwrite)")
        _write_new_file(key_path, self.private_pem(passphrase), 0o600, overwrite)
        _write_new_file(pub_path, self.public_pem(), 0o644, overwrite)
        if self._receive_key is not None:
            _write_new_file(
                receive_key_path_for(key_path),
                _private_pem(self._receive_key, passphrase),
                0o600,
                overwrite,
            )
            _write_new_file(card_path_for(key_path), self.card(), 0o644, overwrite)
        return pub_path

    @classmethod
    def load(cls, key_path: Path, passphrase: bytes | None = None) -> Identity:
        """Load the private keys. The receiving key is loaded if its file exists.

        Raises:
            PassphraseRequired: the file is encrypted and ``passphrase`` is None.
            IdentityError: wrong passphrase, unreadable file or wrong key type.
        """
        key = _load_private_pem(key_path, passphrase)
        if not isinstance(key, Ed25519PrivateKey):
            raise IdentityError(f"{key_path} is not an Ed25519 private key")
        receive: X25519PrivateKey | None = None
        recv_path = receive_key_path_for(Path(key_path))
        if recv_path.exists():
            loaded = _load_private_pem(recv_path, passphrase)
            if not isinstance(loaded, X25519PrivateKey):
                raise IdentityError(f"{recv_path} is not an X25519 private key")
            receive = loaded
        return cls(key, receive)

    def __repr__(self) -> str:  # never print key material
        return f"Identity(fingerprint={self.fingerprint!r})"


def load_public_key(path: Path) -> bytes:
    """Read a PEM public key file and return the raw 32-byte Ed25519 key."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise IdentityError(f"cannot read public key {path}: {exc.strerror}") from exc
    try:
        key = serialization.load_pem_public_key(data)
    except ValueError as exc:
        raise IdentityError(f"{path} is not a valid PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise IdentityError(f"{path} is not an Ed25519 public key")
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def parse_card(data: bytes) -> tuple[bytes, bytes]:
    """Parse and verify a contact card. Returns (sign_key, receive_key).

    The card's signature is checked against the card's own signing key. That
    proves only that the two keys belong together. Whether the signing key
    belongs to the right *person* is what the in-person fingerprint check
    establishes.
    """
    try:
        doc = json.loads(data.decode("utf-8"))
        if doc.get("format") != CARD_FORMAT:
            raise IdentityError("unsupported contact card format")
        sign_key = bytes.fromhex(doc["sign_key"])
        receive_key = bytes.fromhex(doc["receive_key"])
        signature = bytes.fromhex(doc["signature"])
    except (UnicodeDecodeError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise IdentityError(f"malformed contact card: {exc}") from exc
    _check_public_key(sign_key)
    _check_public_key(receive_key)
    try:
        verify_signature(sign_key, signature, CARD_LABEL + receive_key)
    except InvalidSignature as exc:
        raise IdentityError("contact card signature is invalid (card was altered)") from exc
    return sign_key, receive_key


COMPACT_CARD_MAGIC = b"ALC1"


def parse_compact_card(data: bytes) -> tuple[str, bytes, bytes]:
    """Parse the compact binary card the web app shows as a QR code.

    Layout: ``"ALC1" | name_len(1) | name | sign_key(32) | receive_key(32) | sig(64)``.
    The signature is the same as on the JSON card, Sign(sign_key,
    "airlock-card" || receive_key), so both formats bind the keys the same way.
    The name is a suggestion only; it is not signed.
    Returns (suggested_name, sign_key, receive_key).
    """
    if len(data) < 5 or data[:4] != COMPACT_CARD_MAGIC:
        raise IdentityError("not an AirLock compact card")
    n = data[4]
    if len(data) != 5 + n + 128:
        raise IdentityError("malformed compact card")
    try:
        name = data[5 : 5 + n].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IdentityError("malformed compact card name") from exc
    sign_key, receive_key, sig = data[5 + n : 37 + n], data[37 + n : 69 + n], data[69 + n :]
    try:
        verify_signature(sign_key, sig, CARD_LABEL + receive_key)
    except InvalidSignature as exc:
        raise IdentityError("contact card signature is invalid (card was altered)") from exc
    return name, sign_key, receive_key


def load_peer_keys(path: Path) -> tuple[bytes, bytes | None]:
    """Load a peer's keys from a ``.card`` (both keys) or a ``.pub`` (signing key only)."""
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise IdentityError(f"cannot read {path}: {exc.strerror}") from exc
    if data.lstrip().startswith(b"{"):
        return parse_card(data)
    if data.startswith(COMPACT_CARD_MAGIC):
        _name, sign_key, receive_key = parse_compact_card(data)
        return sign_key, receive_key
    return load_public_key(path), None


def _validate_peer_name(name: str) -> str:
    name = name.strip()
    if not name or len(name) > MAX_PEER_NAME or not name.isprintable():
        raise IdentityError(f"peer name must be 1-{MAX_PEER_NAME} printable characters")
    return name


class TrustStore:
    """Pinned peer keys: ``name -> Ed25519 key`` (plus an optional X25519 receiving key).

    A handshake succeeds only if the peer's signing key is byte-for-byte
    equal to one of these entries (threat T1). Changing a pinned key needs an
    explicit remove followed by an add, the same model as SSH's known_hosts.
    """

    def __init__(self, peers: dict[str, bytes] | None = None, path: Path | None = None) -> None:
        self._peers: dict[str, bytes] = {}
        self._receive: dict[str, bytes] = {}
        self.path = Path(path) if path is not None else None
        for name, key in (peers or {}).items():
            self.add(name, key)

    @classmethod
    def load(cls, path: Path) -> TrustStore:
        """Load a store from JSON. A missing file means an empty store."""
        path = Path(path)
        store = cls(path=path)
        if not path.exists():
            return store
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if doc.get("format") != TRUST_STORE_FORMAT:
                raise IdentityError(f"unsupported trust store format in {path}")
            for name, entry in doc["peers"].items():
                receive = entry.get("receive_key")
                store.add(
                    name,
                    bytes.fromhex(entry["public_key"]),
                    bytes.fromhex(receive) if receive else None,
                )
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            raise IdentityError(f"corrupt trust store {path}: {exc}") from exc
        return store

    def save(self, path: Path | None = None) -> None:
        """Write atomically: a crash cannot leave a half-written store behind."""
        target = Path(path) if path is not None else self.path
        if target is None:
            raise IdentityError("trust store has no path")
        target.parent.mkdir(parents=True, exist_ok=True)
        peers: dict[str, dict[str, str]] = {}
        for name, key in sorted(self._peers.items()):
            entry = {"public_key": key.hex(), "fingerprint": fingerprint(key)}
            if name in self._receive:
                entry["receive_key"] = self._receive[name].hex()
            peers[name] = entry
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".trust-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"format": TRUST_STORE_FORMAT, "peers": peers}, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def add(self, name: str, public_key: bytes, receive_key: bytes | None = None) -> None:
        """Pin ``public_key`` (and optionally ``receive_key``) under ``name``.

        Refuses to silently replace either key.
        """
        name = _validate_peer_name(name)
        _check_public_key(public_key)
        public_key = bytes(public_key)
        existing = self._peers.get(name)
        if existing is not None and existing != public_key:
            raise IdentityError(
                f"'{name}' is already trusted with a DIFFERENT key. "
                "If the change is legitimate, remove the old entry first."
            )
        other = self.name_for(public_key)
        if other is not None and other != name:
            raise IdentityError(f"this key is already trusted as '{other}'")
        if receive_key is not None:
            _check_public_key(receive_key)
            old = self._receive.get(name)
            if old is not None and old != bytes(receive_key):
                raise IdentityError(f"'{name}' already has a DIFFERENT receiving key")
            self._receive[name] = bytes(receive_key)
        self._peers[name] = public_key

    def remove(self, name: str) -> None:
        if name not in self._peers:
            raise IdentityError(f"no trusted peer named '{name}'")
        del self._peers[name]
        self._receive.pop(name, None)

    def name_for(self, public_key: bytes) -> str | None:
        """Return the peer name pinned to ``public_key``, or None if it is untrusted."""
        found: str | None = None
        for name, key in self._peers.items():
            # Constant-time compare. Public keys are not secret; this is just hygiene.
            if hmac.compare_digest(key, bytes(public_key)):
                found = name
        return found

    def receive_key_for(self, name: str) -> bytes | None:
        """The pinned X25519 receiving key of ``name``, if one was added from a card."""
        return self._receive.get(name)

    def items(self) -> Iterator[tuple[str, bytes]]:
        return iter(sorted(self._peers.items()))

    def __len__(self) -> int:
        return len(self._peers)

    def __contains__(self, name: object) -> bool:
        return name in self._peers
