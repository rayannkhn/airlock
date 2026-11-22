"""Benchmark: elliptic-curve crypto (what AirLock uses) vs RSA-2048 / RSA-3072.

Every number comes from timing real operations on this machine. Nothing is
estimated. Two CSV files are written:

- ``crypto_ops.csv``: per-primitive timings (keygen, key agreement, sign, verify)
- ``crypto_handshake.csv``: whole-handshake time and bytes on the wire

The RSA rows use an *RSA analogue* of AirLock's handshake, with the same
structure and real operations: both sides sign the transcript with RSA-PSS,
and a 32-byte secret is sent with RSA-OAEP. Two variants are measured:

- "with forward secrecy": the responder generates a fresh RSA key pair per
  session, as forward secrecy requires. This is the fair comparison with
  AirLock's ephemeral X25519.
- "no forward secrecy": the secret is encrypted to a static RSA key. It is
  faster, but recorded sessions fall to a later key theft.
"""

from __future__ import annotations

import csv
import os
import statistics
import time
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from airlock.core.handshake import Initiator, Responder
from airlock.core.identity import Identity, TrustStore
from airlock.core.oneway import SessionStore, create_seal, open_seal

PACKET_OVERHEAD = 34  # AirLock header (30) + CRC (4), the same for every packet
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _time_ms(func: Callable[[], object], reps: int) -> list[float]:
    func()  # warm-up: first calls include one-off setup cost
    samples = []
    for _ in range(reps):
        start = time.perf_counter()
        func()
        samples.append((time.perf_counter() - start) * 1000)
    return samples


def _row(scheme: str, op: str, samples: list[float]) -> dict[str, object]:
    ordered = sorted(samples)
    return {
        "scheme": scheme,
        "operation": op,
        "reps": len(samples),
        "median_ms": round(statistics.median(samples), 4),
        "mean_ms": round(statistics.fmean(samples), 4),
        "p95_ms": round(ordered[max(0, int(len(ordered) * 0.95) - 1)], 4),
    }


def _der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def bench_primitives(reps: int, rsa_reps: int, rsa_keygen_reps: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    msg = os.urandom(64)

    x_a, x_b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    rows.append(_row("X25519", "keygen", _time_ms(X25519PrivateKey.generate, reps)))
    rows.append(_row("X25519", "key agreement", _time_ms(lambda: x_a.exchange(x_b.public_key()), reps)))

    ed = Ed25519PrivateKey.generate()
    sig = ed.sign(msg)
    rows.append(_row("Ed25519", "keygen", _time_ms(Ed25519PrivateKey.generate, reps)))
    rows.append(_row("Ed25519", "sign", _time_ms(lambda: ed.sign(msg), reps)))
    rows.append(_row("Ed25519", "verify", _time_ms(lambda: ed.public_key().verify(sig, msg), reps)))

    for bits in (2048, 3072):
        name = f"RSA-{bits}"
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        pub = key.public_key()
        rsa_sig = key.sign(msg, _PSS, hashes.SHA256())
        ct = pub.encrypt(os.urandom(32), _OAEP)
        rows.append(_row(name, "keygen", _time_ms(
            lambda b=bits: rsa.generate_private_key(public_exponent=65537, key_size=b),
            rsa_keygen_reps)))
        rows.append(_row(name, "encrypt 32 B (OAEP)", _time_ms(lambda: pub.encrypt(b"k" * 32, _OAEP), rsa_reps)))
        rows.append(_row(name, "decrypt 32 B (OAEP)", _time_ms(lambda: key.decrypt(ct, _OAEP), rsa_reps)))
        rows.append(_row(name, "sign (PSS)", _time_ms(lambda: key.sign(msg, _PSS, hashes.SHA256()), rsa_reps)))
        rows.append(_row(name, "verify (PSS)", _time_ms(
            lambda: pub.verify(rsa_sig, msg, _PSS, hashes.SHA256()), rsa_reps)))
    return rows


def _airlock_interactive(alice: Identity, a_trust: TrustStore, bob: Identity, b_trust: TrustStore) -> int:
    init, resp = Initiator(alice, a_trust), Responder(bob, b_trust)
    m1 = init.start()
    m2 = resp.on_hello(m1)
    m3 = init.on_reply(m2)
    resp.on_finish(m3)
    return len(m1) + len(m2) + len(m3)


def _airlock_oneway(alice: Identity, a_trust: TrustStore, bob: Identity, b_trust: TrustStore) -> int:
    seal, _ = create_seal(alice, a_trust, "bob")
    open_seal(bob, b_trust, seal, SessionStore())
    return len(seal)


def _rsa_handshake(bits: int, forward_secrecy: bool, id_i, id_r) -> int:
    """RSA analogue of the 3-message handshake. Returns the bytes on the wire."""
    transcript = os.urandom(32)  # stands in for the hash of M1 (commitment + session id)
    if forward_secrecy:
        target = rsa.generate_private_key(public_exponent=65537, key_size=bits)  # per-session key
    else:
        target = id_r  # static key transport
    target_der = _der(target.public_key())
    r_der, i_der = _der(id_r.public_key()), _der(id_i.public_key())
    # M2: responder sends its key-transport public key + identity, signed
    sig_r = id_r.sign(b"R" + transcript + target_der + r_der, _PSS, hashes.SHA256())
    id_r.public_key().verify(sig_r, b"R" + transcript + target_der + r_der, _PSS, hashes.SHA256())
    # M3: initiator encrypts a fresh secret to it and signs everything
    secret = os.urandom(32)
    ct = target.public_key().encrypt(secret, _OAEP)
    sig_i = id_i.sign(b"I" + transcript + ct + i_der, _PSS, hashes.SHA256())
    id_i.public_key().verify(sig_i, b"I" + transcript + ct + i_der, _PSS, hashes.SHA256())
    shared = target.decrypt(ct, _OAEP)
    HKDF(algorithm=hashes.SHA256(), length=120, salt=transcript, info=b"keys").derive(shared)
    m1 = 32
    m2 = (len(target_der) if forward_secrecy else 0) + len(r_der) + len(sig_r)
    m3 = len(ct) + len(i_der) + len(sig_i)
    return m1 + m2 + m3 + 3 * PACKET_OVERHEAD


def bench_handshakes(reps: int, rsa_reps: int, rsa_fs_reps: int) -> list[dict[str, object]]:
    alice, bob = Identity.generate(), Identity.generate()
    a_trust, b_trust = TrustStore(), TrustStore()
    a_trust.add("bob", bob.public_key, bob.receive_public_key)
    b_trust.add("alice", alice.public_key, alice.receive_public_key)

    rows: list[dict[str, object]] = []
    cases: list[tuple[str, str, Callable[[], int], int]] = [
        ("AirLock interactive (X25519 + Ed25519)", "yes",
         lambda: _airlock_interactive(alice, a_trust, bob, b_trust), reps),
        ("AirLock one-way (X25519 + Ed25519)", "sender side only",
         lambda: _airlock_oneway(alice, a_trust, bob, b_trust), reps),
    ]
    for bits in (2048, 3072):
        id_i = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        id_r = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        cases.append((f"RSA-{bits} analogue, with forward secrecy", "yes",
                      lambda b=bits, i=id_i, r=id_r: _rsa_handshake(b, True, i, r), rsa_fs_reps))
        cases.append((f"RSA-{bits} analogue, no forward secrecy", "no",
                      lambda b=bits, i=id_i, r=id_r: _rsa_handshake(b, False, i, r), rsa_reps))

    for name, fs, func, n in cases:
        wire_bytes = func()
        row = _row(name, "full handshake", _time_ms(func, n))
        row["forward_secrecy"] = fs
        row["wire_bytes"] = wire_bytes
        row["qr_codes"] = -(-wire_bytes // 200)  # about 200 bytes fit in one of AirLock's QR codes
        rows.append(row)
    return rows


def key_sizes() -> list[dict[str, object]]:
    rows = [
        {"scheme": "X25519", "public_key_bytes": 32, "signature_bytes": "", "security_bits": 128},
        {"scheme": "Ed25519", "public_key_bytes": 32, "signature_bytes": 64, "security_bits": 128},
    ]
    for bits, security in ((2048, 112), (3072, 128)):
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        rows.append({
            "scheme": f"RSA-{bits}",
            "public_key_bytes": len(_der(key.public_key())),
            "signature_bytes": len(key.sign(b"m", _PSS, hashes.SHA256())),
            "security_bits": security,  # NIST SP 800-57 comparable strength
        })
    return rows


def _write(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    for row in rows:
        fields += [k for k in row if k not in fields]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def run(out_dir: Path, quick: bool = False) -> list[Path]:
    reps, rsa_reps, keygen_reps, fs_reps = (20, 5, 2, 2) if quick else (500, 50, 10, 10)
    paths = [out_dir / "crypto_ops.csv", out_dir / "crypto_handshake.csv", out_dir / "crypto_sizes.csv"]
    print(f"crypto: timing primitives ({reps} reps EC, {rsa_reps} RSA, {keygen_reps} RSA keygen) ...")
    _write(paths[0], bench_primitives(reps, rsa_reps, keygen_reps))
    print("crypto: timing whole handshakes ...")
    _write(paths[1], bench_handshakes(reps, rsa_reps, fs_reps))
    _write(paths[2], key_sizes())
    return paths
