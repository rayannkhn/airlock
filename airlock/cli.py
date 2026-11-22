"""Command-line interface.

Commands:
    demo-setup                      create demo users alice + bob who trust each other
    keygen / verify / trust ...     manage your own identity and trusted peers
    send FILE --render out.mp4      one-way QR transfer (video or .html for a phone)
    send FILE --to HOST:PORT        interactive transfer over TCP (testing)
    receive --camera 0              read a QR transfer from the webcam
    receive --video out.mp4         read a QR transfer from a video file
    receive                         TCP receiver (testing)

State lives in one directory, ``~/.airlock`` by default (override it with
``--home`` or ``AIRLOCK_HOME``). After ``demo-setup``, ``send`` acts as
alice and ``receive`` acts as bob automatically. ``--as NAME`` picks a user
explicitly.

Exit codes: 0 = success, 1 = aborted (security or I/O failure),
2 = usage error, 130 = interrupted.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Callable, Sequence

from airlock import PROTOCOL_VERSION, __version__
from airlock.core.handshake import HandshakeError
from airlock.core.identity import (
    Identity,
    IdentityError,
    PassphraseRequired,
    TrustStore,
    card_path_for,
    fingerprint,
    load_peer_keys,
    load_public_key,
    public_path_for,
)
from airlock.core.oneway import SessionStore
from airlock.demo_users import DEMO_FILE, setup_demo_users
from airlock.core.session import (
    DEFAULT_CHUNK_SIZE,
    ReceiveReport,
    TransferError,
    build_oneway_transfer,
    receive_file,
    receive_file_oneway,
    send_file,
)
from airlock.transports.base import TransportError
from airlock.transports.tcp import TcpTransport, parse_endpoint

PASSPHRASE_ENV = "AIRLOCK_PASSPHRASE"
DEFAULT_PORT = 9000
#: Smaller chunks give smaller QR codes (version 10, 57x57 modules), which a
#: webcam reads more reliably from a phone screen.
QR_CHUNK_SIZE = 150


# ---------------------------------------------------------------- paths


def _base(args: argparse.Namespace) -> Path:
    if args.home:
        return Path(args.home).expanduser()
    env = os.environ.get("AIRLOCK_HOME")
    return Path(env).expanduser() if env else Path.home() / ".airlock"


def _resolve_user_home(args: argparse.Namespace, role: str | None) -> Path:
    """Pick the user directory: --as NAME, a real identity in HOME, or the demo user."""
    base = _base(args)
    if args.as_user:
        return base / args.as_user
    if (base / "identity.key").exists() or role is None:
        return base
    demo = base / DEMO_FILE
    if demo.exists():
        try:
            name = json.loads(demo.read_text(encoding="utf-8"))[role]
        except (OSError, ValueError, KeyError) as exc:
            raise IdentityError(f"corrupt {demo}: {exc}") from exc
        _out(f"(demo) acting as '{name}'")
        return base / name
    return base


def _key_path(args: argparse.Namespace) -> Path:
    if getattr(args, "key", None):
        return Path(args.key).expanduser()
    return args.user_home / "identity.key"


def _trust_path(args: argparse.Namespace) -> Path:
    return args.user_home / "trusted_peers.json"


def _session_store_path(args: argparse.Namespace) -> Path:
    return args.user_home / "used_sessions.json"


# ---------------------------------------------------------------- helpers


def _out(message: str) -> None:
    print(message, flush=True)


def _err(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _read_passphrase(confirm: bool) -> bytes:
    """Read a passphrase from AIRLOCK_PASSPHRASE (for scripts) or from the terminal."""
    env = os.environ.get(PASSPHRASE_ENV)
    if env is not None:
        return env.encode("utf-8")
    first = getpass.getpass("Passphrase for identity key: ")
    if confirm:
        if len(first) < 8:
            raise IdentityError("passphrase must be at least 8 characters")
        if getpass.getpass("Repeat passphrase: ") != first:
            raise IdentityError("passphrases do not match")
    return first.encode("utf-8")


def _load_identity(args: argparse.Namespace) -> Identity:
    path = _key_path(args)
    if not path.exists():
        raise IdentityError(f"no identity at {path}. Run 'airlock demo-setup' or 'airlock keygen'.")
    try:
        return Identity.load(path)
    except PassphraseRequired:
        return Identity.load(path, _read_passphrase(confirm=False))


def _ask_yes(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _progress_printer(label: str) -> Callable[[int, int], None]:
    """Show progress on an interactive terminal only (keeps logs clean)."""
    interactive = sys.stdout.isatty()
    state = {"last": -1}

    def show(done: int, total: int) -> None:
        if not interactive or total <= 0:
            return
        percent = done * 100 // total
        if percent != state["last"]:
            state["last"] = percent
            end = "\n" if done == total else ""
            print(f"\r{label}: {done}/{total} packets ({percent}%)", end=end, flush=True)

    return show


def _sas_confirmer(args: argparse.Namespace) -> Callable[[str, str], bool]:
    def confirm(peer: str, sas: str) -> bool:
        _out(f"Verification code  : {sas}")
        if args.accept_sas:
            _out("(--accept-sas: skipping the manual comparison; signatures still verified)")
            return True
        return _ask_yes("Does the sender show the SAME code? [y/N] ")

    return confirm


def _print_receive_report(report: ReceiveReport) -> None:
    stats = report.stats
    _out(f"SUCCESS: wrote {report.path} ({report.size} bytes) from '{report.peer_name}'.")
    _out(
        f"Packets: {stats.accepted} accepted, {stats.duplicates} duplicates, "
        f"{stats.crc_errors} CRC errors, {stats.aead_failures} auth failures, "
        f"{stats.rejected} rejected."
    )


# ---------------------------------------------------------------- identity commands


def cmd_demo_setup(args: argparse.Namespace) -> int:
    """Create alice and bob, each pinning the other's keys (stands in for the in-person meeting)."""
    base = _base(args)
    identities = setup_demo_users(base, force=args.force)
    for name, ident in identities.items():
        _out(f"Created {name:<6} fingerprint {ident.fingerprint}")
    _out("alice trusts bob, bob trusts alice.")
    _out(f"State: {base}  (demo keys are NOT passphrase-protected)")
    _out("Next: airlock send FILE --render out.mp4   (or: airlock ui)")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    key_path = _key_path(args)
    passphrase = None if args.no_passphrase else _read_passphrase(confirm=True)
    identity = Identity.generate()
    pub_path = identity.save(key_path, passphrase, overwrite=args.force)
    _out(f"Private key : {key_path}" + ("  (NOT passphrase-protected)" if passphrase is None else ""))
    _out(f"Public key  : {pub_path}")
    _out(f"Contact card: {card_path_for(key_path)}")
    _out(f"Fingerprint : {identity.fingerprint}")
    _out("Give the contact card to your peer and compare fingerprints IN PERSON.")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.pubfile).expanduser() if args.pubfile else public_path_for(_key_path(args))
    sign_key, _ = load_peer_keys(path)
    _out(f"{path}")
    _out(f"Fingerprint : {fingerprint(sign_key)}")
    return 0


def cmd_trust_add(args: argparse.Namespace) -> int:
    sign_key, receive_key = load_peer_keys(Path(args.pubfile).expanduser())
    _out(f"Peer        : {args.name}")
    _out(f"Fingerprint : {fingerprint(sign_key)}")
    if receive_key is None:
        _out("(public key only: one-way QR transfers TO this peer will not be possible)")
    if not args.yes and not _ask_yes(
        "Have you compared this fingerprint with the peer's own screen, in person? [y/N] "
    ):
        _err("Not trusted. Compare the fingerprint first.")
        return 1
    store = TrustStore.load(_trust_path(args))
    store.add(args.name, sign_key, receive_key)
    store.save()
    _out(f"Trusted '{args.name}' ({_trust_path(args)})")
    return 0


def cmd_trust_list(args: argparse.Namespace) -> int:
    store = TrustStore.load(_trust_path(args))
    if not len(store):
        _out("No trusted peers yet. Use 'airlock trust add NAME identity.card'.")
    for name, key in store.items():
        oneway = "one-way ok" if store.receive_key_for(name) else "signing key only"
        _out(f"{name:<20} {fingerprint(key)}  ({oneway})")
    return 0


def cmd_trust_remove(args: argparse.Namespace) -> int:
    store = TrustStore.load(_trust_path(args))
    store.remove(args.name)
    store.save()
    _out(f"Removed '{args.name}'")
    return 0


# ---------------------------------------------------------------- send


def _pick_recipient(trust: TrustStore, requested: str | None) -> str:
    candidates = [name for name, _ in trust.items() if trust.receive_key_for(name)]
    if requested:
        return requested
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise IdentityError("no trusted peer has a receiving key; add their identity.card first")
    raise IdentityError(f"several possible recipients ({', '.join(candidates)}): use --recipient")


def _send_oneway(args: argparse.Namespace, path: Path) -> int:
    from airlock.transports.qr import render_html, render_video, verify_video

    identity = _load_identity(args)
    trust = TrustStore.load(_trust_path(args))
    recipient = _pick_recipient(trust, args.recipient)
    packets, result = build_oneway_transfer(
        identity, trust, recipient, path, chunk_size=args.chunk_size or QR_CHUNK_SIZE
    )
    out = Path(args.render).expanduser()
    _out(f"Recipient        : {recipient}")
    _out(f"Verification code: {result.sas_text}")
    _out(f"Packets          : {len(packets)} (1 seal + 1 manifest + {len(packets) - 2} chunks)")

    if out.suffix.lower() == ".gif":
        from airlock.transports.qr import render_gif, verify_gif

        seconds = render_gif(packets, out, codes_per_second=args.fps / args.hold)
        size_kb = out.stat().st_size / 1024
        _out(f"Wrote {out}: {len(packets)} codes, {seconds:.0f} s per loop, loops forever ({size_kb:.0f} KB)")
        readable = verify_gif(out, packets)
        _out(f"Self-check       : {readable}/{len(packets)} QR codes readable from the GIF")
        if readable < len(packets):
            _err("WARNING: some codes are unreadable; try --render out.html instead.")
            return 1
    elif out.suffix.lower() in (".html", ".htm"):
        render_html(packets, out, codes_per_second=args.fps / args.hold)
        _out(f"Wrote {out}: {len(packets)} codes, loops forever in any browser.")
    else:
        seconds = render_video(packets, out, fps=args.fps, hold=args.hold, loops=args.loops)
        size_mb = out.stat().st_size / 1e6
        _out(f"Wrote {out}: {len(packets)} codes x {args.loops} loops ({seconds:.0f} s, {size_mb:.1f} MB)")
        readable = verify_video(out, packets, hold=args.hold)
        _out(f"Self-check       : {readable}/{len(packets)} QR codes readable from the video file")
        if readable < len(packets):
            _err(
                "WARNING: some codes did not survive video compression. "
                "Render to .html instead, or use a larger --hold."
            )
            return 1
    _out(f"Next: copy {out.name} to the phone (USB cable), play it fullscreen,")
    _out("      and run:  airlock receive --camera 0")
    return 0


def _send_tcp(args: argparse.Namespace, path: Path) -> int:
    identity = _load_identity(args)
    trust = TrustStore.load(_trust_path(args))

    def show_sas(peer: str, sas: str) -> None:
        _out(f"Authenticated peer : {peer}")
        _out(f"Verification code  : {sas}   (the receiver must see the same code)")

    host, port = parse_endpoint(args.to, default_host="127.0.0.1")
    with TcpTransport.connect(host, port or DEFAULT_PORT, retry_for=args.connect_retry) as transport:
        report = send_file(
            transport,
            identity,
            trust,
            path,
            chunk_size=args.chunk_size or DEFAULT_CHUNK_SIZE,
            timeout=args.timeout,
            wait_for_receipt=not args.no_receipt,
            on_sas=show_sas,
            on_progress=_progress_printer("Sending"),
        )
    _out(f"Sent {report.bytes_sent} bytes in {report.packets} packets.")
    if report.receipt_verified:
        _out("SUCCESS: receiver confirmed the file (authenticated receipt, SHA-256 matched).")
    else:
        _out("SENT: no receipt requested, so delivery is unconfirmed.")
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    path = Path(args.file).expanduser()
    if not path.is_file():
        raise TransferError(f"{path} is not a file")
    if args.render:
        return _send_oneway(args, path)
    if args.to:
        return _send_tcp(args, path)
    raise ValueError("give --render FILE.mp4 (QR, one-way) or --to HOST:PORT (TCP)")


# ---------------------------------------------------------------- receive


def _receive_oneway(args: argparse.Namespace) -> int:
    from airlock.transports.qr import QrReceiver

    identity = _load_identity(args)
    trust = TrustStore.load(_trust_path(args))
    if not len(trust):
        raise IdentityError("trust store is empty: nobody could authenticate to you")
    store = SessionStore.load(_session_store_path(args))
    if args.video:
        receiver = QrReceiver.open_video(Path(args.video).expanduser(), frame_step=2)
    else:
        receiver = QrReceiver.open_camera(args.camera, preview=not args.no_preview)

    _out(f"Your fingerprint: {identity.fingerprint}")
    _out(f"Waiting for QR codes on {receiver.source_name} ..."
         + ("" if args.video or args.no_preview else " (press q in the preview window to abort)"))
    show_progress = _progress_printer("Receiving")

    def authenticated(peer: str) -> None:
        receiver.status = f"authenticated: {peer}"
        _out(f"Authenticated sender: {peer}")

    def progress(done: int, total: int) -> None:
        receiver.status = f"receiving {done}/{total} packets"
        show_progress(done, total)

    with receiver:
        report = receive_file_oneway(
            receiver,
            identity,
            trust,
            Path(args.out).expanduser(),
            store,
            timeout=args.timeout,
            confirm_sas=_sas_confirmer(args),
            max_file_size=int(args.max_size_mb * 1024 * 1024),
            max_age=int(args.max_age_hours * 3600),
            on_authenticated=authenticated,
            on_progress=progress,
        )
    _print_receive_report(report)
    return 0


def _receive_tcp(args: argparse.Namespace) -> int:
    identity = _load_identity(args)
    trust = TrustStore.load(_trust_path(args))
    if not len(trust):
        raise IdentityError("trust store is empty: nobody could authenticate to you")
    host, port = parse_endpoint(args.listen, default_host="127.0.0.1")
    confirm = _sas_confirmer(args)

    def confirm_with_peer(peer: str, sas: str) -> bool:
        _out(f"Authenticated peer : {peer}")
        return confirm(peer, sas)

    _out(f"Your fingerprint: {identity.fingerprint}")
    with TcpTransport.listen(
        host, port, on_listening=lambda h, p: _out(f"Listening on {h}:{p} ...")
    ) as transport:
        report = receive_file(
            transport,
            identity,
            trust,
            Path(args.out).expanduser(),
            timeout=args.timeout,
            confirm_sas=confirm_with_peer,
            max_file_size=int(args.max_size_mb * 1024 * 1024),
            on_progress=_progress_printer("Receiving"),
        )
    _print_receive_report(report)
    return 0


def cmd_receive(args: argparse.Namespace) -> int:
    if args.camera is not None or args.video:
        return _receive_oneway(args)
    return _receive_tcp(args)


def cmd_ui(args: argparse.Namespace) -> int:
    """Open the point-and-click demo page (send, receive, attacks) in the browser."""
    from airlock.ui.server import serve

    serve(_base(args), port=args.port, camera=args.camera, open_browser=not args.no_browser)
    return 0


# ---------------------------------------------------------------- parser


def build_parser() -> argparse.ArgumentParser:
    from airlock.transports.qr import DEFAULT_FPS, DEFAULT_HOLD, DEFAULT_LOOPS

    parser = argparse.ArgumentParser(
        prog="airlock",
        description="Secure air-gapped file transfer (protocol v%d)." % PROTOCOL_VERSION,
    )
    parser.add_argument("--version", action="version", version=f"airlock {__version__}")
    parser.add_argument("--home", help="state directory (default: ~/.airlock or $AIRLOCK_HOME)")
    parser.add_argument("--as", dest="as_user", metavar="NAME", help="act as user NAME in HOME")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("demo-setup", help="create demo users alice and bob who trust each other")
    p.add_argument("--force", action="store_true", help="recreate the demo users")
    p.set_defaults(func=cmd_demo_setup)

    p = sub.add_parser("ui", help="open the point-and-click demo page in your browser")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--camera", type=int, default=0, help="webcam index for receiving")
    p.add_argument("--no-browser", action="store_true", help="do not open a browser window")
    p.set_defaults(func=cmd_ui)

    p = sub.add_parser("keygen", help="create your long-term identity keys")
    p.add_argument("--key", help="private key path (default: HOME/identity.key)")
    p.add_argument("--force", action="store_true", help="overwrite an existing identity")
    p.add_argument(
        "--no-passphrase", action="store_true", help="store the keys unencrypted (testing only)"
    )
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("verify", help="show a fingerprint to compare in person")
    p.add_argument("pubfile", nargs="?", help=".pub or .card file (default: your own)")
    p.add_argument("--key", help="your private key path (to locate your .pub)")
    p.set_defaults(func=cmd_verify)

    trust = sub.add_parser("trust", help="manage trusted peers").add_subparsers(
        dest="trust_command", required=True
    )
    p = trust.add_parser("add", help="pin a peer's keys from their .card (or .pub)")
    p.add_argument("name")
    p.add_argument("pubfile", metavar="CARD_OR_PUB")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p.set_defaults(func=cmd_trust_add)
    p = trust.add_parser("list", help="list trusted peers")
    p.set_defaults(func=cmd_trust_list)
    p = trust.add_parser("remove", help="unpin a peer")
    p.add_argument("name")
    p.set_defaults(func=cmd_trust_remove)

    p = sub.add_parser("send", help="send a file (QR video with --render, or TCP with --to)")
    p.add_argument("file")
    p.add_argument("--render", metavar="OUT",
                   help="one-way QR: write OUT.gif (plays on every phone), OUT.mp4 or OUT.html")
    p.add_argument("--recipient", help="one-way: trusted peer to encrypt for")
    p.add_argument("--to", help="TCP: receiver HOST:PORT")
    p.add_argument("--key", help="private key path")
    p.add_argument("--chunk-size", type=int, default=None,
                   help=f"plaintext bytes per packet (QR default {QR_CHUNK_SIZE}, TCP {DEFAULT_CHUNK_SIZE})")
    p.add_argument("--fps", type=int, default=DEFAULT_FPS, help="video frame rate")
    p.add_argument("--hold", type=int, default=DEFAULT_HOLD, help="video frames per QR code")
    p.add_argument("--loops", type=int, default=DEFAULT_LOOPS, help="times the video repeats")
    p.add_argument("--timeout", type=float, default=30.0, help="TCP: seconds per handshake step")
    p.add_argument("--connect-retry", type=float, default=0.0, help="TCP: keep retrying (s)")
    p.add_argument("--no-receipt", action="store_true", help="TCP: do not wait for a receipt")
    p.set_defaults(func=cmd_send)

    p = sub.add_parser("receive", help="receive one file (QR with --camera/--video, else TCP)")
    p.add_argument("--camera", type=int, metavar="INDEX", help="read QR codes from this webcam")
    p.add_argument("--video", metavar="FILE", help="read QR codes from a video file")
    p.add_argument("--no-preview", action="store_true", help="do not open the camera window")
    p.add_argument("--max-age-hours", type=float, default=24.0,
                   help="one-way: reject transfers older than this (replay window)")
    p.add_argument(
        "--listen",
        default=f"127.0.0.1:{DEFAULT_PORT}",
        help="TCP: HOST:PORT to listen on; use 0.0.0.0:PORT for another machine",
    )
    p.add_argument("--out", default="received", help="output directory")
    p.add_argument("--key", help="private key path")
    p.add_argument("--timeout", type=float, default=60.0, help="idle seconds before aborting")
    p.add_argument("--max-size-mb", type=float, default=16.0)
    p.add_argument(
        "--accept-sas", action="store_true", help="do not prompt for the verification code"
    )
    p.set_defaults(func=cmd_receive)
    return parser


_ROLES = {"send": "sender", "receive": "receiver"}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.user_home = _resolve_user_home(args, _ROLES.get(args.command))
        return int(args.func(args))
    except (HandshakeError, TransferError, TransportError, IdentityError, OSError) as exc:
        _err(f"ABORTED: {exc}")
        if args.command == "receive":
            _err("Nothing was written to disk.")
        return 1
    except ValueError as exc:  # bad endpoint, bad number, missing mode
        _err(f"ERROR: {exc}")
        return 2
    except KeyboardInterrupt:
        _err("\nABORTED: interrupted. Nothing was written to disk.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
