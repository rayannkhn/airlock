"""TCP transport, for testing and development only.

This transport uses a network, which the physical AirLock scenario forbids.
Its job is to exercise the full protocol between two real processes, or two
machines, before the camera and microphone get involved.

Framing: each datagram is a 4-byte big-endian length followed by the bytes.
"""

from __future__ import annotations

import socket
import struct
import sys
import time
from typing import Callable

from airlock.transports.base import Transport, TransportClosed, TransportError, TransportTimeout

#: Bigger than any AirLock packet. A larger length prefix is treated as a
#: protocol violation, so a peer cannot make us allocate gigabytes.
MAX_FRAME = 64 * 1024
_LEN = struct.Struct(">I")


def parse_endpoint(text: str, default_host: str = "127.0.0.1") -> tuple[str, int]:
    """Parse ``host:port``, ``:port`` or ``port``. IPv6 must be written as ``[::1]:9000``."""
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port_text = rest.lstrip(":")
    elif ":" in text:
        host, _, port_text = text.rpartition(":")
    else:
        host, port_text = "", text
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError(f"invalid endpoint '{text}': port must be a number") from exc
    if not 0 <= port <= 65535:
        raise ValueError(f"invalid port {port}")
    return host or default_host, port


class TcpTransport(Transport):
    """Length-prefixed datagrams over one TCP connection."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buffer = bytearray()
        self._closed = False
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    @classmethod
    def connect(
        cls, host: str, port: int, timeout: float = 10.0, retry_for: float = 0.0
    ) -> TcpTransport:
        """Connect to a listening receiver, retrying for ``retry_for`` seconds."""
        deadline = time.monotonic() + retry_for
        while True:
            try:
                return cls(socket.create_connection((host, port), timeout=timeout))
            except OSError as exc:
                if time.monotonic() >= deadline:
                    raise TransportError(f"cannot connect to {host}:{port}: {exc}") from exc
                time.sleep(0.2)

    @classmethod
    def listen(
        cls,
        host: str,
        port: int,
        accept_timeout: float | None = None,
        on_listening: Callable[[str, int], None] | None = None,
    ) -> TcpTransport:
        """Accept exactly one connection. ``on_listening`` gets the real port (useful with port 0)."""
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        listener = socket.socket(family, socket.SOCK_STREAM)
        try:
            if sys.platform == "win32":
                # On Windows SO_REUSEADDR lets another process hijack the
                # port. SO_EXCLUSIVEADDRUSE prevents that.
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((host, port))
            listener.listen(1)
            if on_listening:
                bound = listener.getsockname()
                on_listening(bound[0], bound[1])
            listener.settimeout(accept_timeout)
            try:
                conn, _addr = listener.accept()
            except socket.timeout as exc:
                raise TransportTimeout("no sender connected in time") from exc
            except OSError as exc:
                raise TransportError(f"accept failed: {exc}") from exc
        finally:
            listener.close()
        conn.settimeout(None)
        return cls(conn)

    def send(self, data: bytes) -> None:
        if self._closed:
            raise TransportError("transport is closed")
        if len(data) > MAX_FRAME:
            raise TransportError("datagram too large")
        try:
            self._sock.sendall(_LEN.pack(len(data)) + data)
        except OSError as exc:
            raise TransportError(f"send failed: {exc}") from exc

    def _take_frame(self) -> bytes | None:
        if len(self._buffer) < _LEN.size:
            return None
        (length,) = _LEN.unpack_from(self._buffer)
        if length > MAX_FRAME:
            raise TransportError(f"peer announced a {length}-byte frame; refusing")
        end = _LEN.size + length
        if len(self._buffer) < end:
            return None
        frame = bytes(self._buffer[_LEN.size : end])
        del self._buffer[:end]
        return frame

    def receive(self, timeout: float | None = None) -> bytes:
        """Return one datagram. A timeout leaves partial data buffered, so the stream never desyncs."""
        if self._closed:
            raise TransportError("transport is closed")
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            frame = self._take_frame()
            if frame is not None:
                return frame
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TransportTimeout(f"no data within {timeout}s")
                self._sock.settimeout(remaining)
            else:
                self._sock.settimeout(None)
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout as exc:
                raise TransportTimeout(f"no data within {timeout}s") from exc
            except OSError as exc:
                raise TransportError(f"receive failed: {exc}") from exc
            if not chunk:
                raise TransportClosed("peer closed the connection")
            self._buffer += chunk

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass  # already disconnected
        self._sock.close()
