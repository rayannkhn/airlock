"""AirLock: secure file transfer over sound, screen-to-camera (QR) and light.

The secure protocol lives in :mod:`airlock.core`; physical channels live in
:mod:`airlock.transports` and only move opaque bytes.
"""

__version__ = "0.1.0"

#: Wire-protocol version byte. Covered by the handshake transcript and the AEAD
#: associated data, so it cannot be silently downgraded (threat T18).
PROTOCOL_VERSION: int = 1
