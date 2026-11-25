"""Key layer: FROZEN INTERFACE (Week 1 Day 2) + real helpers.

Owner: Vaibhav Gautam (Key Layer Lead)

Public interface (other layers code against these names only):
    keygen(level)      -> (ek, dk)
    encaps(ek)         -> (ct, ss)
    decaps(dk, ct)     -> ss
    derive_keys(ss, k_qkd=None) -> 64 bytes = K_AES(16) + K_perm(16) + K_MAC(32)

`level` is one of 512, 768, 1024 (ML-KEM security level).
Never log or write raw ss, dk or derived keys.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# FIPS 203 sizes in bytes: level -> (ek, dk, ct, ss)
FIPS203_SIZES = {
    512: (800, 1632, 768, 32),
    768: (1184, 2400, 1088, 32),
    1024: (1568, 3168, 1568, 32),
}
LEVELS = tuple(FIPS203_SIZES)

# Same info string as the team benchmark script, so the first 32 bytes of the new 64 B output
# equal the old 32 B output (HKDF-Expand prefix property): K_AES and K_perm do not change.
HKDF_INFO = b"pqc-stego-v1"
K_AES_LEN, K_PERM_LEN, K_MAC_LEN = 16, 16, 32
OKM_LEN = K_AES_LEN + K_PERM_LEN + K_MAC_LEN  # 64


class KeyLayerError(Exception):
    """Clean error for the key layer (never contains secret material)."""


def check_level(level: int) -> int:
    if level not in FIPS203_SIZES:
        raise KeyLayerError(f"unsupported ML-KEM level {level!r}; use one of {LEVELS}")
    return level


def derive_keys(ss: bytes, k_qkd: bytes | None = None) -> bytes:
    """HKDF-SHA256 -> 64 B. Hybrid modes pass k_qkd (ss || k_qkd is the input)."""
    if not isinstance(ss, (bytes, bytearray)) or len(ss) != 32:
        raise KeyLayerError("shared secret must be exactly 32 bytes")
    ikm = bytes(ss) + (bytes(k_qkd) if k_qkd is not None else b"")
    return HKDF(algorithm=hashes.SHA256(), length=OKM_LEN, salt=None, info=HKDF_INFO).derive(ikm)


def split_keys(okm: bytes) -> tuple[bytes, bytes, bytes]:
    """64 B -> (K_AES 16 B, K_perm 16 B, K_MAC 32 B)."""
    if len(okm) != OKM_LEN:
        raise KeyLayerError(f"derived key block must be {OKM_LEN} bytes")
    return okm[:16], okm[16:32], okm[32:64]


def zeroise(buf) -> bool:
    """Best-effort wipe. Works on bytearray / memoryview only.

    Python bytes are immutable and may be copied by the interpreter, so this
    is NOT a guarantee that secrets are gone from memory (state this limit in
    the report). Returns True if a mutable buffer was wiped, else False.
    """
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
        return True
    if isinstance(buf, memoryview) and not buf.readonly:
        buf[:] = bytes(len(buf))
        return True
    return False


# ---- simulated-QKD key file (hybrid-qkdsim mode only) -----------------------
# This file is a SIMULATION of a key delivered by QKD. It is shared out of band.
# It is not quantum security. Format: MAGIC(8) | length(1) | key | check(4)
# The BB84 simulator in the benchmark script outputs a 128-bit (16 B) key, so 16 B is the default;
# 32 B is also accepted.
QKD_MAGIC = b"SIMQKDv1"
QKD_KEY_LEN = 16
QKD_ALLOWED_LENGTHS = (16, 32)


class QkdKeyFileError(KeyLayerError):
    pass


def write_qkd_keyfile(path, key: bytes | None = None) -> Path:
    """Write a simulated-QKD key file (binary, pathlib). Fresh 16 B key if none given."""
    key = os.urandom(QKD_KEY_LEN) if key is None else bytes(key)
    if len(key) not in QKD_ALLOWED_LENGTHS:
        raise QkdKeyFileError("simulated QKD key must be 16 or 32 bytes")
    body = QKD_MAGIC + bytes([len(key)]) + key
    p = Path(path)
    p.write_bytes(body + hashlib.sha256(body).digest()[:4])
    return p


def read_qkd_keyfile(path) -> bytes:
    """Read K_QKD. Raises QkdKeyFileError with a plain message on any problem."""
    p = Path(path)
    try:
        raw = p.read_bytes()
    except FileNotFoundError:
        raise QkdKeyFileError("simulated-QKD key file not found") from None
    except OSError:
        raise QkdKeyFileError("simulated-QKD key file cannot be read") from None
    if len(raw) < 14 or raw[:8] != QKD_MAGIC:
        raise QkdKeyFileError("not a valid simulated-QKD key file")
    n = raw[8]
    if n not in QKD_ALLOWED_LENGTHS or len(raw) != 9 + n + 4:
        raise QkdKeyFileError("not a valid simulated-QKD key file")
    body, check = raw[:9 + n], raw[9 + n:]
    if hashlib.sha256(body).digest()[:4] != check:
        raise QkdKeyFileError("simulated-QKD key file is corrupted")
    return raw[9:9 + n]
