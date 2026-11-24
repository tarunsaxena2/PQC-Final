"""container.py - FROZEN INTERFACE v1 (stub). Owner: Uday (container + integrity layer).

keys = the 64-byte output of derive_keys(ss): K_AES[0:16] + K_perm[16:32] + K_MAC[32:64].
Body = IV + ciphertext + tag (CBC + HMAC), or nonce + ciphertext + tag (GCM).
Real pack/unpack come in Week 2; the stub passes bytes through.
"""
from dataclasses import dataclass
import numpy as np

MAGIC = b"PQCS"
VERSION = 1
CT_LEN = {1: 768, 2: 1088, 3: 1568}          # level -> KEM ciphertext bytes (ML-KEM-512/768/1024)
MODE_PQC, MODE_HYBRID_X25519, MODE_HYBRID_QKDSIM = 0, 1, 2
FLAG_GCM = 0x10                               # mode byte: low 4 bits = key mode, bit 4 = GCM


class ContainerError(Exception):
    """Clean, non-leaking error for bad header, MAC failure, wrong key."""


@dataclass
class Header:
    level: int          # 1 = ML-KEM-512, 2 = 768, 3 = 1024
    mode: int           # MODE_PQC / MODE_HYBRID_X25519 / MODE_HYBRID_QKDSIM
    kem_ct: bytes       # KEM ciphertext, length fixed by level
    body_len: int       # bytes in IV + ciphertext + tag
    gcm: bool = False   # False = CBC + HMAC (default)
    version: int = VERSION


def header_encode(h: Header) -> bytes:
    if h.level not in CT_LEN or len(h.kem_ct) != CT_LEN[h.level]:
        raise ContainerError("bad level or ciphertext length")
    mode_byte = h.mode | (FLAG_GCM if h.gcm else 0)
    return MAGIC + bytes([h.version, h.level, mode_byte]) + h.kem_ct + h.body_len.to_bytes(4, "big")


def header_decode(data: bytes) -> Header:
    if len(data) < 7 or data[:4] != MAGIC:
        raise ContainerError("not a valid container")
    version, level, mode_byte = data[4], data[5], data[6]
    if version != VERSION or level not in CT_LEN:
        raise ContainerError("unsupported version or level")
    n = CT_LEN[level]
    if len(data) < 7 + n + 4:
        raise ContainerError("header truncated")
    return Header(level=level, mode=mode_byte & 0x0F, gcm=bool(mode_byte & FLAG_GCM),
                  kem_ct=data[7:7 + n], body_len=int.from_bytes(data[7 + n:11 + n], "big"),
                  version=version)


def body_length(n_plain: int, gcm: bool = False) -> int:
    """Real value (Week 2): CBC = 16 + (n//16+1)*16 + 32 ; GCM = 12 + n + 16. Stub: n."""
    return n_plain


def pack(file_bytes: bytes, keys: bytes, header: Header) -> np.ndarray:
    """STUB. Returns body as a uint8 array of 0/1 bits. Header is covered by the MAC."""
    return np.unpackbits(np.frombuffer(file_bytes, dtype=np.uint8))


def unpack(body_bits: np.ndarray, keys: bytes, header: Header) -> bytes:
    """STUB. Returns the file bytes or raises ContainerError (never partial output)."""
    return np.packbits(body_bits).tobytes()


def zeroise(*buffers) -> None:
    """Best effort: overwrite bytearrays in place (Python cannot guarantee this)."""
    for b in buffers:
        if isinstance(b, bytearray):
            b[:] = bytes(len(b))
