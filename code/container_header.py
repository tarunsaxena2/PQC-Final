"""container_header.py - container v1 header (fixed positions, read first by the receiver).

Layout: magic(4) version(1) level(1) mode byte(1) | KEM ciphertext (768/1088/1568 B) | body_len(4, big endian)
Mode byte: low 4 bits = key mode (0 pqc, 1 hybrid-x25519, 2 hybrid-qkdsim); bit 4 = AES-GCM;
the other bits are reserved and must be 0. The whole header is authenticated (MAC input or GCM AAD).
Decision (Week 1, Day 5): the plaintext magic is kept and recorded as a detectability limitation.
"""
from dataclasses import dataclass

MAGIC = b"PQCS"
VERSION = 1
CT_LEN = {1: 768, 2: 1088, 3: 1568}   # level -> ML-KEM-512 / 768 / 1024 ciphertext bytes
MODE_PQC, MODE_HYBRID_X25519, MODE_HYBRID_QKDSIM = 0, 1, 2
MODE_NAMES = {MODE_PQC: "pqc", MODE_HYBRID_X25519: "hybrid-x25519", MODE_HYBRID_QKDSIM: "hybrid-qkdsim"}
FLAG_GCM = 0x10
PREFIX_LEN = 7                         # magic + version + level + mode byte
_LEN_FIELD = 4


class ContainerError(Exception):
    """Clean, non-leaking error: bad header, failed authentication, wrong key, size mismatch."""


@dataclass(frozen=True)
class Header:
    level: int          # 1 = ML-KEM-512, 2 = ML-KEM-768, 3 = ML-KEM-1024
    mode: int           # MODE_PQC / MODE_HYBRID_X25519 / MODE_HYBRID_QKDSIM
    kem_ct: bytes       # KEM ciphertext, length fixed by level
    body_len: int       # bytes in the body (IV + ciphertext + tag)
    gcm: bool = False   # False = CBC + HMAC (default)
    version: int = VERSION


def header_len(level):
    if level not in CT_LEN:
        raise ContainerError("unsupported security level")
    return PREFIX_LEN + CT_LEN[level] + _LEN_FIELD


def peek_header_len(prefix):
    """Given the first PREFIX_LEN bytes, return the full header length."""
    if len(prefix) < PREFIX_LEN or bytes(prefix[:4]) != MAGIC:
        raise ContainerError("not a valid container")
    if prefix[4] != VERSION:
        raise ContainerError("unsupported version")
    return header_len(prefix[5])


def header_encode(h):
    if h.mode not in MODE_NAMES:
        raise ContainerError("unknown mode")
    if h.level not in CT_LEN or len(h.kem_ct) != CT_LEN[h.level]:
        raise ContainerError("bad level or ciphertext length")
    if not 0 <= h.body_len < 2 ** 32:
        raise ContainerError("bad body length")
    mode_byte = h.mode | (FLAG_GCM if h.gcm else 0)
    return (MAGIC + bytes([h.version, h.level, mode_byte]) + bytes(h.kem_ct)
            + h.body_len.to_bytes(_LEN_FIELD, "big"))


def header_decode(data):
    total = peek_header_len(bytes(data[:PREFIX_LEN]))
    if len(data) < total:
        raise ContainerError("header truncated")
    mode_byte = data[6]
    if mode_byte & ~(0x0F | FLAG_GCM) & 0xFF:       # reserved bits must be zero
        raise ContainerError("bad mode byte")
    mode = mode_byte & 0x0F
    if mode not in MODE_NAMES:
        raise ContainerError("unknown mode")
    level = data[5]
    ct_end = PREFIX_LEN + CT_LEN[level]
    return Header(level=level, mode=mode, gcm=bool(mode_byte & FLAG_GCM),
                  kem_ct=bytes(data[PREFIX_LEN:ct_end]),
                  body_len=int.from_bytes(data[ct_end:total], "big"), version=data[4])
