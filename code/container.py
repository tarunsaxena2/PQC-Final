"""container.py - FROZEN INTERFACE v1. Header is real (Day 1); pack/unpack are still stubs until Day 2."""
import numpy as np
from container_header import (CT_LEN, FLAG_GCM, MAGIC, MODE_HYBRID_QKDSIM, MODE_HYBRID_X25519, MODE_NAMES,
                              MODE_PQC, PREFIX_LEN, VERSION, ContainerError, Header, header_decode,
                              header_encode, header_len, peek_header_len)


def body_length(n_plain, gcm=False):
    return n_plain


def pack(file_bytes, keys, header):
    return np.unpackbits(np.frombuffer(file_bytes, dtype=np.uint8))


def unpack(body_bits, keys, header):
    return np.packbits(body_bits).tobytes()


def zeroise(*buffers):
    for b in buffers:
        if isinstance(b, bytearray):
            b[:] = bytes(len(b))
