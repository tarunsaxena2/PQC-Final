import os
import pytest
import container as c
from helpers import make_header


@pytest.mark.parametrize("gcm", [False, True])
def test_every_header_bit_flip_is_rejected(gcm):
    data, keys = os.urandom(200), os.urandom(64)
    h = make_header(200, gcm)
    bits = c.pack(data, keys, h)
    raw = c.header_encode(h)
    for i in range(len(raw)):
        for b in range(8):
            bad = bytearray(raw)
            bad[i] ^= 1 << b
            with pytest.raises(c.ContainerError):
                c.unpack(bits, keys, c.header_decode(bytes(bad)))


@pytest.mark.parametrize("gcm", [False, True])
def test_every_body_bit_flip_is_rejected(gcm):
    # body = IV (or nonce) + ciphertext + MAC (or GCM tag): every region is covered
    data, keys = os.urandom(200), os.urandom(64)
    h = make_header(200, gcm)
    bits = c.pack(data, keys, h)
    for i in range(len(bits)):
        bad = bits.copy()
        bad[i] ^= 1
        with pytest.raises(c.ContainerError):
            c.unpack(bad, keys, h)
