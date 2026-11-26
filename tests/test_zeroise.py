import os
import container as c
from helpers import make_header


def test_zeroise_overwrites_bytearrays():
    b = bytearray(b"secret key material")
    c.zeroise(b)
    assert b == bytearray(len(b))


def test_pack_does_not_change_callers_keys():
    keys = bytearray(os.urandom(64))
    before = bytes(keys)
    c.pack(b"hello", keys, make_header(5))
    assert bytes(keys) == before     # we wipe our own copies, never the caller's
