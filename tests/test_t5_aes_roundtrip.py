import os
import pytest
import container as c
from helpers import make_header

SIZES = [0, 1, 15, 16, 17, 1024 * 1024]


@pytest.mark.parametrize("gcm", [False, True])
@pytest.mark.parametrize("n", SIZES)
def test_round_trip(n, gcm):
    data, keys = os.urandom(n), os.urandom(64)
    h = make_header(n, gcm)
    bits = c.pack(data, keys, h)
    assert len(bits) == 8 * h.body_len
    assert c.unpack(bits, keys, h) == data


def test_body_length_formula():
    assert c.body_length(0) == 64 and c.body_length(16) == 80 and c.body_length(17) == 80
    assert c.body_length(0, gcm=True) == 28


def test_cbc_uses_fresh_iv():
    data, keys = os.urandom(64), os.urandom(64)
    h = make_header(64)
    assert (c.pack(data, keys, h) != c.pack(data, keys, h)).any()


def test_payload_length_must_match_header():
    # CBC pads to 16-byte blocks, so 10 and 11 bytes give the same body length; use sizes in different blocks
    with pytest.raises(c.ContainerError):
        c.pack(os.urandom(10), os.urandom(64), make_header(20))


def test_payload_length_must_match_header_gcm():
    with pytest.raises(c.ContainerError):
        c.pack(os.urandom(10), os.urandom(64), make_header(11, gcm=True))

