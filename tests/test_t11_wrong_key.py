import os
import pytest
import container as c
from helpers import make_header

MODES = [c.MODE_PQC, c.MODE_HYBRID_X25519, c.MODE_HYBRID_QKDSIM]


@pytest.mark.parametrize("gcm", [False, True])
@pytest.mark.parametrize("mode", MODES)
def test_wrong_key_fails_cleanly(mode, gcm):
    # A wrong dk gives a different shared secret (implicit rejection), hence different keys.
    data = os.urandom(500)
    right, wrong = os.urandom(64), os.urandom(64)
    h = make_header(500, gcm, mode=mode)
    bits = c.pack(data, right, h)
    with pytest.raises(c.ContainerError):
        c.unpack(bits, wrong, h)


def test_wrong_key_and_tamper_give_the_same_message():
    data, keys = os.urandom(100), os.urandom(64)
    h = make_header(100)
    bits = c.pack(data, keys, h)
    with pytest.raises(c.ContainerError) as wrong:
        c.unpack(bits, os.urandom(64), h)
    bad = bits.copy()
    bad[40] ^= 1
    with pytest.raises(c.ContainerError) as tampered:
        c.unpack(bad, keys, h)
    assert str(wrong.value) == str(tampered.value)


def test_bad_key_length_rejected():
    with pytest.raises(c.ContainerError):
        c.pack(b"x", os.urandom(63), make_header(1))


@pytest.mark.skip(reason="needs the key layer and facade; wire up on integration day (Week 2, Day 4)")
def test_hybrid_qkdsim_extract_without_key_file_fails_cleanly():
    pass
