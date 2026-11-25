"""
facade_mock.py  -  MOCK tool-layer facade (Week 1, Day 2, Tarun)

Frozen interface (proposal for the Day 2 meeting):

    keygen(level, out_dir)                          -> (ek_path, dk_path)
    hide(carrier, file, ek, level, mode,
         qkd_key_file=None, out=None)               -> stego_path
    extract(stego, dk, qkd_key_file=None,
            out=None)                               -> extracted_file_path

    mode in {"pqc", "hybrid-x25519", "hybrid-qkdsim"}
    level in {512, 768, 1024}
    All paths are pathlib.Path (str accepted). All file I/O is binary.

NOTE: qkd_key_file and out are optional keyword arguments added to the plan's
signature. hybrid-qkdsim needs the simulated-QKD key file on both sides, so
this must be agreed by all four members before the interface is frozen.

This module is a MOCK. There is no real ML-KEM, AES, HMAC, QIM or WAV code.
The "stego file" is a plain byte container, not audio. It exists only so the
CLI and GUI can be built and tested before the real layers are integrated.
"""
import os
import struct
from pathlib import Path

MODES = {"pqc": 0, "hybrid-x25519": 1, "hybrid-qkdsim": 2}
MODE_NAMES = {v: k for k, v in MODES.items()}
LEVELS = (512, 768, 1024)

MAGIC = b"MOCK"
VERSION = 1
# magic(4) version(1) level(2) mode(1) key_id(8) payload_len(4)
HEADER_FMT = ">4sBHB8sI"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# Stub constant: capacity of a 20 s clip, from the plan (51,652 B)
MOCK_CAPACITY = 51652


class FacadeError(Exception):
    """Base class for clean, user-readable errors."""


class PayloadTooLargeError(FacadeError):
    pass


class KeyMismatchError(FacadeError):
    pass


class MissingQkdKeyFileError(FacadeError):
    pass


class BadStegoFileError(FacadeError):
    pass


def capacity(carrier):
    """Stub: returns the plan's capacity figure for a 20 s clip."""
    return MOCK_CAPACITY


def keygen(level, out_dir):
    if level not in LEVELS:
        raise FacadeError("level must be one of %s" % (LEVELS,))
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_id = os.urandom(8)
    lv = struct.pack(">H", level)
    ek_path = out_dir / ("ek_%d.bin" % level)
    dk_path = out_dir / ("dk_%d.bin" % level)
    ek_path.write_bytes(b"MOCKEK" + lv + key_id)
    dk_path.write_bytes(b"MOCKDK" + lv + key_id)
    return ek_path, dk_path


def _read_key(path, prefix):
    data = Path(path).read_bytes()
    if not data.startswith(prefix) or len(data) != len(prefix) + 2 + 8:
        raise KeyMismatchError("not a valid key file: %s" % path)
    level = struct.unpack(">H", data[len(prefix):len(prefix) + 2])[0]
    return level, data[len(prefix) + 2:]


def _check_mode(mode):
    if mode not in MODES:
        raise FacadeError("mode must be one of %s" % (sorted(MODES),))


def _check_qkd(mode, qkd_key_file):
    if mode == "hybrid-qkdsim":
        if qkd_key_file is None or not Path(qkd_key_file).is_file():
            raise MissingQkdKeyFileError(
                "hybrid-qkdsim needs the simulated-QKD key file (simulation only)")


def hide(carrier, file, ek, level, mode, qkd_key_file=None, out=None):
    _check_mode(mode)
    if level not in LEVELS:
        raise FacadeError("level must be one of %s" % (LEVELS,))
    _check_qkd(mode, qkd_key_file)
    carrier, file = Path(carrier), Path(file)
    if not carrier.is_file():
        raise FacadeError("carrier not found: %s" % carrier)
    payload = file.read_bytes()
    ek_level, key_id = _read_key(ek, b"MOCKEK")
    if ek_level != level:
        raise KeyMismatchError("key level %d does not match level %d" % (ek_level, level))
    if len(payload) + HEADER_SIZE > capacity(carrier):
        raise PayloadTooLargeError(
            "payload too large: %d B + %d B header > capacity %d B"
            % (len(payload), HEADER_SIZE, capacity(carrier)))
    out = Path(out) if out else carrier.with_name(carrier.stem + "_stego.bin")
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, level, MODES[mode], key_id, len(payload))
    out.write_bytes(header + payload)  # written only after every check passed
    return out


def extract(stego, dk, qkd_key_file=None, out=None):
    stego = Path(stego)
    data = stego.read_bytes()
    if len(data) < HEADER_SIZE:
        raise BadStegoFileError("file too short to be a stego file")
    magic, version, level, mode_byte, key_id, n = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
    if magic != MAGIC or version != VERSION or mode_byte not in MODE_NAMES:
        raise BadStegoFileError("not a valid stego file")
    mode = MODE_NAMES[mode_byte]
    _check_qkd(mode, qkd_key_file)
    dk_level, dk_id = _read_key(dk, b"MOCKDK")
    if dk_level != level or dk_id != key_id:
        raise KeyMismatchError("wrong key: this dk does not belong to this stego file")
    payload = data[HEADER_SIZE:HEADER_SIZE + n]
    if len(payload) != n:
        raise BadStegoFileError("stego file is truncated")
    out = Path(out) if out else stego.with_name(stego.stem + "_extracted.bin")
    out.write_bytes(payload)
    return out


def _selftest():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        carrier = td / "carrier.wav"
        carrier.write_bytes(b"RIFFfake")
        msg = td / "msg.txt"
        msg.write_bytes(b"hello facade" * 10)
        qkd = td / "qkd.key"
        qkd.write_bytes(b"simulation")
        ek, dk = keygen(768, td / "keys")
        _, dk2 = keygen(768, td / "keys2")

        for mode in MODES:
            q = qkd if mode == "hybrid-qkdsim" else None
            st = hide(carrier, msg, ek, 768, mode, qkd_key_file=q)
            got = extract(st, dk, qkd_key_file=q)
            assert got.read_bytes() == msg.read_bytes(), mode

        def fails(exc, fn):
            try:
                fn()
            except exc:
                return True
            return False

        st = hide(carrier, msg, ek, 768, "pqc", out=td / "s.bin")
        assert fails(KeyMismatchError, lambda: extract(st, dk2))
        assert fails(MissingQkdKeyFileError,
                     lambda: hide(carrier, msg, ek, 768, "hybrid-qkdsim"))
        assert fails(FacadeError, lambda: hide(carrier, msg, ek, 768, "bogus"))
        big = td / "big.bin"
        big.write_bytes(b"x" * (MOCK_CAPACITY + 1))
        target = td / "no_output.bin"
        assert fails(PayloadTooLargeError,
                     lambda: hide(carrier, big, ek, 768, "pqc", out=target))
        assert not target.exists()  # no partial output
    print("facade_mock selftest: PASS")


if __name__ == "__main__":
    _selftest()
