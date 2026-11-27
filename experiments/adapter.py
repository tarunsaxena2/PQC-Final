"""adapter.py - the ONLY file that knows the other layers' real function names.
Fill in the functions marked TODO once, after Integration Day. E3 and E8 import only from here.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "code"))

BACKEND = "TODO: liboqs or pure-python (the report needs this on every result)"


# ---- audio layer (Yatharth) -------------------------------------------------
def capacity_bytes(cover_wav):
    """Max payload bytes for this clip (header + MAC overhead included if the layer counts it)."""
    raise NotImplementedError("TODO: call the audio layer's capacity(clip)")


def embed_bits(cover_wav, bits, out_wav, perm_key, step):
    """Embed a uint8 0/1 array into cover_wav and write out_wav (16-bit WAV).
    perm_key=None must mean NO permutation (identity order) - ask Yatharth for this switch."""
    raise NotImplementedError("TODO: call embed_body (and a no-permutation option)")


def extract_bits(stego_wav, n_bits, perm_key, step):
    """Return a uint8 0/1 array of n_bits."""
    raise NotImplementedError("TODO: call extract_body")


# ---- tool layer (Tarun), used by E8 only --------------------------------------
def keygen(level):
    """Return (ek, dk) for the receiver."""
    raise NotImplementedError("TODO: key layer keygen(level)")


def make_qkd_key_file(path):
    """Write the simulated-QKD key file (hybrid-qkdsim mode). Labelled simulation."""
    raise NotImplementedError("TODO: Vaibhav's key file helper")


def hide(carrier, payload_bytes, ek, level, mode, out_wav, gcm=False, qkd_key_file=None):
    """mode in {'pqc', 'hybrid-x25519', 'hybrid-qkdsim'}. Writes out_wav."""
    raise NotImplementedError("TODO: Tarun's facade hide(...)")


def extract(stego_wav, dk, qkd_key_file=None):
    """Return the file bytes, or RAISE an exception. Must never return partial or garbage bytes."""
    raise NotImplementedError("TODO: Tarun's facade extract(...)")
