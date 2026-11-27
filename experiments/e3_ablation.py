import argparse
import csv
import os
import statistics
import sys
from pathlib import Path

import numpy as np
from scipy.io import wavfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adapter
import container as c

ROOT = Path(__file__).resolve().parent.parent


def psnr(a, b):
    mse = np.mean((a.astype(np.float64) - b.astype(np.float64)) ** 2)
    return float("inf") if mse == 0 else float(10 * np.log10(32767.0 ** 2 / mse))


def entropy_bits_per_byte(bits):
    counts = np.bincount(np.packbits(bits), minlength=256)
    p = counts[counts > 0] / counts.sum()
    return float(-(p * np.log2(p)).sum())


def locality(cover, stego, frame):
    n = len(cover) // frame
    changed = (cover[: n * frame] != stego[: n * frame]).reshape(n, frame).any(axis=1)
    if not changed.any():
        return 0.0, 0.0
    idx = np.flatnonzero(changed)
    return float(changed.mean()), float((idx[-1] - idx[0] + 1) / n)


def make_payload(path, size, rng):
    base = Path(path).read_bytes()
    if not base:
        raise SystemExit("payload file is empty")
    data = base * (size // len(base) + 2)
    start = int(rng.integers(0, len(base)))
    return data[start:start + size]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clips", default=str(ROOT / "audio" / "carriers"))
    ap.add_argument("--step", type=float, required=True, help="final QIM step from E6 / notation sheet")
    ap.add_argument("--frame", type=int, required=True, help="frame size N from the notation sheet")
    ap.add_argument("--payload", default=str(ROOT / "notes" / "container_interface_v1.md"),
                    help="a real text file (structured data makes the entropy column meaningful)")
    ap.add_argument("--payload-bytes", type=int, default=4096)
    ap.add_argument("--trials", type=int, default=30)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", default=str(ROOT / "results" / "e3_ablation.csv"))
    args = ap.parse_args()

    tmp = ROOT / "results" / "tmp_e3.wav"
    rows = []
    for clip in sorted(Path(args.clips).glob("*.wav")):
        cap = adapter.capacity_bytes(clip)
        _, cover = wavfile.read(clip)
        for abl in "ABCD":
            for t in range(args.trials):
                seed = args.seed + t
                rng = np.random.default_rng(seed)
                payload = make_payload(args.payload, args.payload_bytes, rng)
                keys = os.urandom(64)               # stand-in for derive_keys(ss); never written out
                header = c.Header(level=2, mode=c.MODE_PQC, kem_ct=os.urandom(c.CT_LEN[2]),
                                  body_len=c.body_length(len(payload)))
                if abl in "BD":
                    bits = c.pack(payload, keys, header)
                else:
                    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
                perm_key = bytes(keys[16:32]) if abl in "CD" else None
                if len(bits) // 8 > cap:
                    print("skip (payload > capacity):", clip.name)
                    break
                adapter.embed_bits(clip, bits, tmp, perm_key, args.step)
                _, stego = wavfile.read(tmp)
                got = np.asarray(adapter.extract_bits(tmp, len(bits), perm_key, args.step), dtype=np.uint8)
                frac, span = locality(cover, stego, args.frame)
                decrypt_ok = ""
                if abl in "BD":
                    try:
                        decrypt_ok = c.unpack(got, keys, header) == payload
                    except c.ContainerError:
                        decrypt_ok = False
                rows.append({"clip": clip.name, "backend": adapter.BACKEND, "ablation": abl, "trial": t,
                             "seed": seed, "embedded_bits": len(bits), "ber": float(np.mean(got != bits)),
                             "psnr_db": psnr(cover, stego),
                             "entropy_bits_per_byte": entropy_bits_per_byte(bits),
                             "frames_changed_frac": frac, "span_frac": span, "decrypt_ok": decrypt_ok})
        print("done", clip.name)

    tmp.unlink(missing_ok=True)
    Path(args.out).parent.mkdir(exist_ok=True)
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    print("\nablation  mean BER   mean PSNR   entropy   frames_changed")
    for abl in "ABCD":
        r = [x for x in rows if x["ablation"] == abl and np.isfinite(x["psnr_db"])]
        if r:
            print(f"   {abl}     {statistics.mean(x['ber'] for x in r):.5f}   "
                  f"{statistics.mean(x['psnr_db'] for x in r):7.2f}   "
                  f"{statistics.mean(x['entropy_bits_per_byte'] for x in r):.3f}     "
                  f"{statistics.mean(x['frames_changed_frac'] for x in r):.3f}")
    print("written", args.out)


if __name__ == "__main__":
    main()
