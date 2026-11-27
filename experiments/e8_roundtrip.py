import argparse
import csv
import os
import shutil
import sys
from pathlib import Path

import numpy as np
from scipy.io import wavfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import adapter
import container as c

ROOT = Path(__file__).resolve().parent.parent
MODES = ["pqc", "hybrid-x25519", "hybrid-qkdsim"]
LEVEL = 2                                   # ML-KEM-768


def damage(src, dst, rng, n=300):
    """Heavy random damage to samples of a copy of the stego WAV (tamper at the file level)."""
    sr, x = wavfile.read(src)
    x = x.copy()
    idx = rng.choice(len(x), size=min(n, len(x)), replace=False)
    x[idx] ^= 0x4000
    wavfile.write(dst, sr, x)


def attempt(fn):
    """Return ('ok', result) or ('fail', exception class name). Never leaks secrets: only the class name."""
    try:
        return "ok", fn()
    except Exception as e:                  # noqa: BLE001 - we want to classify every failure
        return "fail", type(e).__name__


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clips", default=str(ROOT / "audio" / "carriers"))
    ap.add_argument("--sizes", type=int, nargs="+", default=[1024, 4096, 8192, 16384])
    ap.add_argument("--clips-limit", type=int, default=2, help="use the first N clips")
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--out", default=str(ROOT / "results" / "e8_roundtrip.csv"))
    args = ap.parse_args()

    rng = np.random.default_rng(args.seed)
    tmp = ROOT / "results" / "tmp_e8"
    tmp.mkdir(parents=True, exist_ok=True)
    clips = sorted(Path(args.clips).glob("*.wav"))[: args.clips_limit]
    if not clips:
        raise SystemExit("no WAV clips found in " + args.clips)
    qkd_file = tmp / "qkd_sim_key.bin"
    adapter.make_qkd_key_file(qkd_file)

    rows = []
    for clip in clips:
        cap = adapter.capacity_bytes(clip)
        for mode in MODES:
            for gcm in (False, True):
                for n in args.sizes:
                    if n > cap:
                        continue
                    payload = rng.bytes(n)
                    ek, dk = adapter.keygen(LEVEL)
                    _, dk_wrong = adapter.keygen(LEVEL)
                    stego = tmp / "stego.wav"
                    kf = qkd_file if mode == "hybrid-qkdsim" else None
                    adapter.hide(clip, payload, ek, LEVEL, mode, stego, gcm=gcm, qkd_key_file=kf)

                    s, out = attempt(lambda: adapter.extract(stego, dk, qkd_key_file=kf))
                    roundtrip = (s == "ok" and out == payload)

                    s, out = attempt(lambda: adapter.extract(stego, dk_wrong, qkd_key_file=kf))
                    wrong_key = "WRONG_BYTES" if (s == "ok") else "clean_fail:" + out

                    bad = tmp / "stego_damaged.wav"
                    damage(stego, bad, rng)
                    s, out = attempt(lambda: adapter.extract(bad, dk, qkd_key_file=kf))
                    if s == "ok":
                        tamper = "correct_file" if out == payload else "WRONG_BYTES"
                    else:
                        tamper = "clean_fail:" + out

                    if mode == "hybrid-qkdsim":
                        s, out = attempt(lambda: adapter.extract(stego, dk, qkd_key_file=None))
                        nokey = "WRONG_BYTES" if s == "ok" else "clean_fail:" + out
                    else:
                        nokey = "n/a"

                    overhead = c.header_len(LEVEL) + c.body_length(n, gcm) - n
                    rows.append({
                        "clip": clip.name, "backend": adapter.BACKEND, "mode": mode,
                        "cipher": "GCM" if gcm else "CBC+HMAC", "payload_B": n,
                        "overhead_B": overhead, "overhead_pct_of_capacity": round(100 * overhead / cap, 2),
                        "roundtrip_identical": roundtrip, "wrong_key": wrong_key,
                        "damaged_wav": tamper, "no_qkd_key_file": nokey, "seed": args.seed})
                    print(rows[-1]["mode"], rows[-1]["cipher"], n, roundtrip, wrong_key, tamper, nokey)

    Path(args.out).parent.mkdir(exist_ok=True)
    with open(args.out, "w", newline="") as f:      # no keys, secrets or payloads are written
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    shutil.rmtree(tmp, ignore_errors=True)
    bad_rows = [r for r in rows if not r["roundtrip_identical"] or "WRONG_BYTES" in
                (r["wrong_key"] + r["damaged_wav"] + r["no_qkd_key_file"])]
    print(f"\n{len(rows)} cases, {len(bad_rows)} problem cases, written {args.out}")


if __name__ == "__main__":
    main()
