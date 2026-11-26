import csv
import os
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "code"))
import container as c

CAP = 51652                      # bytes, 20 s clip: the one capacity figure used everywhere
SIZES = [1024 * k for k in (1, 4, 8, 16, 32)]
TRIALS, WARMUP = 30, 3


def run(gcm, level, n):
    data, keys = os.urandom(n), os.urandom(64)
    h = c.Header(level=level, mode=c.MODE_PQC, kem_ct=os.urandom(c.CT_LEN[level]),
                 body_len=c.body_length(n, gcm), gcm=gcm)
    tp, tu = [], []
    for i in range(WARMUP + TRIALS):
        t0 = time.perf_counter()
        bits = c.pack(data, keys, h)
        t1 = time.perf_counter()
        out = c.unpack(bits, keys, h)
        t2 = time.perf_counter()
        assert out == data
        if i >= WARMUP:
            tp.append((t1 - t0) * 1e3)
            tu.append((t2 - t1) * 1e3)
    hdr = len(c.header_encode(h))
    overhead = hdr + h.body_len - n
    return {"cipher": "GCM" if gcm else "CBC+HMAC", "level": level, "payload_B": n, "header_B": hdr,
            "body_B": h.body_len, "overhead_B": overhead,
            "overhead_pct_of_capacity": round(100 * overhead / CAP, 2),
            "pack_ms_mean": round(statistics.mean(tp), 4), "pack_ms_sd": round(statistics.stdev(tp), 4),
            "unpack_ms_mean": round(statistics.mean(tu), 4), "unpack_ms_sd": round(statistics.stdev(tu), 4)}


rows = [run(gcm, level, n) for gcm in (False, True) for level in (2, 3) for n in SIZES]
out = ROOT / "results" / "e8_container_prototype.csv"
out.parent.mkdir(exist_ok=True)
with out.open("w", newline="") as f:          # no keys or secrets are written
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
for r in rows:
    print(r["cipher"], r["level"], r["payload_B"], "overhead", r["overhead_B"], "B", r["overhead_pct_of_capacity"], "%")
print("written", out)
