import csv
import sys
from pathlib import Path

import numpy as np
from scipy.io import wavfile

rows = []
for p in sorted(Path(sys.argv[1]).glob("*.wav")):
    sr, x = wavfile.read(p)
    rows.append({"clip": p.name, "sample_rate_Hz": sr, "duration_s": round(len(x) / sr, 2),
                 "peak": int(np.max(np.abs(x.astype(np.int32)))),
                 "clipped_samples": int(np.sum(np.abs(x.astype(np.int32)) >= 32767)),
                 "type": "speech or music", "source": "", "licence": ""})
out = Path("results") / "clip_info.csv"
with out.open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]))
    w.writeheader()
    w.writerows(rows)
print(len(rows), "clips ->", out)
