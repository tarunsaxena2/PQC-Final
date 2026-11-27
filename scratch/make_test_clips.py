import sys
from pathlib import Path

import numpy as np
from scipy.io import wavfile

out = Path(sys.argv[1])
out.mkdir(parents=True, exist_ok=True)
sr = 44100
rng = np.random.default_rng(1)
t = np.arange(20 * sr) / sr
for i, f0 in enumerate((220, 330, 440), start=1):
    x = 0.3 * np.sin(2 * np.pi * f0 * t) + 0.1 * np.sin(2 * np.pi * 2 * f0 * t) + 0.02 * rng.standard_normal(len(t))
    wavfile.write(out / f"test_clip_{i}.wav", sr, (x * 20000).astype(np.int16))
print("wrote 3 synthetic test clips to", out)
