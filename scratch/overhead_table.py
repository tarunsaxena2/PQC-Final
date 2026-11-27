import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "code"))
import container as c

CAP = 51652   # bytes, 20 s clip (the one capacity figure used everywhere)
print("level | header B | cipher | payload B | body B | overhead B | % of capacity")
for level, name in ((1, "512"), (2, "768"), (3, "1024")):
    for gcm in (False, True):
        for n in (1000, 1024, 4096, 8192, 16384, 32768):
            hdr, body = c.header_len(level), c.body_length(n, gcm)
            ov = hdr + body - n
            print(f"ML-KEM-{name} | {hdr} | {'GCM' if gcm else 'CBC+HMAC'} | {n} | {body} | {ov} | {100 * ov / CAP:.2f}")
