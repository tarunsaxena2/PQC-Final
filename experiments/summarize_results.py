import csv
import statistics
from pathlib import Path

R = Path(__file__).resolve().parent.parent / "results"


def read(name):
    p = R / name
    return list(csv.DictReader(p.open(encoding="utf-8"))) if p.exists() else []


def ms(values):
    if not values:
        return "n/a"
    sd = statistics.stdev(values) if len(values) > 1 else 0.0
    return f"{statistics.mean(values):.4f} +/- {sd:.4f}"


e3 = read("e3_ablation.csv")
if e3:
    print("### E3 ablation (mean +/- sd over all clips and trials)")
    print("| Ablation | n | BER | PSNR (dB) | Entropy (bits/byte) | Frames changed | Decrypt OK |")
    print("|---|---|---|---|---|---|---|")
    for a in "ABCD":
        rows = [r for r in e3 if r["ablation"] == a]
        if not rows:
            continue
        psnr = [float(r["psnr_db"]) for r in rows if float(r["psnr_db"]) != float("inf")]
        skipped = len(rows) - len(psnr)
        dec = [r["decrypt_ok"] for r in rows if r["decrypt_ok"] != ""]
        dec_txt = f"{sum(d == 'True' for d in dec)}/{len(dec)}" if dec else "n/a"
        print(f"| {a} | {len(rows)} | {ms([float(r['ber']) for r in rows])} | {ms(psnr)}"
              f"{' (' + str(skipped) + ' infinite skipped)' if skipped else ''} | "
              f"{ms([float(r['entropy_bits_per_byte']) for r in rows])} | "
              f"{ms([float(r['frames_changed_frac']) for r in rows])} | {dec_txt} |")
else:
    print("no results\\e3_ablation.csv yet")

e8 = read("e8_roundtrip.csv")
if e8:
    print("\n### E8 round trip")
    problems = [r for r in e8 if r["roundtrip_identical"] != "True"
                or "WRONG_BYTES" in r["wrong_key"] + r["damaged_wav"] + r["no_qkd_key_file"]]
    print(f"cases: {len(e8)}, round trip identical: {sum(r['roundtrip_identical'] == 'True' for r in e8)}, "
          f"problem cases: {len(problems)}")
    print("| Mode | Cipher | Overhead (B) | Overhead (% of capacity) |")
    print("|---|---|---|---|")
    for mode in sorted({r["mode"] for r in e8}):
        for cipher in sorted({r["cipher"] for r in e8}):
            rows = [r for r in e8 if r["mode"] == mode and r["cipher"] == cipher]
            if rows:
                ob = [int(r["overhead_B"]) for r in rows]
                op = [float(r["overhead_pct_of_capacity"]) for r in rows]
                print(f"| {mode} | {cipher} | {min(ob)} to {max(ob)} | {min(op):.2f} to {max(op):.2f} |")
    print("back-end(s):", ", ".join(sorted({r["backend"] for r in e8})))
else:
    print("no results\\e8_roundtrip.csv yet")
