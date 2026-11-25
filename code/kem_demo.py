"""Week 1 Day 3: ML-KEM demo + back-end comparison (Vaibhav, Key Layer).

Run from the project root (venv active):
    python code/kem_demo.py            # print tables
    python code/kem_demo.py --write    # also save notes/vaibhav/week1/day3_kem_demo_results.md
Prints only sizes, timings and True/False. Never prints secrets.
"""
import argparse, importlib, platform, statistics, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))
from key_layer import FIPS203_SIZES, KeyLayerError  # noqa: E402


def load_backends():
    found, notes = {}, {}
    for name, mod in (("liboqs", "liboqs_backend"), ("openssl", "openssl_backend"), ("pure-python", "pure_backend")):
        try:
            m = importlib.import_module(f"key_layer.{mod}")
            if name == "liboqs":
                m._oqs()
            if name == "openssl" and not m.available():
                raise KeyLayerError("cryptography wheel has no working ML-KEM")
            found[name] = m
        except ModuleNotFoundError:
            notes[name] = "module not in repo yet (add key_layer/pure_backend.py)" if name == "pure-python" else "missing"
        except Exception as exc:
            notes[name] = f"unavailable: {exc}"
    return found, notes


def roundtrip(m, level, reps=20):
    t = {"keygen": [], "encaps": [], "decaps": []}
    ok = True
    for _ in range(reps):
        a = time.perf_counter(); ek, dk = m.keygen(level); b = time.perf_counter()
        ct, ss1 = m.encaps(ek); c = time.perf_counter()
        ss2 = m.decaps(dk, ct); d = time.perf_counter()
        t["keygen"].append(b - a); t["encaps"].append(c - b); t["decaps"].append(d - c)
        ok &= ss1 == ss2
    sizes = (len(ek), len(dk), len(ct), len(ss1))
    return sizes, ok, {k: statistics.median(v) * 1000 for k, v in t.items()}


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    backends, notes = load_backends()
    lines = [f"# Day 3 results: ML-KEM demo and back-end comparison", "",
             f"Python {platform.python_version()} on {platform.platform()}", ""]
    try:
        import oqs
        lines.append(f"liboqs {oqs.oqs_version()}, liboqs-python {oqs.oqs_python_version()}")
    except Exception:
        lines.append("liboqs: not importable")
    import cryptography
    lines += [f"cryptography {cryptography.__version__}", "",
              "## Sizes and round trips (ek / dk / ct / ss in bytes; medians of 20 runs, ms, order of magnitude only)", "",
              "| Back-end | Level | ek | dk | ct | ss | FIPS 203 sizes | Round trip | keygen ms | encaps ms | decaps ms |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, m in backends.items():
        for level in (512, 768, 1024):
            try:
                sizes, ok, t = roundtrip(m, level)
            except KeyLayerError as exc:
                lines.append(f"| {name} | {level} | - | - | - | - | - | not supported | - | - | - |")
                continue
            std = "yes" if (name == "openssl" or sizes == FIPS203_SIZES[level]) else "NO"
            if name == "openssl":
                std = "ek/ct yes; dk is 64 B seed"
            lines.append(f"| {name} | {level} | {sizes[0]} | {sizes[1]} | {sizes[2]} | {sizes[3]} | {std} | {ok} | "
                         f"{t['keygen']:.3f} | {t['encaps']:.3f} | {t['decaps']:.3f} |")
    lines += ["", "## Back-end availability", ""]
    for n in ("liboqs", "openssl", "pure-python"):
        lines.append(f"- {n}: " + ("available" if n in backends else notes.get(n, "unavailable")))
    if "liboqs" in backends and "openssl" in backends:
        lines += ["", "## Cross-back-end agreement (swap ek / ct; each side decapsulates with its own dk)", ""]
        for level in (768, 1024):
            L, O = backends["liboqs"], backends["openssl"]
            ek_o, dk_o = O.keygen(level); ct, ss = L.encaps(ek_o); a = O.decaps(dk_o, ct) == ss
            ek_l, dk_l = L.keygen(level); ct, ss = O.encaps(ek_l); b = L.decaps(dk_l, ct) == ss
            lines.append(f"- ML-KEM-{level}: liboqs encaps -> OpenSSL decaps {a}; OpenSSL encaps -> liboqs decaps {b}")
    lines += ["", "## OpenSSL ML-KEM availability note", "",
              "- " + ("The cryptography wheel exposes ML-KEM-768 and ML-KEM-1024 (not 512), so OpenSSL can be a third back-end for those two levels."
                      if "openssl" in backends else "The cryptography wheel does NOT expose ML-KEM here, so the selector is liboqs + pure-Python only; the report says so."),
              "- Only the speed ORDER of magnitude is recorded here; the real timing runs (E1) are in Week 3 on the frozen machine."]
    text = "\n".join(lines)
    print(text)
    if args.write:
        out = ROOT / "notes" / "vaibhav" / "week1" / "day3_kem_demo_results.md"
        out.parent.mkdir(parents=True, exist_ok=True); out.write_text(text + "\n", encoding="utf-8")
        print(f"\nsaved {out}")


if __name__ == "__main__":
    main()
