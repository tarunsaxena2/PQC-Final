import sys, platform, json
from importlib import metadata as md
from pathlib import Path

pkgs = ["cryptography", "numpy", "scipy", "psutil", "matplotlib", "openpyxl", "pytest"]
info = {"python": sys.version, "windows": platform.platform()}
for p in pkgs:
    try:
        info[p] = md.version(p)
    except md.PackageNotFoundError:
        info[p] = "NOT INSTALLED"
try:
    from cryptography.hazmat.primitives.asymmetric import mlkem
    info["mlkem_module"] = "present"
except ImportError:
    info["mlkem_module"] = "absent"
out = Path("results") / "versions_day1.json"
out.write_text(json.dumps(info, indent=2), encoding="utf-8")
print(json.dumps(info, indent=2))
