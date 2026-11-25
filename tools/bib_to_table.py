"""Fill the references 1-9 table from references/references.bib (no extra packages)."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIB = ROOT / "references" / "references.bib"
OUT = ROOT / "notes" / "vaibhav" / "week1" / "day4_references_1_to_9_verification.md"


def field(body, name):
    m = re.search(rf"\b{name}\s*=\s*[{{\"](.+?)[}}\"]\s*,?\s*(?:\n|$)", body, re.S | re.I)
    return re.sub(r"\s+", " ", m.group(1)).strip("{} ") if m else ""


def main():
    if not BIB.exists():
        sys.exit(f"Put the .bib file at {BIB} first.")
    entries = re.findall(r"@(\w+)\s*\{\s*([^,\s]+)\s*,(.*?)\n\}", BIB.read_text(encoding="utf-8"), re.S)
    rows = []
    for i, (_, key, body) in enumerate(entries[:9], 1):
        link = field(body, "doi") or field(body, "url") or field(body, "eprint")
        rows.append(f"| {i} | {key} | {field(body, 'title')} | {field(body, 'author')} | {field(body, 'year')} | {link} |  |  |  |  |")
    text = OUT.read_text(encoding="utf-8")
    head = "| # | Key | Title in report | Authors | Year | DOI / URL | Opened (Y/N) | Matches source page | Supports the citing sentence | Fix needed |\n|---|---|---|---|---|---|---|---|---|---|\n"
    a = text.index(head) + len(head)
    b = text.index("\n\n## Claim-to-source")
    OUT.write_text(text[:a] + "\n".join(rows) + text[b:], encoding="utf-8")
    print(f"wrote {len(rows)} rows to {OUT}")
    if len(entries) != 36:
        print(f"warning: .bib has {len(entries)} entries, the report expects 36")


if __name__ == "__main__":
    main()
