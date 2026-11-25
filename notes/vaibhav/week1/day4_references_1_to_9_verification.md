# References 1 to 9: verification table (Vaibhav)

How to fill it: put the project .bib at `references/references.bib`, then run
```
python tools/bib_to_table.py
```
It rewrites this table's rows from entries 1 to 9. Then open each source page and fill the last columns by hand.
Rule: only cite what you have opened. Software or URL-only entries (liboqs, Kyber specification) need a version and an access date instead of a DOI.

| # | Key | Title in report | Authors | Year | DOI / URL | Opened (Y/N) | Matches source page | Supports the citing sentence | Fix needed |
|---|---|---|---|---|---|---|---|---|---|

## Claim-to-source check (V13)
For each sentence citing [1] to [9] write: sentence location, what it claims, what the source says, verdict.
Check these first: RSA qubit estimates in 1.1, QKD attacks [12] and [13] (note: 12 and 13 sit in Yatharth's range, so tell him which sentences cite them).

| Report section | Sentence (short) | Ref | Source says | Verdict |
|---|---|---|---|---|
