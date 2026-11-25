# References 1 to 9: verification table (Vaibhav)

How to fill it: put the project .bib at `references/references.bib`, then run
```
python tools/bib_to_table.py
```
It rewrites this table's rows from entries 1 to 9. Then open each source page and fill the last columns by hand.
Rule: only cite what you have opened. Software or URL-only entries (liboqs, Kyber specification) need a version and an access date instead of a DOI.

| # | Key | Title in report | Authors | Year | DOI / URL | Opened (Y/N) | Matches source page | Supports the citing sentence | Fix needed |
|---|---|---|---|---|---|---|---|---|---|
| 1 | nist203 | Module-Lattice-Based Key-Encapsulation Mechanism Standard | National Institute of Standards and Technology | 2024 | 10.6028/NIST.FIPS.203 |  |  |  |  |
| 2 | bos2018 | CRYSTALS-Kyber: A CCA-secure module-lattice-based KEM | Bos, Joppe and Ducas, Léo and Kiltz, Eike and Lepoint, Tancrède and Lyubashevsky, Vadim and Schanck, John M. and Schwabe, Peter and Seiler, Gregor and Stehlé, Damien | 2018 | 10.1109/EuroSP.2018.00032 |  |  |  |  |
| 3 | shor97 | Polynomial-time algorithms for prime factorization and discrete logarithms on a quantum computer | Shor, Peter W. | 1997 | 10.1137/S0097539795293172 |  |  |  |  |
| 4 | gidney21 | How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits | Gidney, Craig and Ekerå, Martin | 2021 | 10.22331/q-2021-04-15-433 |  |  |  |  |
| 5 | gidney25 | How to factor a 2048-bit RSA integer with less than a million noisy qubits | Gidney, Craig | 2025 | https://arxiv.org/abs/2505.15917 |  |  |  |  |
| 6 | mosca18 | Cybersecurity in an era with quantum computers: Will we be ready? | Mosca, Michele | 2018 | 10.1109/MSP.2018.3761723 |  |  |  |  |
| 7 | nistir8547 | Transition to post-quantum cryptography standards (initial public draft) | Moody, Dustin and Perlner, Ray and Regenscheid, Andrew and Robinson, Angela and Cooper, David | 2024 | 10.6028/NIST.IR.8547.ipd |  |  |  |  |
| 8 | bb84 | Quantum cryptography: Public key distribution and coin tossing | Bennett, Charles H. and Brassard, Gilles | 1984 |  |  |  |  |  |
| 9 | scarani09 | The security of practical quantum key distribution | Scarani, Valerio and Bechmann-Pasquinucci, Helle and Cerf, Nicolas J. and Dušek, Miloslav and Lütkenhaus, Norbert and Peev, Momtchil | 2009 | 10.1103/RevModPhys.81.1301 |  |  |  |  |

## Claim-to-source check (V13)
For each sentence citing [1] to [9] write: sentence location, what it claims, what the source says, verdict.
Check these first: RSA qubit estimates in 1.1, QKD attacks [12] and [13] (note: 12 and 13 sit in Yatharth's range, so tell him which sentences cite them).

| Report location (PDF page) | Sentence (short) | Ref | Source should say (from my knowledge; confirm on the page) | Verdict |
|---|---|---|---|---|
| Abstract/summary (p5) | ML-KEM (FIPS 203, derived from Kyber), NIST-standardised, runs in software on a classical channel | [1], [2] | FIPS 203 specifies ML-KEM and says it is derived from CRYSTALS-Kyber; [2] is the Kyber paper | Supported. Confirm the "derived from" wording in FIPS 203 |
| 1.1 (p12) | "In 1994 Peter Shor showed ... polynomial time" | [3] | [3] is the 1997 SIAM J. Comput. journal version; 1994 is the earlier conference version | FIX: year and reference disagree. Say "in 1994 (journal version 1997)" or drop the year |
| 1.1 (p12) | About twenty million noisy qubits in 2019-2021 | [4] | Gidney and Ekera: 2048-bit RSA in 8 hours with 20 million noisy qubits (arXiv 2019, Quantum 2021) | Supported. Confirm "about" and the years |
| 1.1 (p12) | Fewer than one million noisy qubits in 2025 | [5] | Gidney 2025 preprint: under one million noisy qubits | Supported. Confirm the run time and the exact title (see title note below) |
| 1.1 (p12) | Migration date depends on how long data must stay secret | [6] | Mosca 2018: the migration-time argument (shelf life plus migration time versus time to a quantum computer) | Supported. Check whether the phrase "harvest now, decrypt later" appears in [6]; if not, cite it only for the argument |
| 1.1 (p12) | "National and international agencies have already published timelines" | [7] | NIST IR 8547 is one US agency's report | FIX: "international" is not supported by [7] alone. Reword to NIST, or add other sources you have opened |
| 1.1 (p12) | QKD began with BB84 [8]; uses quantum mechanics to establish a key [9] | [8], [9] | Bennett and Brassard 1984; Scarani et al. 2009 review | Supported |
| 2.1 (p17) | Sifting keeps matching-basis positions; error rate in a sample bounds eavesdropper information | [8], [9] | Sifting is in [8]; the information bound is treated in [9] | Supported. Confirm the bound statement in [9] |
| 2.1 (p18) | PQC is introduced by updating libraries; agencies published migration timelines | [7] | NIST IR 8547 gives a NIST timeline | Partly supported: same "agencies" problem as above |
| 2.2 (p18) | NIST standardised ML-KEM as FIPS 203 and ML-DSA as FIPS 204 in August 2024 | [1], [17] | FIPS 203 and FIPS 204 were released in Aug 2024 | Supported. Confirm the date on both pages |
| 2.2 (p18) | Kyber design and security proof in the QROM are described in | [2], [20] | [2] Kyber paper; [20] is the Kyber specification | Supported if [20] is the specification (Uday checks [20]) |
| 2.3 (p18) | Ring R_q = Z_q[X]/(X^256+1), q = 3329, three parameter sets for NIST categories 1, 3, 5 | [1] | FIPS 203 parameter table | Supported. Confirm the category numbers |
| 4.1 (p26) | Compress_d(x) = round((2^d/q)x) mod 2^d | [1] | FIPS 203 defines Compress and Decompress | Supported. Compare the equation with FIPS 203 |
| 4.1 (p26) | Table 4.1 parameter sets | [1], [20] | Sizes from FIPS 203; failure probabilities from the Kyber spec | Sizes: supported. Failure probabilities: Uday checks [20] |
| 4.2 (p27) | Asymptotic secret fraction r >= 1 - (1+f)h2(Q) | [9] | [9] gives BB84 key-rate bounds; check that this exact form with the efficiency factor f is in [9] | CHECK: if not, say "following the Shor-Preskill style bound [9]" and cite the right section |
| 6.12.1 (p51) | Adversary records messages and later breaks public-key crypto (harvest now, decrypt later) | [6] | Same as the 1.1 [6] check | Check the phrase, as above |
| 6.12.1 (p51) | ML-KEM-768 targets NIST category 3 | [1] | FIPS 203 parameter table | Supported |

All nine references are cited at least once in the text I extracted. Page numbers are PDF page numbers, not the printed ones.

### Reference-list title note for [5]
The report's reference list gives [5] as "How to factor 2048 bit RSA integers with less than a million noisy qubits". The `.bib` has "How to factor a 2048-bit RSA integer with less than a million noisy qubits". The two differ. I believe the report wording matches the arXiv record, but open arxiv.org/abs/2505.15917 and copy the title exactly, then fix the `.bib` or the report.

## Pre-check findings (made before you open the pages; confirm each one on the source page)
Checked against the .bib file, plus one web search for entry 7. Nothing here replaces opening the source.

| # | Finding | Action |
|---|---|---|
| 7 | NIST IR 8547 is cited as the 2024 initial public draft (`10.6028/NIST.IR.8547.ipd`). NIST published the FINAL report on 27 Oct 2026 (DOI `10.6028/NIST.IR.8547`, page https://csrc.nist.gov/pubs/ir/8547/final). | Decide with the team: cite the final (author order and year change to 2026) or keep the draft and say "draft". Re-check every sentence citing [7], for example migration dates, against the version you choose. |
| 8 | `bb84` has no DOI or URL. It is a 1984 conference paper. | Add a stable link you have opened, for example the arXiv reprint (arXiv:2003.06557) or the 2014 reprint in Theoretical Computer Science. Confirm the details on that page. |
| 5 | `gidney25` is an arXiv preprint. | Cite it as a preprint. Confirm the title and the qubit and time figures on arxiv.org/abs/2505.15917. |
| 4, 5 | Section 1.1 uses RSA qubit estimates from both. They are different numbers (2021 and 2025). | Make sure each number in the report is attributed to the right entry. |
| 1 | `nist203` has no `author` person names, only NIST. | Fine. Check the month (Aug 2024) on the FIPS 203 page. |
| 6, 9 | Page ranges and volumes look consistent in the .bib. | Check them on the publisher pages. |
| - | The .bib has 34 entries but the report expects 36. | Ask Tarun for the two missing entries (35 and 36). |
| 14 | `liboqs` (software) is entry 14, in Yatharth's range, but you own liboqs. | Give Yatharth the version (0.16.0, python wrapper 0.16.0.2) and today's access date. |
