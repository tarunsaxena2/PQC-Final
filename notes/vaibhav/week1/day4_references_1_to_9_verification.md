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
| 2 | bos2018 | CRYSTALS-Kyber}: A {CCA}-secure module-lattice-based {KEM | Bos, Joppe and Ducas, Léo and Kiltz, Eike and Lepoint, Tancrède and Lyubashevsky, Vadim and Schanck, John M. and Schwabe, Peter and Seiler, Gregor and Stehlé, Damien | 2018 | 10.1109/EuroSP.2018.00032 |  |  |  |  |
| 3 | shor97 | Polynomial-time algorithms for prime factorization and discrete logarithms on a quantum computer | Shor, Peter W. | 1997 | 10.1137/S0097539795293172 |  |  |  |  |
| 4 | gidney21 | How to factor 2048 bit {RSA} integers in 8 hours using 20 million noisy qubits | Gidney, Craig and Ekerå, Martin | 2021 | 10.22331/q-2021-04-15-433 |  |  |  |  |
| 5 | gidney25 | How to factor a 2048-bit {RSA} integer with less than a million noisy qubits | Gidney, Craig | 2025 | https://arxiv.org/abs/2505.15917 |  |  |  |  |
| 6 | mosca18 | Cybersecurity in an era with quantum computers: Will we be ready? | Mosca, Michele | 2018 | 10.1109/MSP.2018.3761723 |  |  |  |  |
| 7 | nistir8547 | Transition to post-quantum cryptography standards (initial public draft) | Moody, Dustin and Perlner, Ray and Regenscheid, Andrew and Robinson, Angela and Cooper, David | 2024 | 10.6028/NIST.IR.8547.ipd |  |  |  |  |
| 8 | bb84 | Quantum cryptography: Public key distribution and coin tossing | Bennett, Charles H. and Brassard, Gilles | 1984 |  |  |  |  |  |
| 9 | scarani09 | The security of practical quantum key distribution | Scarani, Valerio and Bechmann-Pasquinucci, Helle and Cerf, Nicolas J. and Dušek, Miloslav and Lütkenhaus, Norbert and Peev, Momtchil | 2009 | 10.1103/RevModPhys.81.1301 |  |  |  |  |

## Claim-to-source check (V13)
For each sentence citing [1] to [9] write: sentence location, what it claims, what the source says, verdict.
Check these first: RSA qubit estimates in 1.1, QKD attacks [12] and [13] (note: 12 and 13 sit in Yatharth's range, so tell him which sentences cite them).

| Report section | Sentence (short) | Ref | Source says | Verdict |
|---|---|---|---|---|
