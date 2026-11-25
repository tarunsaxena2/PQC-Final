# QKD note, part A: hardware needs and cost (Vaibhav)

Access date for every source below: 25 November 2026. Only facts the sources state are used. No price figure is given, because none was found in a primary source; do not add one without a source.

## Points
1. **Special-purpose equipment.** NSA's guidance on QKD says QKD needs special-purpose equipment because its security comes from physical-layer communication, and it does not recommend QKD for National Security Systems unless its listed limitations are overcome. Source: NSA, "Quantum Key Distribution (QKD) and Quantum Cryptography (QC)" (https://www.nsa.gov/Cybersecurity/Quantum-Key-Distribution-QKD-and-Quantum-Cryptography-QC/, as quoted in secondary summaries; open the NSA page itself and copy the exact title and date before citing).
2. **Infrastructure cost.** The same NSA document lists higher infrastructure cost and insider-threat risk as limitations, and says quantum-resistant cryptography is a more cost-effective and more easily maintained option. Secondary summary: The Quantum Insider, 30 Oct 2020 (https://thequantuminsider.com/2020/10/30/nsa-says-quantum-key-distribution-are-currently-impractical-for-protecting-national-security-systems).
3. **PQC needs no special hardware.** UK NCSC white paper "Quantum security technologies": quantum-safe algorithms run on today's classical computers and, unlike QKD, need no dedicated or specialist hardware (https://www.ncsc.gov.uk/whitepaper/quantum-security-technologies).
4. **Integration burden.** NCSC, "Quantum networking technologies": combining specialised QKD hardware with existing network infrastructure adds complexity (https://www.ncsc.gov.uk/whitepaper/quantum-networking-technologies).
5. **Authentication is still needed.** NCSC states QKD does not provide authentication, so it needs quantum-resistant authentication alongside it (same page as point 4).
6. **Government position.** NCSC will not support QKD for government or military use and names PQC as the best mitigation (same NCSC page).

## Counter-view to mention for balance
The QKD industry disputes the NSA points: a vendor article (HEQA Security, https://heqa-sec.com/?p=356) argues that QKD equipment costs are falling. It is a vendor opinion, not independent evidence; cite it as an opinion only.

## To do before this goes in the report
- [ ] Open the NSA page directly; one search result says the page was rewritten in June 2026 (postquantum.com). Check that points 1 and 2 still match the current wording.
- [ ] Replace the secondary sources in points 1 and 2 with the NSA page once opened.
- [ ] Merge with parts B (Yatharth), C (Uday), D (Tarun) into the 1-page note (Tarun).
