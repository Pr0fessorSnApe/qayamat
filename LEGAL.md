# QAYAMAT — Legal Usage Agreement

**Version:** 2.0 · **Last updated:** May 2026

## READ BEFORE USE

By downloading, installing, or using QAYAMAT, you agree to these terms in full.

---

## Authorized Use Only

QAYAMAT is for **authorized security testing** only. You must have **explicit, documented, written authorization** before scanning any target.

Permitted uses:

- Systems you own
- Penetration tests under a signed SOW
- **In-scope** bug bounty programs
- Internal red team exercises with documented approval

---

## Prohibited Uses

You may **not**:

1. Test systems without written permission  
2. Run denial-of-service or resource exhaustion attacks  
3. Exfiltrate data beyond minimal proof-of-concept  
4. Violate applicable law  
5. Bypass controls on systems you do not own  
6. Disrupt production services  
7. Test **out-of-scope** assets (use the exclusions parser and program rules)  

---

## Platform API Submission

Submitting reports via HackerOne or Bugcrowd APIs uses **your own** API credentials. You must only submit to programs where you are authorized and in scope. QAYAMAT does not store platform passwords; tokens live in your local `.env` file.

---

## Pause / Resume & Data Handling

Checkpoints saved under `data/checkpoints/` may contain URLs, hostnames, and scan configuration. **Protect this data** as you would any engagement notes. Delete checkpoints when the assessment ends if your policy requires it.

---

## Legal Compliance

You are solely responsible for compliance with laws in your jurisdiction, including but not limited to:

- Pakistan: Prevention of Electronic Crimes Act (PECA) 2016  
- USA: Computer Fraud and Abuse Act (CFAA)  
- UK: Computer Misuse Act 1990  
- EU: Directive on Attacks Against Information Systems  

---

## Responsible Disclosure

Report vulnerabilities promptly and in good faith. Follow the target’s disclosure policy. Do not publish details without consent or before a reasonable fix window.

---

## Accuracy Notice

QAYAMAT uses automated scanners, heuristics, and optional AI triage to **reduce** false positives. **No tool is 100% accurate.** Manually verify every finding before submission or client delivery.

---

## Disclaimer of Liability

The author (Pr0fessor_SnApe) and contributors provide QAYAMAT **"AS IS"** without warranty. The author accepts **no liability** for unauthorized use, damages, or legal consequences. **All compliance and ethical conduct is your responsibility.**

---

*Using QAYAMAT means you accept these terms.*
