# Executive Summary - HYP-2026-001
**TLP:AMBER** | Prepared 2026-11-05 | Owner: CTI - Threat Research

## Bottom line up front
External reporting supports the hypothesis that Scattered Spider tradecraft (Help-desk social engineering leading to identity provider takeover and RMM persistence) is relevant to us. Our current detections cover 4 of 7 expected techniques (57%), with 3 gap(s) that need engineering work before we could reliably see this attack.

## What we are asking for
- Close detection gap **T1566.004 Phishing: Spearphishing Voice** (needs: ITSM ticket logs).
- Close detection gap **T1078.004 Valid Accounts: Cloud Accounts** (needs: IdP sign-in logs, CASB).
- Close detection gap **T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage** (needs: proxy, CASB, EDR network events).
- Identity control change: control recommendation (verified call-back, MFA re-registration cooldown).

## Risk view
- 4 high-priority indicators are live and loaded to the TIP and SIEM lookup.
- 1 related known-exploited vulnerabilities flagged to Vulnerability Management.
- Internal hunt (90-day lookback) is in progress; findings will update this assessment.

_Probability terms follow ICD 203 (e.g., likely = 55-80%)._
