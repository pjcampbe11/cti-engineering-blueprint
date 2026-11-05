# Executive Summary - HYP-2026-002
**TLP:AMBER** | Prepared 2026-11-05 | Owner: CTI - Threat Research (AI threats)

## Bottom line up front
External reporting supports the hypothesis that the tradecraft described in this hypothesis (Indirect prompt injection against an internal RAG assistant to leak customer or internal data) is relevant to us. Our current detections cover 2 of 4 expected techniques (50%), with 2 gap(s) that need engineering work before we could reliably see this attack.

## What we are asking for
- Close detection gap **AML.T0054 LLM Jailbreak** (needs: prompt/response logs, guardrail verdict logs).
- Close detection gap **AML.T0057 LLM Data Leakage** (needs: response DLP scan, guardrail logs).

## Risk view
- 2 high-priority indicators are live and loaded to the TIP and SIEM lookup.
- 0 related known-exploited vulnerabilities flagged to Vulnerability Management.
- Internal hunt (90-day lookback) is in progress; findings will update this assessment.

_Probability terms follow ICD 203 (e.g., likely = 55-80%)._
