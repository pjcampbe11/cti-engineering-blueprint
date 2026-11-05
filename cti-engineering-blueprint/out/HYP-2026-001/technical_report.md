# HYP-2026-001: Help-desk social engineering leading to identity provider takeover and RMM persistence
**TLP:AMBER** | Status: active | PIR: PIR-03 | Generated 2026-11-05 16:50 UTC

## 1. Requirement and hypothesis
**Requirement (PIR-03):** Which financially motivated actors are targeting U.S. financial institutions through identity and help-desk channels, and would our current identity, endpoint and SIEM detections catch them?

**Hypothesis:** A financially motivated intrusion set using Scattered Spider-style tradecraft is likely to call our IT service desk impersonating employees, obtain an MFA reset, register an attacker-controlled MFA device, and install a commercial remote monitoring and management (RMM) tool for persistence. If that is true, we should see (a) MFA device registrations shortly after help-desk resets, (b) MFA push bursts against the same identities, and (c) RMM binaries that are not on our approved software list executing on endpoints.

**Competing hypotheses (ACH):**
- H2: The observed MFA reset volume is a benign process change (new onboarding workflow)
- H3: RMM tools are installed by shadow IT / vendors, not an adversary

## 2. Key judgments
- KJ1: It is **likely** that the intrusion set described is actively using infrastructure relevant to this hypothesis: 10 relevant live indicators from 6 distinct sources, 2 corroborated by more than one source. *Confidence: moderate* (independent sources, no internal sighting yet).
- KJ2: Our detection coverage for the expected chain is **57%** (4 covered, 0 partial, 3 gap). *Confidence: high* (based on our own detection inventory).
- KJ3: Hash-based blocking is a poor control for this tradecraft because the tools are legitimate signed software; behavioral detections and identity process controls carry the defense. *Confidence: high.*

## 3. Detection coverage (ATT&CK / ATLAS)
| Technique | Name | State | Detections | Data sources needed |
|---|---|---|---|---|
| T1656 | Impersonation | covered | MFA Reset Followed By New Factor Enrollment Within 60 Minutes | ITSM ticket logs, call recordings metadata |
| T1566.004 | Phishing: Spearphishing Voice | gap | - | ITSM ticket logs |
| T1621 | Multi-Factor Authentication Request Generation | covered | Okta Verify Push Denied By User, MFA Push Fatigue - Multiple Okta Verify Denials For One User | Okta System Log, Entra ID sign-in logs |
| T1098.005 | Account Manipulation: Device Registration | covered | Okta MFA Factors Reset (Help Desk / Admin), Okta MFA Factor Activated, MFA Reset Followed By New Factor Enrollment Within 60 Minutes | Okta System Log, Entra ID audit logs |
| T1078.004 | Valid Accounts: Cloud Accounts | gap | - | IdP sign-in logs, CASB |
| T1219 | Remote Access Software | covered | Unapproved Remote Monitoring and Management Tool Execution | EDR process events, Sysmon EID 1, DNS, proxy |
| T1567.002 | Exfiltration Over Web Service: Exfiltration to Cloud Storage | gap | - | proxy, CASB, EDR network events |

## 4. Recommendations by team
- **Detection Engineering:** Sigma rules in detections/sigma tagged HYP-2026-001
- **Threat Hunting:** hunt package (SPL + hypothesis) for 90-day lookback
- **SOC:** enriched IOC lookup + triage notes for the RMM rule
- **Red Team / Purple Team:** adversary emulation plan for reset->register->RMM chain
- **Identity Engineering:** control recommendation (verified call-back, MFA re-registration cooldown)
- **Leadership:** executive summary, BLUF, risk rating

## 5. Evaluation criteria (agreed before analysis)
**Confirm if:**
- any MFA device registration within 60 minutes of a help-desk MFA reset for the same user, from a new ASN
- unapproved RMM binary execution on a host owned by a user with a recent help-desk reset
**Refute if:**
- 90 days of IdP + ITSM data reviewed with zero correlated reset->register->RMM sequences

## 6. Related known-exploited vulnerabilities
- CVE-2024-1709 - ConnectWise ScreenConnect: ConnectWise ScreenConnect Authentication Bypass (ransomware use: Known)

## 7. Pipeline metrics
- raw_observables_collected: 17
- unique_after_dedupe: 14
- dedupe_ratio: 0.176
- corroborated_multi_source: 2
- hypothesis_relevant: 10
- relevance_rate: 0.714
- action_block: 3
- action_detect: 4
- action_hunt: 5
- action_drop: 2
- expired: 1
- ttp_coverage_pct: 57
- sigma_rules_converted: 4
- sigma_errors: 0
- stix_bundle_valid: True
- feeds_ok: 5
- feeds_failed: 0
- run_seconds: 0.3
- yara_rules_compiled: 2
- lookup_rows: 10
- threatstream_objects_staged: 7

## 8. Artifacts
- `HYP-2026-001_hashset.yar`
- `attack_navigator_layer.json`
- `coverage.json`
- `cti_threat_intel_lookup.csv`
- `metrics.json`
- `observables.json`
- `savedsearches.conf`
- `sigma_converted.spl`
- `splunk_hec_events.jsonl`
- `stix_bundle.json`
- `threatstream_patch_payload.json`
- `executive_summary.md`
- `technical_report.md`

## Appendix A - Indicators (defanged)
| Indicator | Type | Score | Action | Sources | Expires |
|---|---|---|---|---|---|
| okta-sso-helpdesk[.]example | domain-name | 90 | block | 3 | 2027-01-28 |
| 203.0.113[.]45 | ipv4-addr | 80 | block | 2 | 2026-12-03 |
| servicedesk-mfa-reset[.]example | domain-name | 73 | block | 1 | 2027-01-31 |
| 203.0.113[.]77 | ipv4-addr | 71 | detect | 1 | 2026-12-02 |
| aa2f4fa70b74a4b8851e3247959596141665da2a6bb16b4d52db4fc81653a707 | file:sha256 | 68 | hunt | 1 | 2027-10-27 |
| 8a83d94d44b74afe4f81305048bf6e5b3f5f5ba22a2947652fdcf5b83290fc8c | file:sha256 | 65 | hunt | 1 | 2027-11-01 |
| hxxps://files-share-cdn.test/ScreenConnect.ClientSetup[.]exe | url | 58 | detect | 1 | 2026-12-01 |
| hxxps://okta-sso-helpdesk[.]example/login/reset | url | 57 | detect | 1 | 2026-11-29 |
| files-share-cdn[.]test | domain-name | 55 | detect | 1 | 2027-01-30 |
| 198.51.100[.]23 | ipv4-addr | 51 | hunt | 1 | 2026-12-01 |
