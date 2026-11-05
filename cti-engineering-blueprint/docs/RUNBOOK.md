# CTI Practitioner Runbook

Companion to the PDF playbook. This is the checklist version you keep open while working.

## 0. Intake - turn an ask into a requirement

**RFI template**
```
RFI-ID:            RFI-2026-NNN
Requester / team:
Decision it supports:      (what will they DO differently with the answer?)
Question (one sentence):
Deadline / perishability:
Classification / TLP needed:
Linked PIR:                (if none, flag to CTI manager - may become a new PIR)
Format wanted:             (BLUF email, brief, detection, hunt package, IOC list)
```
Rule: if the requester cannot name the decision, the RFI is not ready.

## 1. Direction - write the hypothesis

Checklist (the loader in `ctikit/hypothesis.py` enforces most of this):
- [ ] Linked to a PIR and named stakeholders
- [ ] Statement is specific and falsifiable (actor style + path + observable effects)
- [ ] Expected TTPs with ATT&CK / ATLAS IDs **and the data source that would show each**
- [ ] Collection plan: each source mapped to the sub-question it answers
- [ ] confirm_if / refute_if / partial_if written **before** looking at data
- [ ] At least one competing hypothesis (ACH)
- [ ] Handoffs listed per consuming team
- [ ] Review date

## 2. Research (all-source)

| Layer | Sources | What you pull |
|---|---|---|
| Frameworks | ATT&CK group/software pages + STIX data, ATLAS, D3FEND | baseline TTPs, software, mitigations |
| Government | CISA advisories + KEV, FBI/IC3 PSAs, NCSC | official TTP writeups, exploited CVEs |
| Sector | FS-ISAC (TAXII + reports), peer bank sharing | sightings at banks - highest relevance |
| Commercial | via TIP: GTI/Mandiant, Recorded Future, Intel 471, Flashpoint, CrowdStrike | finished intel, actor tracking, underground |
| Open | abuse.ch, vendor blogs, DFIR Report, Unit 42, Talos, Microsoft TI, Secureworks | IOCs, intrusion narratives |
| Pivoting | GTI/VT, passive DNS, certificate transparency (crt.sh), Shodan/Censys, URLscan | infrastructure expansion |

Source grading: Admiralty code - reliability A-F, credibility 1-6. Record it on anything that drives a key judgment.

**VT / GTI loop**
1. Seed: hashes / domains from reporting.
2. Pivot on behavior, not just hashes: imphash, rich header, signer, C2 config fields, JARM/JA4, cert subject, registrant patterns, URL path structure.
3. Draft YARA on what is expensive to change (code, config format, unique strings) - avoid strings the packer controls.
4. **Retrohunt** (approx. last 12 months) - measure FP rate, find siblings, size the campaign.
5. Promote to **Livehunt**; route notifications (IoC Stream) into the TIP as a watched feed.
6. Pull samples for reversing.

## 3. Sample analysis (enough to extract TTPs)

Lab: isolated VLAN or cloud account, no corporate creds, snapshot before detonation. FLARE-VM (Windows static/dynamic), REMnux (Linux tooling), CAPEv2 sandbox for config extraction. Scripts (PowerShell/JS/VBA/batch): deobfuscate, note LOLBins and command lines verbatim - those become Sigma.

Output per sample: hashes, family, config (C2, campaign IDs), execution chain, persistence, ATT&CK techniques with procedure-level detail, detection opportunities.

## 4. Lab validation - make it collide with our telemetry

1. Build the range: Splunk Attack Range (AWS/Azure/GCP; v5 has web app + REST API) with Windows DC/server/client, Sysmon, Zeek, Splunk ES.
2. Emulate: Atomic Red Team tests for each expected technique, or Caldera / a short custom script reproducing the procedure exactly as reversed.
3. Capture: dump the raw logs (Attack Range dump / replay) - these become regression data for CI.
4. Check: does each Sigma -> SPL search fire? Does the data source exist with the fields the rule needs? Record gaps.
5. Hand the replay data to Detection Engineering with the rule.

## 5. Production - per consumer

| Consumer | Product | Format |
|---|---|---|
| Detection Engineering | rule + test data + FP notes | Sigma MR in Git, SPL, replay logs |
| Threat Hunting | hunt package | hypothesis, SPL, time window, pivots, exit criteria |
| SOC | triage context | lookup CSV / TIP enrichment, playbook notes |
| IR | actor profile, IOCs, scoping queries | STIX, technical report |
| Red / Purple | emulation plan | ATT&CK-mapped procedures, success criteria |
| Vuln Mgmt | prioritized CVEs | KEV + actor-use context |
| Identity / Eng | control recommendation | short design note |
| Leadership | BLUF + risk | exec summary (1 page) |

## 6. Report writing rules

- BLUF in two sentences.
- Key judgments: ICD 203 likelihood words + separate confidence level (low/moderate/high) + why.
- Separate fact (what we observed), assessment (what we think it means), and gap (what we don't know).
- Every recommendation names an owner team.
- IOCs defanged in documents; machine-readable copy alongside.
- TLP 2.0 on every product.

## 7. Purple team handoff template

```
Hypothesis:       HYP-YYYY-NNN
Technique(s):     T#### / AML.T####   procedure as observed in the wild
Emulation steps:  exact commands / tool / config
Expected telemetry: source, event ID, key fields
Expected detection: rule name / search
Pass criteria:    alert fires within N minutes with correct entities
Result:           detected / logged-not-alerted / not-logged
Follow-ups:       tickets for DE / logging owners
```

## 8. Close-out

- Update hypothesis status (validated / refuted / parked) with evidence.
- Update Navigator layer and coverage metrics.
- Expire or downgrade indicators; keep for retro-hunt.
- Ask each stakeholder: did this change a decision? Record the answer - that is the program's value metric.
