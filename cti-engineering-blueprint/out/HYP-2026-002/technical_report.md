# HYP-2026-002: Indirect prompt injection against an internal RAG assistant to leak customer or internal data
**TLP:AMBER** | Status: draft | PIR: PIR-07 | Generated 2026-11-05 16:50 UTC

## 1. Requirement and hypothesis
**Requirement (PIR-07):** How are adversaries attacking enterprise LLM applications and agents, and which of our AI deployments are exposed to those techniques?

**Hypothesis:** An adversary who can place content in a source our internal RAG assistant indexes (shared drive, wiki, inbound email, vendor portal) can embed instructions that cause the assistant to reveal data from other retrieved documents or call tools outside the user's intent. If true, we should see retrieved chunks containing instruction-like text, model outputs containing data classes the requesting user is not entitled to, and tool calls that do not trace to the user's prompt.

**Competing hypotheses (ACH):**
- H2: Instruction-like text in the corpus is benign (templates, documentation about prompts)

## 2. Key judgments
- KJ1: No indicator-level evidence was collected; this is a behavior-driven hypothesis and the assessment rests on published technique reporting and our own exposure. Likelihood is **not yet assessed**. *Confidence: low* until internal telemetry is reviewed.
- KJ2: Our detection coverage for the expected chain is **50%** (2 covered, 0 partial, 2 gap). *Confidence: high* (based on our own detection inventory).
- KJ3: Hash-based blocking is a poor control for this tradecraft because the tools are legitimate signed software; behavioral detections and identity process controls carry the defense. *Confidence: high.*

## 3. Detection coverage (ATT&CK / ATLAS)
| Technique | Name | State | Detections | Data sources needed |
|---|---|---|---|---|
| AML.T0051.001 | LLM Prompt Injection: Indirect | covered | Instruction-Like Text In RAG Retrieved Content | RAG retrieval logs, ingestion pipeline logs |
| AML.T0054 | LLM Jailbreak | gap | - | prompt/response logs, guardrail verdict logs |
| AML.T0057 | LLM Data Leakage | gap | - | response DLP scan, guardrail logs |
| T1213 | Data from Information Repositories | covered | Instruction-Like Text In RAG Retrieved Content | SharePoint/Confluence audit logs |

## 4. Recommendations by team
- **Detection Engineering:** Sigma rules for AI gateway logs tagged HYP-2026-002
- **Red Team / Purple Team:** injection test cases replayed against staging assistant
- **AI Platform:** control recommendations (content provenance, tool-call allowlists, output DLP)
- **Leadership:** executive summary

## 5. Evaluation criteria (agreed before analysis)
**Confirm if:**
- retrieved document chunk containing instruction text followed by a response that exposes data outside the user's entitlement
**Refute if:**
- 30 days of retrieval + guardrail logs show no instruction-bearing chunks reaching the model

## 6. Related known-exploited vulnerabilities
- none

## 7. Pipeline metrics
- raw_observables_collected: 17
- unique_after_dedupe: 14
- dedupe_ratio: 0.176
- corroborated_multi_source: 2
- hypothesis_relevant: 0
- relevance_rate: 0.0
- action_block: 1
- action_detect: 3
- action_hunt: 8
- action_drop: 2
- expired: 1
- ttp_coverage_pct: 50
- sigma_rules_converted: 4
- sigma_errors: 0
- stix_bundle_valid: True
- feeds_ok: 5
- feeds_failed: 0
- run_seconds: 0.38
- yara_rules_compiled: 1
- lookup_rows: 0
- threatstream_objects_staged: 0

## 8. Artifacts
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
