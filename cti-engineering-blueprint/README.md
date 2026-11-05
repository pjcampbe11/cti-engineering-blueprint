# cti-engineering-blueprint

**Building a CTI program from the engineering side.** This repo shows how to stitch a threat intelligence platform, a SIEM, several EDRs, cloud runtime sensors and custom host telemetry into one working system, and how to connect that system to the SOC, detection engineering, hunt, IR, red and purple teams. It includes working code for every integration.

The full write-up is in [`docs/CTI_Engineering_Blueprint.pdf`](docs/CTI_Engineering_Blueprint.pdf) (clickable contents) and [`docs/CTI_Engineering_Blueprint.md`](docs/CTI_Engineering_Blueprint.md).

> All hosts, users, indicators and inventories in this repo are **synthetic**: RFC 5737 IP ranges, `.example` / `.test` domains, invented names. Nothing here is real intelligence.

## What's inside

| Part | Path | What it does |
|---|---|---|
| **Lifecycle toolkit** | `cti.py`, `ctikit/`, `hypotheses/`, `detections/`, `data/` | One intelligence question from hypothesis to collection (abuse.ch, CISA KEV, ThreatStream, TAXII 2.1), dedupe, VT/GTI enrichment, explainable scoring and expiry, STIX 2.1, Sigma to SPL, YARA hunts, reports, metrics |
| **Integration layer** | `fabric_cli.py`, `fabric/` | On-demand EDR pivots (CrowdStrike FalconPy, SentinelOne Mgmt API + SDL PowerQuery, Carbon Black Cloud SDK, Microsoft Defender via Graph), Wiz Defend runtime detections, TIP lookups, asset/identity/change context, fidelity scoring, Splunk HEC write-back, field budgeting, coverage reconciliation, connector health |
| **Sensor content** | `sensors/` | Modular Sysmon config and builder (ATT&CK-tagged), Sysmon for Linux, auditd rules, osquery pack, Splunk inputs, TIP match search for hosts without EDR |
| **Splunk app** | `splunk_app/TA-cti-edrpivot` | `| edrpivot` custom search command backed by the same pivot code |
| **Tests** | `tests/` | 29 tests: unit, end to end, fake SDK objects, mock vendor APIs |
| **CI** | `.github/workflows/ci.yml` | Validates content, builds Sysmon, runs tests and demos on every PR |

## Quick start (offline, no keys)

```bash
pip install -r requirements.txt

# Same alert name, three different truths: escalate / suppress / review
python fabric_cli.py pivot --mock

# Which hosts have no EDR or no telemetry at all, and what to do about it
python fabric_cli.py coverage --inventory mocks/coverage --now 2026-11-05T15:00:00Z

# Which EDR fields are worth paying to index vs fetching on demand
python fabric_cli.py field-budget --sample mocks/field_budget_sample.jsonl \
    --detections mocks/field_budget_detections --events-per-day 2000000000

# Hypothesis-driven intel lifecycle
python cti.py run hypotheses/HYP-2026-001-helpdesk-idp-takeover.yaml --offline

# Build the Sysmon config from modules
python sensors/sysmon/build_sysmon.py

python -m unittest discover -s tests -v
```

Outputs land in `out/`.

## Live mode

Copy the variables in `config/env.example` into your environment from a vault. Never commit them. Each adapter documents the exact scopes it needs. All writes default to dry run; response actions (host containment) refuse to run without `allow_response=True` **and** an approval or ticket reference.

## Core ideas

1. **Normalize once.** One data model; adapters absorb vendor quirks.
2. **Index what you detect on, pivot for the rest.** The SIEM gets thin alerts; the EDR API answers the deep questions on demand.
3. **Fidelity from combination.** Behavior plus rarity plus intel plus context. Context discounts soft signals, never hard ones.
4. **Coverage is a metric.** Reconcile CMDB, EDR, sensors and SIEM weekly. Blind critical assets are a work list.
5. **Read-only by default, response gated, everything owned and observable.**

## Verify before production

Vendor schemas move: SentinelOne SDL fields, Falcon CQL event fields, Carbon Black event fields, and the Wiz GraphQL schema (`queries/wiz_detections.graphql` is a template). Also note that SentinelOne legacy Deep Visibility APIs stop working on Feb 15, 2027. Fidelity weights are starting points; calibrate them against analyst dispositions.

## License

Add your preferred license (MIT recommended for sample code like this) before publishing.
