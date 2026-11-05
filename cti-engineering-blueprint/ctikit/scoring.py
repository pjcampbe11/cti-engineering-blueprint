"""
scoring.py - transparent confidence scoring and indicator lifecycle.

Interview framing: "I don't trust a black-box score I can't explain to the SOC
lead at 2 a.m. Every point in this score traces to a factor you can read."

score (0-100) = weighted sum of five factors
  35%  source confidence      - what the feed/analyst asserted, as reported
  20%  corroboration          - how many independent sources reported it (caps at 4)
  25%  reputation             - enrichment verdicts (VT/GTI engine counts)
  10%  recency                - exponential decay by observable type half-life
  10%  relevance              - matches the hypothesis / our sector

Then rules decide the ACTION, which is separate from the score on purpose:
  block  - high score, cheap-to-change infrastructure, low collateral risk
  detect - good score but blocking is risky (shared hosting, CDN, cloud IPs)
  hunt   - context only: legit-but-abused software hashes, old IOCs, low score
  drop   - not worth anyone's time

Lifecycle (Pyramid of Pain in practice): the cheaper an indicator is for the
adversary to change, the shorter we let it live.
  hash 365d   domain 90d   url 30d   ip 30d   email 90d
Expired indicators are not deleted - they move to "expired" and stay
searchable for retro-hunting and attribution.
"""

from __future__ import annotations

import math
from datetime import timedelta

from .models import Observable, parse_ts, utcnow, iso, TYPE_IPV4, TYPE_IPV6, TYPE_URL, \
    TYPE_DOMAIN, TYPE_EMAIL, HASH_TYPES

WEIGHTS = {"source": 0.35, "corroboration": 0.20, "reputation": 0.25,
           "recency": 0.10, "relevance": 0.10}

TTL_DAYS = {TYPE_IPV4: 30, TYPE_IPV6: 30, TYPE_URL: 30, TYPE_DOMAIN: 90,
            TYPE_EMAIL: 90, "file:md5": 365, "file:sha1": 365, "file:sha256": 365}

# Families that are legitimate commercial software abused by actors. Their
# hashes are real signed vendor binaries - blocking them by hash breaks IT.
# These become behavioral detections (Sigma) and hunt context instead.
DUAL_USE = {"screenconnect", "anydesk", "atera", "splashtop", "teamviewer",
            "tacticalrmm", "fleetdeck", "ngrok", "rclone"}


def _reputation(o: Observable) -> float:
    vt = o.enrichment.get("vt") or {}
    mal, sus = vt.get("malicious", 0), vt.get("suspicious", 0)
    total = sum(vt.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    if not total:
        return 40.0  # unknown is not benign; neutral-low
    # Saturating curve: 5+ malicious engines is already strong evidence.
    return min(100.0, 100 * (1 - math.exp(-(mal + 0.5 * sus) / 3)))


def _recency(o: Observable) -> float:
    ts = parse_ts(o.last_seen or o.first_seen)
    if not ts:
        return 50.0
    age = (utcnow() - ts).days
    half_life = TTL_DAYS.get(o.type, 60) / 2
    return 100 * 0.5 ** (max(age, 0) / half_life)


def score(o: Observable, relevant: bool) -> int:
    factors = {
        "source": float(o.source_confidence),
        "corroboration": min(len(o.sources), 4) / 4 * 100,
        "reputation": _reputation(o),
        "recency": _recency(o),
        "relevance": 100.0 if relevant else 0.0,
    }
    s = sum(WEIGHTS[k] * v for k, v in factors.items())
    if "offline" in o.tags:
        s -= 15
    o.enrichment["score_factors"] = {k: round(v, 1) for k, v in factors.items()}
    return max(0, min(100, round(s)))


def decide_action(o: Observable) -> str:
    fam = (o.malware_family or "").lower()
    signed = ((o.enrichment.get("vt") or {}).get("signature_info") or {}).get("verified") == "Signed"
    if o.type in HASH_TYPES and (signed or any(d in fam for d in DUAL_USE)):
        return "hunt"           # never block a legit vendor binary by hash
    if o.score is None or o.score < 35:
        return "drop"
    if o.score < 55:
        return "hunt"
    if o.type in (TYPE_IPV4, TYPE_IPV6):
        # IPs are the most collateral-prone block (shared hosting/cloud).
        return "block" if o.score >= 75 else "detect"
    if o.type in (TYPE_DOMAIN, TYPE_URL):
        return "block" if o.score >= 65 else "detect"
    return "detect"


def apply(observables: list[Observable], relevance_fn) -> None:
    """Score, set action, set expiry and priority in place."""
    now = utcnow()
    for o in observables:
        rel = bool(relevance_fn(o))
        if rel and "hypothesis-relevant" not in o.tags:
            o.tags.append("hypothesis-relevant")
        o.score = score(o, rel)
        o.action = decide_action(o)
        o.priority = "high" if o.score >= 70 else "medium" if o.score >= 50 else "low"
        anchor = parse_ts(o.last_seen or o.first_seen) or now
        o.expires = iso(anchor + timedelta(days=TTL_DAYS.get(o.type, 60)))
        o.status = "expired" if parse_ts(o.expires) < now else "scored"
