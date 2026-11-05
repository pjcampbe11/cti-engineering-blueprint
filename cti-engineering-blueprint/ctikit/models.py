"""
models.py - the normalized data model every other module speaks.

Why this matters
----------------
Every feed describes an indicator differently: ThreatFox calls it "ioc",
URLhaus calls it "url", ThreatStream calls it "value" with an "itype", a STIX
feed hides it inside a pattern string. If each downstream consumer (Splunk,
Anomali, STIX export, reporting) had to understand every feed format, the
integration count would grow as feeds x consumers. Normalizing once into a
single Observable shape turns that into feeds + consumers.

This is the "single pane of glass" idea expressed as a data contract.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Observable types we support. These names deliberately line up with STIX 2.1
# Cyber-observable object (SCO) naming so export is a straight mapping.
# ---------------------------------------------------------------------------
TYPE_IPV4 = "ipv4-addr"
TYPE_IPV6 = "ipv6-addr"
TYPE_DOMAIN = "domain-name"
TYPE_URL = "url"
TYPE_MD5 = "file:md5"
TYPE_SHA1 = "file:sha1"
TYPE_SHA256 = "file:sha256"
TYPE_EMAIL = "email-addr"
TYPE_UNKNOWN = "unknown"

HASH_TYPES = {TYPE_MD5, TYPE_SHA1, TYPE_SHA256}

# Regexes are intentionally strict. A loose regex in an IOC pipeline is how
# "1.1.1.1" from a version string ends up blocked on the perimeter.
_RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$"
)
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,63}$")


def utcnow() -> datetime:
    """Timezone-aware UTC now. Naive datetimes are a classic TIP bug source."""
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    """STIX timestamps require millisecond precision and a trailing Z."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{int(dt.microsecond / 1000):03d}Z"


def parse_ts(value: Optional[str]) -> Optional[datetime]:
    """Parse the handful of timestamp shapes feeds actually send us."""
    if not value:
        return None
    v = value.strip().replace("Z", "+00:00")
    for fmt in ("%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        dt = datetime.fromisoformat(v)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Defang / refang. Reports and tickets carry defanged values so nobody clicks
# them; machines need the refanged value. We store refanged, render defanged.
# ---------------------------------------------------------------------------
def refang(value: str) -> str:
    v = value.strip()
    v = v.replace("hxxps://", "https://").replace("hxxp://", "http://")
    v = v.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    v = v.replace("[:]", ":").replace("[@]", "@")
    return v


def defang(value: str) -> str:
    v = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Only defang the last dot in IPs/domains/URL hosts - enough to break
    # auto-linking while staying readable.
    head, sep, tail = v.rpartition(".")
    return f"{head}[.]{tail}" if sep else v


def detect_type(value: str) -> str:
    """Classify a raw string into one of our observable types."""
    v = refang(value)
    if _RE_SHA256.match(v):
        return TYPE_SHA256
    if _RE_SHA1.match(v):
        return TYPE_SHA1
    if _RE_MD5.match(v):
        return TYPE_MD5
    if v.lower().startswith(("http://", "https://")):
        return TYPE_URL
    try:
        ip = ipaddress.ip_address(v)
        return TYPE_IPV4 if ip.version == 4 else TYPE_IPV6
    except ValueError:
        pass
    if _RE_EMAIL.match(v):
        return TYPE_EMAIL
    if _RE_DOMAIN.match(v):
        return TYPE_DOMAIN
    return TYPE_UNKNOWN


# RFC 5737 / RFC 3849 documentation ranges. The bundled synthetic demo data
# uses ONLY these ranges so nothing in the demo is a real host. Python's
# ipaddress module flags them as "private", so demo mode has to allow them
# explicitly. Live mode leaves this False and they are filtered like any other
# non-routable address.
ALLOW_DOC_RANGES = False
_DOC_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]


def is_non_routable(value: str) -> bool:
    """True for private, loopback, link-local, multicast and reserved space.

    Pushing 10.0.0.1 to a firewall blocklist because a sandbox report listed it
    is one of the most common (and embarrassing) TIP-to-control failures.
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ALLOW_DOC_RANGES and any(ip in n for n in _DOC_NETS if n.version == ip.version):
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


# ---------------------------------------------------------------------------
# The Observable record.
# ---------------------------------------------------------------------------
@dataclass
class Observable:
    value: str                       # refanged canonical value
    type: str                        # one of the TYPE_* constants
    sources: list[str] = field(default_factory=list)   # every feed that reported it
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: list[str] = field(default_factory=list)       # free tags (actor, family, campaign)
    malware_family: Optional[str] = None
    threat_actor: Optional[str] = None
    attack_techniques: list[str] = field(default_factory=list)  # e.g. ["T1219", "T1566.004"]
    tlp: str = "TLP:AMBER"           # default conservative; TLP 2.0 labels
    source_confidence: int = 50      # 0-100 as reported/assumed per source
    enrichment: dict = field(default_factory=dict)      # VT verdicts, ASN, WHOIS, etc.
    score: Optional[int] = None      # computed by scoring.py
    priority: Optional[str] = None   # high / medium / low / drop
    expires: Optional[str] = None    # computed by scoring.py (indicator lifecycle)
    action: Optional[str] = None     # block | detect | hunt | drop  (what a control should do)
    status: str = "new"              # new -> enriched -> scored -> published | expired | falsepositive
    notes: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        """Stable dedupe key: type + lowercase value hashed.

        Hashing keeps the key a fixed length for use as a lookup/primary key
        in Splunk KV store or a SQL table.
        """
        raw = f"{self.type}|{self.value.lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def merge(self, other: "Observable") -> None:
        """Fold a duplicate sighting from another feed into this record.

        Corroboration across independent sources is one of the strongest
        signals in the scoring model, so we never throw away the duplicate's
        source - we union it in.
        """
        for s in other.sources:
            if s not in self.sources:
                self.sources.append(s)
        for t in other.tags:
            if t not in self.tags:
                self.tags.append(t)
        for t in other.attack_techniques:
            if t not in self.attack_techniques:
                self.attack_techniques.append(t)
        self.malware_family = self.malware_family or other.malware_family
        self.threat_actor = self.threat_actor or other.threat_actor
        self.source_confidence = max(self.source_confidence, other.source_confidence)
        # Widen the observation window.
        fs = [x for x in (self.first_seen, other.first_seen) if x]
        ls = [x for x in (self.last_seen, other.last_seen) if x]
        self.first_seen = min(fs) if fs else None
        self.last_seen = max(ls) if ls else None
        self.enrichment.update(other.enrichment)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["key"] = self.key
        return d


def make_observable(raw_value: str, source: str, **kwargs) -> Optional[Observable]:
    """Factory used by every collector. Returns None for junk values so
    collectors can stay simple and the filtering rule lives in one place."""
    if not raw_value:
        return None
    value = refang(str(raw_value))
    otype = kwargs.pop("type", None) or detect_type(value)
    # ThreatFox reports IPs as "ip:port" - strip the port but keep it as a tag.
    if otype == TYPE_UNKNOWN and re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d+$", value):
        value, port = value.rsplit(":", 1)
        otype = TYPE_IPV4
        kwargs.setdefault("tags", []).append(f"port:{port}")
    if otype == TYPE_UNKNOWN:
        return None
    if otype in (TYPE_IPV4, TYPE_IPV6) and is_non_routable(value):
        return None
    if otype in HASH_TYPES:
        value = value.lower()
    if otype == TYPE_DOMAIN:
        value = value.lower().rstrip(".")
    return Observable(value=value, type=otype, sources=[source], **kwargs)
