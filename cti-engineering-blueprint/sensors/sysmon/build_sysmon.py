#!/usr/bin/env python3
"""
build_sysmon.py - assemble a Sysmon config from modules and report ATT&CK coverage.

Why modular: one monolithic XML becomes unreviewable. Modules (one per event
type or use case) can be owned, reviewed in merge requests and tested
independently - the same detection-as-code discipline as Sigma. This follows
the convention popularized by community projects (sysmon-modular,
SwiftOnSecurity's config): ATT&CK IDs go in the rule `name` attribute so they
appear in the RuleName field of every event and can drive SIEM mapping.

Deployment notes:
  * Sysmon became a native optional feature in Windows 11 in 2026 (same engine,
    same XML schema, event channel Microsoft-Windows-Sysmon/Operational); the
    standalone Sysinternals build remains supported for servers and older OS.
  * Set schemaversion to what `sysmon -s` reports on your target build.
  * Apply: sysmon -accepteula -i sysmonconfig.xml   update: sysmon -c sysmonconfig.xml
  * Ship events with the Splunk UF (see sensors/splunk/inputs.conf) or Windows
    Event Forwarding to a collector.

Usage: python build_sysmon.py [--schema 4.90] [--hash-algorithms SHA256,IMPHASH]
"""
import argparse, re, sys
from pathlib import Path
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent

def build(schema: str, hashes: str) -> tuple[str, dict]:
    parts = []
    for p in sorted((HERE / "modules").glob("*.xml")):
        body = p.read_text()
        body = re.sub(r"<!--.*?-->", "", body, flags=re.S).strip()
        parts.append(f"    <!-- module: {p.name} -->\n    " + body.replace("\n", "\n    "))
    xml = (f'<Sysmon schemaversion="{schema}">\n'
           f'  <HashAlgorithms>{hashes}</HashAlgorithms>\n'
           '  <CheckRevocation/>\n'
           '  <EventFiltering>\n' + "\n".join(parts) + '\n  </EventFiltering>\n</Sysmon>\n')
    root = ET.fromstring(xml)                     # well-formedness check
    cov = {}
    for el in root.iter():
        m = re.search(r"technique_id=([^,]+),technique_name=([^,]+)", el.attrib.get("name", ""))
        if m:
            cov.setdefault(m.group(1), m.group(2))
    return xml, cov

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema", default="4.90")
    ap.add_argument("--hash-algorithms", default="SHA256,IMPHASH")
    ap.add_argument("--out", default=str(HERE / "sysmonconfig.xml"))
    a = ap.parse_args()
    xml, cov = build(a.schema, a.hash_algorithms)
    Path(a.out).write_text(xml)
    print(f"wrote {a.out}; ATT&CK techniques tagged: {len(cov)}")
    for k, v in sorted(cov.items()):
        print(f"  {k:12} {v}")
