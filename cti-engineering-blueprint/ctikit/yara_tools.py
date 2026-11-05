"""
yara_tools.py - turn research output into YARA for hunting.

Two jobs:
  1. Generate a hash-set rule from the pipeline's file observables, for
     Retrohunt / file-share sweeps ("have we ever had any of these?").
  2. Compile-check every .yar in the repo with YARA-X (the Rust rewrite VT/GTI
     moved Livehunt and Retrohunt onto) if the `yara-x` package is installed.

Livehunt vs Retrohunt, the way to say it in the interview:
  * Livehunt - rules run against every new file (and, in GTI, URLs, domains,
    IPs) as it arrives; you get a notification stream. That is the
    "tell me when the actor builds a new one" sensor.
  * Retrohunt - the same rule over roughly the last 12 months of the corpus;
    that is how you size a campaign and pull historic samples for reversing.
  * Typical loop: reverse one sample -> write a rule on code/config that is
    expensive for the actor to change -> Retrohunt to measure FP rate and
    find siblings -> promote to Livehunt -> feed new hits back into analysis.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from .models import Observable, HASH_TYPES

log = logging.getLogger("ctikit.yara")


def hash_set_rule(observables: list[Observable], hypothesis_id: str) -> str:
    """Emit a YARA rule matching any of the sha256 file observables."""
    hashes = sorted({o.value for o in observables if o.type == "file:sha256"})
    if not hashes:
        return ""
    name = re.sub(r"[^A-Za-z0-9_]", "_", f"{hypothesis_id}_hashset")
    conds = "\n        or ".join(f'hash.sha256(0, filesize) == "{h}"' for h in hashes)
    return (
        'import "hash"\n\n'
        f"rule {name}\n{{\n    meta:\n"
        f'        hypothesis = "{hypothesis_id}"\n'
        '        description = "Known sample hashes from CTI pipeline - retro sweep only"\n'
        f"    condition:\n        {conds}\n}}\n")


def compile_check(yar_dir: Path, extra_sources: list[str] | None = None) -> dict:
    try:
        import yara_x  # type: ignore
    except ImportError:
        return {"checked": 0, "errors": ["yara-x not installed (pip install yara-x)"], "skipped": True}
    errors, n = [], 0
    sources = [(p.name, p.read_text()) for p in sorted(yar_dir.glob("*.yar"))]
    sources += [(f"generated_{i}.yar", s) for i, s in enumerate(extra_sources or []) if s]
    for name, src in sources:
        try:
            yara_x.compile(src)
            n += 1
        except Exception as e:  # noqa: BLE001
            errors.append(f"{name}: {e}")
    return {"checked": n, "errors": errors, "skipped": False}
