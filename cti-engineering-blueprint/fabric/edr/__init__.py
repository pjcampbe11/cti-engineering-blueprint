"""
edr/ - one adapter per telemetry platform behind a common interface.

Why an interface instead of four scripts?
  * Banks rarely run one EDR. Mergers, regions, server vs workstation, cloud
    workloads and OT all end up on different products. Your pivot logic,
    fidelity scoring and write-back should not care which one fired.
  * The interface also makes testing possible: tests inject fake SDK objects
    or a mock HTTP server, and the pivot code is exercised exactly as in prod.

Every adapter implements EDRAdapter (base.py). Pick one with get_adapter().
"""

from .base import EDRAdapter, get_adapter  # noqa: F401
