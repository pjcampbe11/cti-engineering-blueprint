"""
ctikit - CTI Lifecycle Toolkit
==============================

A small, readable, stdlib-first toolkit that walks one intelligence question
(a hypothesis) through the full cyber threat intelligence lifecycle:

    Direction  -> hypothesis + PIRs                       (hypothesis.py)
    Collection -> OSINT / commercial / internal feeds     (collectors.py, taxii.py, anomali.py)
    Processing -> normalize, dedupe, enrich, score, age   (models.py, enrich.py, scoring.py)
    Analysis   -> ATT&CK / ATLAS mapping, coverage gaps   (attack.py)
    Production -> STIX 2.1, Sigma->SPL, YARA hunts, CSV   (stix_export.py, sigma_tools.py, yara_tools.py, splunk.py)
    Dissemination -> reports, TIP/SIEM pushes             (report.py, anomali.py, splunk.py, taxii.py)
    Feedback   -> pipeline metrics                         (metrics.py)

Everything runs offline against synthetic sample data so the full pipeline can
be demonstrated without API keys. When keys are present (environment variables
only - never hard-coded) the same code paths talk to the real services.
"""

__version__ = "1.0.0"
