"""
http.py - one small HTTP helper shared by every connector.

Design choices worth being able to explain in an interview:
  * stdlib urllib only, so the toolkit runs on a locked-down jump box where
    you cannot pip install. Corporate proxies are honored automatically via
    HTTPS_PROXY / REQUESTS_CA_BUNDLE style environment variables.
  * Retries with exponential backoff on 429 / 5xx - every intel API rate
    limits, and a pipeline that dies on the first 429 is not a pipeline.
  * Secrets come from environment variables (or a vault injecting them into
    the environment). They are never logged; the helper redacts them.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("ctikit.http")

DEFAULT_TIMEOUT = 30
RETRY_STATUS = {429, 500, 502, 503, 504}


def _ssl_context() -> ssl.SSLContext:
    """Respect a custom CA bundle (common behind TLS-inspecting proxies)."""
    ca = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
    return ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()


def request(method: str, url: str, *, headers: dict | None = None,
            params: dict | None = None, body: dict | list | bytes | None = None,
            retries: int = 4, timeout: int = DEFAULT_TIMEOUT) -> dict | list | str:
    """Make an HTTP request and return parsed JSON (or text if not JSON).

    Raises urllib.error.HTTPError after retries are exhausted so the caller
    can decide whether a failure is fatal (TIP push) or skippable (one feed).
    """
    if params:
        url = f"{url}{'&' if '?' in url else '?'}{urllib.parse.urlencode(params, doseq=True)}"
    hdrs = {"User-Agent": "ctikit/1.0", "Accept": "application/json"}
    hdrs.update(headers or {})
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        else:
            data = body

    delay = 2.0
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=_ssl_context()) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    return raw
        except urllib.error.HTTPError as e:
            if e.code in RETRY_STATUS and attempt < retries:
                # Honor Retry-After when the server sends it.
                wait = float(e.headers.get("Retry-After") or delay)
                log.warning("HTTP %s from %s - retry %d in %.0fs", e.code,
                            _redact(url), attempt, wait)
                time.sleep(wait)
                delay *= 2
                continue
            raise
        except urllib.error.URLError as e:
            if attempt < retries:
                log.warning("network error %s - retry %d", e.reason, attempt)
                time.sleep(delay)
                delay *= 2
                continue
            raise
    raise RuntimeError("unreachable")


def _redact(url: str) -> str:
    """Strip query-string secrets (some APIs take keys as params) from logs."""
    parts = urllib.parse.urlsplit(url)
    q = urllib.parse.parse_qsl(parts.query)
    q = [(k, "***" if any(s in k.lower() for s in ("key", "token", "secret")) else v) for k, v in q]
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(q)))
