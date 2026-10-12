"""
HTTPS transport to the AegisX server.

Handles TLS verification, per-agent authentication headers, and classification
of transient vs. permanent failures so the caller can decide whether to retry.
Retries with exponential backoff are applied to transient failures only.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

from .config import Config


class TransportError(Exception):
    """Transient failure — worth retrying (connection error, 5xx, 429)."""


class PermanentError(Exception):
    """Non-retryable failure (4xx other than 429, e.g. bad request/auth)."""


@dataclass
class AgentCredentials:
    agent_id: str
    agent_token: str


class Transport:
    def __init__(self, config: Config, logger=None):
        self.config = config
        self.log = logger
        self.base = config.server.url.rstrip("/")
        self.session = requests.Session()
        # TLS verification: True, or a CA bundle path for self-signed servers.
        self._verify: Any = config.server.ca_cert or config.server.verify_tls

    # ── Low-level request with retry/backoff ──────────────────────────────────

    def _url(self, path: str) -> str:
        return f"{self.base}/api/v1/endpoints{path}"

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        retries: int = 4,
    ) -> Dict[str, Any]:
        attempt = 0
        backoff = 1.0
        last_exc: Optional[Exception] = None
        while attempt <= retries:
            attempt += 1
            try:
                resp = self.session.request(
                    method, self._url(path),
                    json=json_body, headers=headers,
                    timeout=self.config.server.timeout_seconds,
                    verify=self._verify,
                )
            except requests.exceptions.RequestException as exc:
                last_exc = TransportError(f"connection error: {exc}")
            else:
                if resp.status_code < 400:
                    try:
                        return resp.json()
                    except ValueError:
                        return {}
                if resp.status_code in (429,) or resp.status_code >= 500:
                    last_exc = TransportError(f"server {resp.status_code}: {resp.text[:200]}")
                else:
                    raise PermanentError(f"server {resp.status_code}: {resp.text[:200]}")

            if attempt <= retries:
                if self.log:
                    self.log.warning("transport retry %d/%d in %.1fs (%s)",
                                     attempt, retries, backoff, last_exc)
                time.sleep(backoff)
                backoff = min(backoff * 2, self.config.agent.max_backoff_seconds)
        raise last_exc or TransportError("request failed")

    # ── High-level API calls ──────────────────────────────────────────────────

    def enroll(self, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("POST", "/enroll", json_body=body, retries=2)

    def heartbeat(self, creds: AgentCredentials, body: Dict[str, Any]) -> Dict[str, Any]:
        return self.request("POST", "/heartbeat", json_body=body,
                            headers=self._auth_headers(creds), retries=2)

    def send_events(self, creds: AgentCredentials, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        return self.request("POST", "/events", json_body={"events": events},
                            headers=self._auth_headers(creds), retries=3)

    def _auth_headers(self, creds: AgentCredentials) -> Dict[str, str]:
        return {
            "X-Agent-Id": creds.agent_id,
            "Authorization": f"Bearer {creds.agent_token}",
        }
