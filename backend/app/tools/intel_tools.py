"""
Threat Intelligence tools — enrich IPs, domains, and hashes
against external TI sources (VirusTotal, AbuseIPDB, OTX).

All API keys loaded from environment variables — never hard-coded.
Results are merged from multiple sources and returned as a unified dict.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import httpx
import structlog

from app.core.config import settings

log = structlog.get_logger()


class IntelTools:
    """Threat intelligence enrichment — multi-source, async."""

    # ─── IP Lookup ───────────────────────────────────────────────────────────

    async def lookup_ip(self, ip: str) -> Dict:
        """Enrich an IP address from all available TI sources."""
        results: Dict[str, Any] = {"ip": ip, "sources": {}}

        tasks = []
        if settings.VIRUSTOTAL_API_KEY:
            tasks.append(("virustotal", self._vt_lookup_ip(ip)))
        if settings.ABUSEIPDB_API_KEY:
            tasks.append(("abuseipdb", self._abuseipdb_lookup(ip)))
        if settings.OTX_API_KEY:
            tasks.append(("otx", self._otx_lookup_ip(ip)))

        if not tasks:
            return {**results, "warning": "No TI API keys configured. Set VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, or OTX_API_KEY."}

        gathered = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
        for (name, _), res in zip(tasks, gathered):
            results["sources"][name] = res if not isinstance(res, Exception) else {"error": str(res)}

        results["malicious"] = self._is_malicious(results["sources"])
        return results

    async def _vt_lookup_ip(self, ip: str) -> Dict:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "country": data.get("country"),
                "asn": data.get("asn"),
                "as_owner": data.get("as_owner"),
            }

    async def _abuseipdb_lookup(self, ip: str) -> Dict:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            )
            resp.raise_for_status()
            d = resp.json().get("data", {})
            return {
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "country_code": d.get("countryCode"),
                "isp": d.get("isp"),
                "is_tor": d.get("isTor", False),
            }

    async def _otx_lookup_ip(self, ip: str) -> Dict:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
            )
            resp.raise_for_status()
            d = resp.json()
            return {
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "reputation": d.get("reputation", 0),
                "country_name": d.get("country_name"),
                "asn": d.get("asn"),
            }

    # ─── Domain Lookup ────────────────────────────────────────────────────────

    async def lookup_domain(self, domain: str) -> Dict:
        """Enrich a domain from all available TI sources."""
        results: Dict[str, Any] = {"domain": domain, "sources": {}}

        tasks = []
        if settings.VIRUSTOTAL_API_KEY:
            tasks.append(("virustotal", self._vt_lookup_domain(domain)))
        if settings.OTX_API_KEY:
            tasks.append(("otx", self._otx_lookup_domain(domain)))

        if not tasks:
            return {**results, "warning": "No TI API keys configured."}

        gathered = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
        for (name, _), res in zip(tasks, gathered):
            results["sources"][name] = res if not isinstance(res, Exception) else {"error": str(res)}

        results["malicious"] = self._is_malicious(results["sources"])
        return results

    async def _vt_lookup_domain(self, domain: str) -> Dict:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "registrar": data.get("registrar"),
                "creation_date": data.get("creation_date"),
            }

    async def _otx_lookup_domain(self, domain: str) -> Dict:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                headers={"X-OTX-API-KEY": settings.OTX_API_KEY},
            )
            resp.raise_for_status()
            d = resp.json()
            return {
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "validation": [v.get("name") for v in d.get("validation", [])],
            }

    # ─── Hash Lookup ──────────────────────────────────────────────────────────

    async def lookup_hash(self, hash_value: str) -> Dict:
        """Enrich a file hash (MD5/SHA256) from VT."""
        results: Dict[str, Any] = {"hash": hash_value, "sources": {}}

        if settings.VIRUSTOTAL_API_KEY:
            try:
                res = await self._vt_lookup_hash(hash_value)
                results["sources"]["virustotal"] = res
            except Exception as exc:
                results["sources"]["virustotal"] = {"error": str(exc)}
        else:
            return {**results, "warning": "VIRUSTOTAL_API_KEY not set."}

        results["malicious"] = self._is_malicious(results["sources"])
        return results

    async def _vt_lookup_hash(self, hash_value: str) -> Dict:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{hash_value}",
                headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "type_description": data.get("type_description"),
                "meaningful_name": data.get("meaningful_name"),
                "size": data.get("size"),
            }

    # ─── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _is_malicious(sources: Dict) -> bool:
        """Aggregate malicious verdict across sources."""
        for src_data in sources.values():
            if isinstance(src_data, dict):
                if src_data.get("malicious", 0) > 2:
                    return True
                if src_data.get("abuse_confidence_score", 0) > 50:
                    return True
                if src_data.get("pulse_count", 0) > 0:
                    return True
        return False
