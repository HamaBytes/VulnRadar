from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

import aiohttp

from src.config.config import Config
import src.services.logger as logger

_LOG = logger.Logger("osv_fetcher", level="INFO", log_file="logs/osv_fetcher.log")
OSV_API_URL = "https://api.osv.dev/v1/query"


async def fetch_osv_for_cve(session: aiohttp.ClientSession, cve_id: str) -> dict[str, Any]:
    """Fetch OSV vulnerability metadata for a single CVE."""
    payload = {"id": cve_id}
    headers = {
        "Content-Type": "application/json",
        "User-Agent": getattr(Config, "NVD_USER_AGENT", "VulnRadar/1.0"),
    }

    try:
        async with session.post(OSV_API_URL, json=payload, headers=headers, timeout=30) as resp:
            if resp.status != 200:
                _LOG.warning(f"OSV lookup failed for {cve_id}: HTTP {resp.status}")
                return {}
            data = await resp.json(content_type=None)
    except Exception as exc:
        _LOG.warning(f"OSV lookup exception for {cve_id}: {exc}")
        return {}

    if not data or data.get("error"):
        return {}

    references = []
    for ref in data.get("references", []):
        url = ref.get("url")
        if not url:
            continue
        references.append({
            "source": "OSV",
            "url": url,
            "id": ref.get("id"),
            "title": ref.get("type") or "OSV reference",
        })

    severities = []
    for severity in data.get("severity", []):
        score = severity.get("score")
        if score:
            severities.append(f"{severity.get('type')}:{score}")

    return {
        "osv_summary": data.get("summary") or data.get("details"),
        "osv_references": references,
        "osv_severities": severities,
        "osv_id": data.get("id"),
    }


async def fetch_osv_for_cves(
    cve_ids: list[str],
    *,
    concurrency: int = 10,
    timeout: int = 30,
) -> dict[str, dict[str, Any]]:
    if not cve_ids:
        return {}

    normalised = [c.strip().upper() for c in cve_ids if c.strip()]
    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(family=socket.AF_INET, resolver=aiohttp.ThreadedResolver())
    async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
        async def query(cve_id: str) -> tuple[str, dict[str, Any]]:
            async with sem:
                result = await fetch_osv_for_cve(session, cve_id)
                return cve_id, result

        tasks = [query(cve_id) for cve_id in normalised]
        results = await asyncio.gather(*tasks)

    return {cve_id: result for cve_id, result in results if result}


def enrich_records_with_osv(
    records: list[dict[str, Any]],
    osv_lookup: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    for record in records:
        cve_id = record.get("cveID", "").upper()
        info = osv_lookup.get(cve_id)
        if not info:
            record.setdefault("osv_summary", None)
            record.setdefault("osv_references", [])
            record.setdefault("osv_severities", [])
            continue

        record["osv_summary"] = info.get("osv_summary")
        record["osv_severities"] = info.get("osv_severities", [])
        record.setdefault("external_references", []).extend(info.get("osv_references", []))
        record.setdefault("additional_tags", []).append("source:OSV")
    return records
