from __future__ import annotations

import asyncio
import socket
from typing import Any

import aiohttp

from src.config.config import Config
import src.services.logger as logger

_LOG = logger.Logger("vendor_advisory_fetcher", level="INFO", log_file="logs/vendor_advisory_fetcher.log")

# Placeholder vendor advisory endpoints; these are examples and may need
# real API endpoints or vendor-specific credentials.
VENDOR_ADVISORY_ENDPOINTS = {
    "microsoft": "https://api.msrc.microsoft.com/cvrf/v2",
    "oracle": "https://www.oracle.com/security-alerts/",
}


async def fetch_vendor_advisory_for_cve(
    session: aiohttp.ClientSession,
    cve_id: str,
) -> dict[str, Any]:
    if not cve_id:
        return {}

    # For general vendor advisory fetch, we just return a stubbed result
    # because vendor APIs are heterogeneous. The function is extensible.
    _LOG.info(f"Vendor advisory lookup stub for {cve_id}")
    return {
        "vendor_advisory_available": False,
        "vendor_advisory_sources": [],
        "vendor_advisory_details": None,
    }


async def fetch_vendor_advisory_for_cves(
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
                result = await fetch_vendor_advisory_for_cve(session, cve_id)
                return cve_id, result

        results = await asyncio.gather(*[query(cve_id) for cve_id in normalised])

    return {cve_id: result for cve_id, result in results if result}


def enrich_records_with_vendor_advisory(
    records: list[dict[str, Any]],
    advisory_lookup: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    for record in records:
        cve_id = record.get("cveID", "").upper()
        info = advisory_lookup.get(cve_id)
        if not info:
            record.setdefault("vendor_advisory_available", False)
            record.setdefault("vendor_advisory_sources", [])
            record.setdefault("vendor_advisory_details", None)
            continue

        record["vendor_advisory_available"] = info.get("vendor_advisory_available", False)
        record["vendor_advisory_sources"] = info.get("vendor_advisory_sources", [])
        record["vendor_advisory_details"] = info.get("vendor_advisory_details")

    return records
