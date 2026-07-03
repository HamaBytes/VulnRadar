"""Async KEV (Known Exploited Vulnerabilities) fetcher service.

Downloads the CISA KEV catalog JSON and returns a flat list of vulnerability dicts.

Data format (JSON):
    {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2024.01.01",
        "dateReleased": "2024-01-01T00:00:00.0000Z",
        "count": 1000,
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j2",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
                "dateAdded": "2021-12-10",
                "shortDescription": "...",
                "requiredAction": "Apply updates per vendor instructions.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known"
            }
        ]
    }
"""

from __future__ import annotations

import json
from typing import Any

import aiohttp

import src.services.logger as logger

# Create module-level logger (singleton pattern)
_log = logger.Logger("kev_fetcher", level="INFO", log_file="logs/kev_fetcher.log")

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def get_kev_cves(session: aiohttp.ClientSession) -> list[dict[str, Any]]:
    """
    Download the full CISA KEV catalog and return the vulnerabilities list.

    Returns a flat list of dicts with keys like cveID, dateAdded,
    vulnerabilityName, vendorProject, product, etc.

    :param session: Shared aiohttp.ClientSession.
    """
    headers = {"User-Agent": "VulnRadar/1.0"}

    _log.info(f"Downloading KEV catalog from {CISA_KEV_URL} ...")

    try:
        async with session.get(CISA_KEV_URL, headers=headers, timeout=60) as resp:
            resp.raise_for_status()
            _log.debug(f"Response status: {resp.status}")
            payload = await resp.json()
    except aiohttp.ClientError as exc:
        _log.error(f"Failed to download KEV catalog: {exc}", extra={"url": CISA_KEV_URL})
        raise RuntimeError(f"Failed to download KEV catalog: {exc}") from exc
    except json.JSONDecodeError as exc:
        _log.error(f"Failed to parse KEV catalog JSON: {exc}")
        raise RuntimeError(f"Failed to parse KEV catalog JSON: {exc}") from exc

    vulnerabilities = payload.get("vulnerabilities", [])
    _log.info(f"Loaded {len(vulnerabilities)} KEV entries from CISA catalog.")

    return vulnerabilities
