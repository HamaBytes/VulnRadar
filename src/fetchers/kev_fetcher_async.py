from __future__ import annotations
import aiohttp
from typing import Any
from src.config.config import Config
import src.services.logger as logger

# Create module-level logger (singleton pattern)
_log = logger.Logger("kev_fetcher", level="INFO", log_file="logs/kev_fetcher.log")

KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def get_kev_cves(session: aiohttp.ClientSession | None = None) -> list[dict[str, Any]]:
    """
    Fetch Known Exploited Vulnerabilities (KEV) from CISA and format as a list of dicts.
    """
    headers = {
        "User-Agent": getattr(Config, "NVD_USER_AGENT", "VulnRadar/1.0")
    }

    _log.info(f"Fetching KEV data from CISA: {KEV_JSON_URL}")

    if session is None:
        _log.debug("Creating temporary aiohttp.ClientSession")
        async with aiohttp.ClientSession(headers=headers) as local_session:
            return await _fetch_and_parse(local_session)
    else:
        _log.debug("Using provided aiohttp.ClientSession")
        return await _fetch_and_parse(session, headers)


def _clean_text(text: Any) -> Any:
    """Replace common Unicode symbols with standard ASCII equivalents."""
    if not isinstance(text, str):
        return text
    replacements = {
        "\u2018": "'",
        "\u2019": "'",
        "\u201c": '"',
        "\u201d": '"',
        "\u2013": "-",
        "\u2014": "--",
        "\u2026": "...",
        "\u00a0": " ",
        "\ufffd": "?"
    }
    for search, replace in replacements.items():
        text = text.replace(search, replace)
    return text


async def _fetch_and_parse(session: aiohttp.ClientSession, headers: dict[str, str] | None = None) -> list[
    dict[str, Any]]:
    _log.debug("Starting KEV fetch and parse")

    try:
        async with session.get(KEV_JSON_URL, headers=headers, timeout=30) as resp:
            resp.raise_for_status()
            _log.debug(f"KEV API response status: {resp.status}")
            data = await resp.json()
            _log.debug(f"Received JSON payload ({len(data)} bytes)")
    except aiohttp.ClientError as exc:
        _log.error(f"Failed to fetch KEV data: {exc}", extra={"url": KEV_JSON_URL})
        raise RuntimeError(f"Failed to fetch KEV data: {exc}") from exc
    except Exception as exc:
        _log.exception(f"Failed to parse KEV JSON response: {exc}")
        raise RuntimeError(f"Failed to parse KEV JSON: {exc}") from exc

    raw_vulnerabilities = data.get("vulnerabilities", [])
    _log.debug(f"Found {len(raw_vulnerabilities)} raw vulnerability records")

    vulnerabilities = []
    cleaned_count = 0

    for vuln in raw_vulnerabilities:
        cwes = vuln.get("cwes", [])
        if isinstance(cwes, list):
            cleaned_cwes = [_clean_text(cwe) for cwe in cwes]
            cleaned_count += len(cleaned_cwes)
        else:
            cleaned_cwes = cwes

        vulnerabilities.append({
            "cveID": _clean_text(vuln.get("cveID", "")),
            "vendorProject": _clean_text(vuln.get("vendorProject", "")),
            "product": _clean_text(vuln.get("product", "")),
            "vulnerabilityName": _clean_text(vuln.get("vulnerabilityName", "")),
            "dateAdded": _clean_text(vuln.get("dateAdded", "")),
            "shortDescription": _clean_text(vuln.get("shortDescription", "")),
            "requiredAction": _clean_text(vuln.get("requiredAction", "")),
            "dueDate": _clean_text(vuln.get("dueDate", "")),
            "knownRansomwareCampaignUse": _clean_text(vuln.get("knownRansomwareCampaignUse", "Unknown")),
            "notes": _clean_text(vuln.get("notes", "")),
            "cwes": cleaned_cwes
        })

    _log.info(f"Successfully parsed {len(vulnerabilities)} KEV vulnerabilities ({cleaned_count} CWES cleaned)")
    return vulnerabilities