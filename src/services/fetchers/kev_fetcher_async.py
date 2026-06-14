from __future__ import annotations
import aiohttp
from typing import Any
from src.config.config import Config

KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def get_kev_cves(session: aiohttp.ClientSession | None = None) -> list[dict[str, Any]]:
    """
    Fetch Known Exploited Vulnerabilities (KEV) from CISA and format as a list of dicts.
    """
    headers = {
        "User-Agent": getattr(Config, "NVD_USER_AGENT", "VulnRadar/1.0")
    }

    if session is None:
        async with aiohttp.ClientSession(headers=headers) as local_session:
            return await _fetch_and_parse(local_session)
    else:
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

async def _fetch_and_parse(session: aiohttp.ClientSession, headers: dict[str, str] | None = None) -> list[dict[str, Any]]:
    try:
        async with session.get(KEV_JSON_URL, headers=headers, timeout=30) as resp:
            resp.raise_for_status()
            data = await resp.json()
    except aiohttp.ClientError as exc:
        raise RuntimeError(f"Failed to fetch KEV data: {exc}") from exc

    raw_vulnerabilities = data.get("vulnerabilities", [])
    vulnerabilities = []
    
    for vuln in raw_vulnerabilities:
        cwes = vuln.get("cwes", [])
        if isinstance(cwes, list):
            cleaned_cwes = [_clean_text(cwe) for cwe in cwes]
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

    return vulnerabilities
