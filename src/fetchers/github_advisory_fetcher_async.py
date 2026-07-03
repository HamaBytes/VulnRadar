from __future__ import annotations

import asyncio
import socket
from typing import Any

import aiohttp

from src.config.config import Config
import src.services.logger as logger

_LOG = logger.Logger("github_advisory_fetcher", level="INFO", log_file="logs/github_advisory_fetcher.log")
GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


async def _fetch_one_github_advisory(
        session: aiohttp.ClientSession,
        cve_id: str,
        headers: dict[str, str],
        timeout_obj: aiohttp.ClientTimeout,
) -> tuple[str, dict[str, Any]]:
    """Fetch GitHub Advisory data for a single CVE using the correct GraphQL query.

    Uses securityAdvisory(identifier: $cve) to look up by CVE ID.
    """
    # Correct query: securityAdvisory takes an identifier (CVE ID or GHSA ID)
    query = """
    query($cve: String!) {
      securityAdvisory(identifier: $cve) {
        severity
        summary
        references {
          url
        }
        vulnerabilities(first: 1) {
          nodes {
            package {
              name
              ecosystem
            }
            firstPatchedVersion {
              identifier
            }
            vulnerableVersionRange
          }
        }
      }
    }
    """

    json_payload = {"query": query, "variables": {"cve": cve_id}}

    try:
        async with session.post(
                GITHUB_GRAPHQL_URL,
                headers=headers,
                json=json_payload,
                timeout=timeout_obj
        ) as resp:
            if resp.status != 200:
                _LOG.warning(f"GitHub Advisory lookup failed for {cve_id}: HTTP {resp.status}")
                return cve_id, {}
            payload = await resp.json(content_type=None)
    except Exception as exc:
        _LOG.warning(f"GitHub Advisory lookup exception for {cve_id}: {exc}")
        return cve_id, {}

    # Check for GraphQL errors
    if payload.get("errors"):
        error_msg = payload["errors"][0].get("message", "Unknown GraphQL error")
        _LOG.debug(f"GitHub Advisory GraphQL error for {cve_id}: {error_msg}")
        return cve_id, {}

    advisory = payload.get("data", {}).get("securityAdvisory")
    if not advisory:
        _LOG.debug(f"No GitHub Advisory data found for {cve_id}")
        return cve_id, {}

    # Extract package info from vulnerabilities
    package_name = None
    vulnerabilities = advisory.get("vulnerabilities", {}).get("nodes", [])
    if vulnerabilities:
        package_info = vulnerabilities[0].get("package", {})
        package_name = package_info.get("name")

    references = [
        {"source": "GitHub Advisory", "url": ref["url"]}
        for ref in advisory.get("references", [])
        if ref.get("url")
    ]

    result = {
        "github_advisory_summary": advisory.get("summary"),
        "github_advisory_severity": advisory.get("severity"),
        "github_advisory_references": references,
        "github_advisory_package": package_name,
    }

    _LOG.info(f"GitHub Advisory for {cve_id}: severity={result['github_advisory_severity']}, package={package_name}")
    return cve_id, result


async def _fetch_one_with_sem(
        session: aiohttp.ClientSession,
        sem: asyncio.Semaphore,
        cve_id: str,
        headers: dict[str, str],
        timeout_obj: aiohttp.ClientTimeout,
) -> tuple[str, dict[str, Any]]:
    """Run _fetch_one_github_advisory gated by semaphore."""
    async with sem:
        return await _fetch_one_github_advisory(session, cve_id, headers, timeout_obj)


async def fetch_github_advisory_for_cves(
        cve_ids: list[str],
        *,
        concurrency: int = 5,
        timeout: int = 30,
) -> dict[str, dict[str, Any]]:
    """Fetch GitHub Advisory data for a list of CVE IDs.

    :param cve_ids: List of CVE identifiers.
    :param concurrency: Maximum concurrent requests.
    :param timeout: Per-request timeout in seconds.
    :returns: Mapping of CVE ID -> advisory data dict.
    """
    token = getattr(Config, "GITHUB_TOKEN", None)
    if not token:
        _LOG.warning("No GITHUB_TOKEN configured; skipping GitHub Advisory enrichment.")
        return {}

    normalized = [c.strip().upper() for c in cve_ids if c.strip()]
    if not normalized:
        return {}

    connector = aiohttp.TCPConnector(
        family=socket.AF_INET,
        resolver=aiohttp.ThreadedResolver()
    )
    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": getattr(Config, "NVD_USER_AGENT", "VulnRadar/1.0"),
        "Content-Type": "application/json",
    }

    async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
        sem = asyncio.Semaphore(concurrency)
        tasks = [
            _fetch_one_with_sem(session, sem, cve_id, headers, timeout_obj)
            for cve_id in normalized
        ]
        results = await asyncio.gather(*tasks)

    return {cve_id: result for cve_id, result in results if result}


def enrich_records_with_github_advisory(
        records: list[dict[str, Any]],
        advisory_lookup: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Enrich vulnerability records with GitHub Advisory data.

    :param records: List of vulnerability dicts (must contain "cveID" key).
    :param advisory_lookup: Dict returned by fetch_github_advisory_for_cves.
    :returns: The same list, mutated in-place with advisory keys added.
    """
    for record in records:
        cve_id = record.get("cveID", "").upper()
        info = advisory_lookup.get(cve_id)
        if not info:
            record.setdefault("github_advisory_summary", None)
            record.setdefault("github_advisory_references", [])
            record.setdefault("github_advisory_severity", None)
            record.setdefault("github_advisory_package", None)
            continue

        record["github_advisory_summary"] = info.get("github_advisory_summary")
        record["github_advisory_references"] = info.get("github_advisory_references", [])
        record["github_advisory_severity"] = info.get("github_advisory_severity")
        record["github_advisory_package"] = info.get("github_advisory_package")
        record.setdefault("external_references", []).extend(
            info.get("github_advisory_references", [])
        )
        record.setdefault("additional_tags", []).append("source:GitHub Advisory")

    return records
