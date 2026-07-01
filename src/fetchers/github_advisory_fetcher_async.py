from __future__ import annotations

import asyncio
import socket
from typing import Any

import aiohttp

from src.config.config import Config
import src.services.logger as logger

_LOG = logger.Logger("github_advisory_fetcher", level="INFO", log_file="logs/github_advisory_fetcher.log")
GITHUB_SECURITY_URL = "https://api.github.com/graphql"


async def fetch_github_advisory_for_cves(
    cve_ids: list[str],
    *,
    concurrency: int = 5,
    timeout: int = 30,
) -> dict[str, dict[str, Any]]:
    token = getattr(Config, "GITHUB_TOKEN", None)
    if not token:
        _LOG.warning("No GITHUB_TOKEN configured; skipping GitHub Advisory enrichment.")
        return {}

    normalized = [c.strip().upper() for c in cve_ids if c.strip()]
    connector = aiohttp.TCPConnector(family=socket.AF_INET, resolver=aiohttp.ThreadedResolver())
    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": getattr(Config, "NVD_USER_AGENT", "VulnRadar/1.0"),
        "Content-Type": "application/json",
    }

    # GraphQL query returns an issue or advisory for a CVE.
    query = """
    query($cve: String!) {
      securityVulnerabilities(first: 1, advisoryTopic: $cve) {
        nodes {
          severity
          summary
          references {
            url
          }
          package {
            name
          }
        }
      }
    }
    """

    async def fetch_one(session: aiohttp.ClientSession, cve_id: str) -> tuple[str, dict[str, Any]]:
        json_payload = {"query": query, "variables": {"cve": cve_id}}
        async with session.post(GITHUB_SECURITY_URL, headers=headers, json=json_payload, timeout=timeout_obj) as resp:
            if resp.status != 200:
                _LOG.warning(f"GitHub Advisory lookup failed for {cve_id}: HTTP {resp.status}")
                return cve_id, {}
            payload = await resp.json(content_type=None)

        data = payload.get("data", {}) or {}
        nodes = data.get("securityVulnerabilities", {}).get("nodes", [])
        if not nodes:
            return cve_id, {}

        node = nodes[0]
        references = []
        for ref in node.get("references", []):
            url = ref.get("url")
            if url:
                references.append({"source": "GitHub Advisory", "url": url})

        return cve_id, {
            "github_advisory_summary": node.get("summary"),
            "github_advisory_severity": node.get("severity"),
            "github_advisory_references": references,
            "github_advisory_package": node.get("package", {}).get("name"),
        }

    async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
        sem = asyncio.Semaphore(concurrency)
        tasks = [
            _fetch_one_with_sem(session, sem, cve_id)
            for cve_id in normalized
        ]
        results = await asyncio.gather(*tasks)

    return {cve_id: result for cve_id, result in results if result}


async def _fetch_one_with_sem(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    cve_id: str,
) -> tuple[str, dict[str, Any]]:
    async with sem:
        return await fetch_one(session, cve_id)


def enrich_records_with_github_advisory(
    records: list[dict[str, Any]],
    advisory_lookup: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
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
        record.setdefault("external_references", []).extend(info.get("github_advisory_references", []))
        record.setdefault("additional_tags", []).append("source:GitHub Advisory")
    return records
