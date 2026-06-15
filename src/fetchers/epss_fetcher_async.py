"""Async EPSS fetcher service.

Downloads the EPSS CSV data from FIRST.org, parses it, and provides
lookup capabilities for enriching CVE records with EPSS scores.

Data format (CSV, gzipped):
    cve,epss,percentile
    CVE-1999-0001,0.00988,0.77355
    CVE-1999-0002,0.09975,0.93229
"""

from __future__ import annotations

import csv
import gzip
import io
from typing import Any, Optional

import aiohttp

import src.services.logger as logger

# Create module-level logger (singleton pattern)
_log = logger.Logger("epss_fetcher", level="INFO", log_file="logs/epss_fetcher.log")

EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


async def download_epss_scores(
    session: aiohttp.ClientSession,
    *,
    timeout: int = 120,
) -> dict[str, dict[str, float]]:
    """
    Download the full EPSS scores CSV (gzipped) and return a lookup dict.

    Returns a dict mapping CVE-ID -> {"epss": float, "percentile": float}.
    The CSV file is downloaded into memory, decompressed, parsed, and
    then discarded — no file is written to disk.

    :param session: Shared aiohttp.ClientSession.
    :param timeout: Request timeout in seconds (the file is ~12 MB compressed).
    """
    headers = {"User-Agent": "VulnRadar/1.0"}

    _log.info(f"Downloading EPSS scores from {EPSS_CSV_URL} ...")
    _log.debug(f"Timeout: {timeout}s")

    try:
        async with session.get(
            EPSS_CSV_URL,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            resp.raise_for_status()
            _log.debug(f"Response status: {resp.status}")
            compressed_bytes = await resp.read()
            _log.debug(f"Downloaded {len(compressed_bytes)} bytes (compressed)")
    except aiohttp.ClientError as exc:
        _log.error(f"Failed to download EPSS CSV: {exc}", extra={"url": EPSS_CSV_URL})
        raise RuntimeError(f"Failed to download EPSS CSV: {exc}") from exc

    # Decompress gzip in-memory
    try:
        raw_csv = gzip.decompress(compressed_bytes).decode("utf-8")
        _log.debug(f"Decompressed to {len(raw_csv)} bytes (uncompressed)")
    except Exception as exc:
        _log.exception(f"Failed to decompress EPSS CSV: {exc}")
        raise RuntimeError(f"Failed to decompress EPSS CSV: {exc}") from exc

    # Parse CSV — the first line is a comment/metadata line starting with '#'
    epss_lookup: dict[str, dict[str, float]] = {}
    rows_parsed = 0
    rows_skipped = 0

    reader = csv.reader(io.StringIO(raw_csv))
    header_found = False

    for row in reader:
        # Skip comment/metadata lines (start with '#')
        if not row or row[0].startswith("#"):
            rows_skipped += 1
            continue

        # Detect header row
        if not header_found:
            # Header: cve,epss,percentile
            if row[0].strip().lower() == "cve":
                header_found = True
                _log.debug(f"Found header row: {row}")
            continue

        # Data rows
        if len(row) < 3:
            rows_skipped += 1
            continue

        cve_id = row[0].strip()
        try:
            epss_score = float(row[1].strip())
            percentile = float(row[2].strip())
        except (ValueError, IndexError):
            rows_skipped += 1
            _log.debug(f"Skipping invalid row: {row}")
            continue

        epss_lookup[cve_id] = {
            "epss": epss_score,
            "percentile": percentile,
        }
        rows_parsed += 1

    _log.info(f"Loaded EPSS scores for {len(epss_lookup)} CVEs.")
    _log.debug(f"CSV parsing stats: {rows_parsed} parsed, {rows_skipped} skipped")
    return epss_lookup


async def fetch_epss_for_cve(
    session: aiohttp.ClientSession,
    cve_id: str,
) -> Optional[dict[str, float]]:
    """
    Fetch the EPSS score for a single CVE via the FIRST.org REST API.

    Returns {"epss": float, "percentile": float} or None if not found.
    This is useful for on-demand lookups of individual CVEs.

    :param session: Shared aiohttp.ClientSession.
    :param cve_id: The CVE identifier, e.g. "CVE-2023-12345".
    """
    api_url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    headers = {"User-Agent": "VulnRadar/1.0"}

    _log.debug(f"Fetching EPSS for {cve_id}")

    try:
        async with session.get(api_url, headers=headers, timeout=30) as resp:
            resp.raise_for_status()
            _log.debug(f"EPSS API response status: {resp.status}")
            payload = await resp.json()
    except aiohttp.ClientError as exc:
        _log.warning(f"EPSS API request failed for {cve_id}: {exc}")
        return None

    data_list = payload.get("data", [])
    if not data_list:
        _log.debug(f"No EPSS data found for {cve_id}")
        return None

    entry = data_list[0]
    try:
        result = {
            "epss": float(entry.get("epss", 0)),
            "percentile": float(entry.get("percentile", 0)),
        }
        _log.info(f"EPSS for {cve_id}: {result['epss']} (percentile: {result['percentile']})")
        return result
    except (ValueError, TypeError) as exc:
        _log.warning(f"Failed to parse EPSS data for {cve_id}: {exc}")
        return None


def enrich_records_with_epss(
    records: list[dict[str, Any]],
    epss_lookup: dict[str, dict[str, float]],
) -> list[dict[str, Any]]:
    """
    Enrich a list of vulnerability records (dicts) with EPSS data from
    a pre-downloaded lookup table.

    Adds 'epss_score' and 'epss_percentile' keys to each record that
    has a matching CVE-ID in the lookup.

    :param records: List of vulnerability dicts (must contain "cveID" key).
    :param epss_lookup: Dict from download_epss_scores().
    """
    _log.info(f"Enriching {len(records)} records with EPSS data")

    matched = 0
    unmatched = 0

    for record in records:
        cve_id = record.get("cveID", "")
        epss_data = epss_lookup.get(cve_id)
        if epss_data:
            record["epss_score"] = epss_data["epss"]
            record["epss_percentile"] = epss_data["percentile"]
            matched += 1
        else:
            record["epss_score"] = None
            record["epss_percentile"] = None
            unmatched += 1

    _log.info(f"EPSS enrichment complete: {matched} matched, {unmatched} unmatched")
    return records