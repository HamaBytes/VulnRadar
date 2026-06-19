"""NVD fetch service."""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Optional
from urllib.parse import urlencode

import aiohttp

from src.config.config import Config
from src.models.nvd import NvdApiResponse
import src.services.logger as logger

# Create module-level logger (singleton pattern)
_logger = logger.Logger("nvd_fetch", level="DEBUG", log_file="logs/nvd_fetch.log")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _build_headers() -> dict[str, str]:
    headers: dict[str, str] = {
        "User-Agent": getattr(Config, "NVD_USER_AGENT", "VulnRadar/1.0"),
    }
    api_key: Optional[str] = getattr(Config, "NVD_API_KEY", None)
    if api_key:
        headers["apiKey"] = api_key
    return headers


async def fetch_page(
    session: aiohttp.ClientSession,
    *,
    keyword: Optional[str] = None,
    cve_id: Optional[str] = None,
    start_index: int = 0,
    results_per_page: int = 200,
) -> NvdApiResponse:
    """
    Fetch a single page of NVD CVEs.

    :param session: Shared aiohttp ClientSession.
    :param keyword: Optional keywordSearch parameter.
    :param cve_id: Optional cveId parameter to fetch a specific CVE.
    :param start_index: Pagination start index.
    :param results_per_page: Number of CVEs per page (NVD max is 200).
    """
    params: dict[str, str | int] = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
    }
    if keyword:
        params["keywordSearch"] = keyword
    if cve_id:
        params["cveId"] = cve_id

    request_url = f"{NVD_API_URL}?{urlencode(params)}"
    headers = _build_headers()

    _logger.debug(f"Fetching NVD page: startIndex={start_index}, resultsPerPage={results_per_page}")
    if keyword:
        _logger.debug(f"Keyword search: {keyword}")
    if cve_id:
        _logger.debug(f"Specific CVE: {cve_id}")

    max_retries = 3
    retry_delay = 2.0
    payload = None

    for attempt in range(max_retries + 1):
        try:
            async with session.get(request_url, headers=headers, timeout=30) as resp:
                if resp.status in (503, 502, 504, 429) and attempt < max_retries:
                    _logger.warning(
                        f"NVD API returned {resp.status} (attempt {attempt+1}/{max_retries+1}). Retrying in {retry_delay}s...",
                        extra={"url": request_url}
                    )
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                
                resp.raise_for_status()
                payload = await resp.json()
                _logger.info(f"Successfully fetched page at index {start_index}, got {len(payload.get('vulnerabilities', []))} CVEs")
                break
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            if attempt < max_retries:
                _logger.warning(
                    f"NVD fetch connection error: {exc} (attempt {attempt+1}/{max_retries+1}). Retrying in {retry_delay}s...",
                    extra={"url": request_url}
                )
                await asyncio.sleep(retry_delay)
                retry_delay *= 2
                continue
            _logger.error(f"Failed to fetch NVD page after {max_retries+1} attempts: {exc}", extra={"url": request_url, "startIndex": start_index})
            raise RuntimeError(f"Failed to fetch NVD data after {max_retries+1} attempts: {exc}") from exc
        except Exception as exc:
            _logger.exception(f"Unexpected error parsing NVD response: {exc}")
            raise RuntimeError(f"Failed to parse NVD data: {exc}") from exc

    if payload is None:
        raise RuntimeError(f"Failed to fetch NVD page: payload is None after retries")

    return NvdApiResponse.from_dict(payload)


async def iter_vulnerabilities(
    session: aiohttp.ClientSession,
    *,
    keyword: Optional[str] = None,
    max_results: int = 10_000,
    results_per_page: int = 200,
) -> AsyncIterator[NvdApiResponse]:
    """
    Iterate over NVD pages for a given query.

    Yields NvdApiResponse objects page by page until either:
      - all NVD results are exhausted, or
      - max_results is reached.

    :param session: Shared aiohttp ClientSession.
    :param keyword: Optional keywordSearch parameter.
    :param max_results: Hard cap to avoid pulling the entire NVD.
    :param results_per_page: Page size (<= 200 recommended).
    """
    if results_per_page > 200:
        results_per_page = 200

    start_index = 0
    total_results: Optional[int] = None
    fetched_count = 0

    _logger.info(f"Starting NVD vulnerability iteration: keyword={keyword}, max_results={max_results}")

    while start_index < max_results:
        _logger.debug(f"Fetching page {start_index // results_per_page + 1}: startIndex={start_index}")

        page = await fetch_page(
            session,
            keyword=keyword,
            start_index=start_index,
            results_per_page=results_per_page,
        )

        yield page

        # Derive total_results from first page if available
        if total_results is None:
            total_results = getattr(page, "totalResults", None)
            if total_results is None:
                total_results = getattr(page, "total_results", 0)
            _logger.info(f"NVD total results: {total_results}")

        # Count vulnerabilities
        items = getattr(page, "vulnerabilities", []) or []
        fetched_count += len(items)
        _logger.info(f"Page {start_index // results_per_page + 1}: {len(items)} CVEs (total fetched: {fetched_count})")

        # No results on this page → stop
        if not items:
            _logger.warning("No more results returned, stopping iteration")
            break

        start_index += results_per_page

        # Stop if we reached NVD total
        if total_results is not None and start_index >= total_results:
            _logger.info(f"Reached NVD total ({total_results}), stopping")
            break

        # Stop if we reached our own max_results cap
        if start_index >= max_results:
            _logger.info(f"Reached max_results cap ({max_results}), stopping")
            break

    _logger.info(f"Iteration complete: fetched {fetched_count} total CVEs")


async def fetch_vulnerabilities_flat(
    session: aiohttp.ClientSession,
    *,
    keyword: Optional[str] = None,
    max_results: int = 1000,
    results_per_page: int = 200,
) -> list[dict]:
    """
    Convenience helper that flattens all pages into a single list of
    vulnerability items (not NvdApiResponse objects).

    Returns the combined list of `vulnerabilities` entries.
    """
    all_items: list[dict] = []

    _logger.info(f"Fetching all vulnerabilities flat: keyword={keyword}, max_results={max_results}")

    async for page in iter_vulnerabilities(
        session,
        keyword=keyword,
        max_results=max_results,
        results_per_page=results_per_page,
    ):
        items = getattr(page, "vulnerabilities", []) or []
        all_items.extend(items)

        _logger.debug(f"Extended list: now have {len(all_items)} items")

        if len(all_items) >= max_results:
            _logger.info(f"Reached max_results limit, truncating to {max_results}")
            all_items = all_items[:max_results]
            break

    _logger.info(f"Fetch complete: returned {len(all_items)} vulnerabilities")
    return all_items