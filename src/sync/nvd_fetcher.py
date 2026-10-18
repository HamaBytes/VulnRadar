"""NVD fetch service — updated to use Pydantic schemas."""

from __future__ import annotations

import asyncio
from typing import AsyncIterator, Optional, List
from urllib.parse import urlencode

import aiohttp

from src.config.config import Config
from src.schemas.nvd import NvdApiResponse, NvdVulnerability
import src.services.logger as logger

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
        last_modified_start: Optional[str] = None,
        last_modified_end: Optional[str] = None,
) -> NvdApiResponse:
    """Fetch a single page of NVD CVEs. Returns validated Pydantic model."""
    params: dict[str, str | int] = {
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
    }
    if keyword:
        params["keywordSearch"] = keyword
    if cve_id:
        params["cveId"] = cve_id
    if last_modified_start:
        params["lastModStartDate"] = last_modified_start
    if last_modified_end:
        params["lastModEndDate"] = last_modified_end

    request_url = f"{NVD_API_URL}?{urlencode(params)}"
    headers = _build_headers()

    _logger.debug(f"Fetching NVD page: startIndex={start_index}")

    max_retries = 5
    retry_delay = 5.0

    for attempt in range(max_retries + 1):
        try:
            async with session.get(request_url, headers=headers, timeout=60) as resp:
                if resp.status in (503, 502, 504, 429) and attempt < max_retries:
                    _logger.warning(f"NVD API {resp.status}, retrying in {retry_delay}s...")
                    await asyncio.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2, 60)
                    continue

                resp.raise_for_status()
                payload = await resp.json()
                # Use Pydantic validation instead of old dataclass
                return NvdApiResponse.model_validate(payload)

        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            if attempt < max_retries:
                _logger.warning(f"NVD fetch error: {exc}, retrying...")
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60)
                continue
            raise RuntimeError(f"Failed to fetch NVD after {max_retries+1} attempts: {exc}") from exc

    raise RuntimeError("Failed to fetch NVD page")


async def iter_vulnerabilities(
        session: aiohttp.ClientSession,
        *,
        keyword: Optional[str] = None,
        max_results: int = 10_000,
        results_per_page: int = 200,
        last_modified_start: Optional[str] = None,
        last_modified_end: Optional[str] = None,
) -> AsyncIterator[NvdApiResponse]:
    """Iterate over NVD pages."""
    if results_per_page > 200:
        results_per_page = 200

    start_index = 0
    total_results: Optional[int] = None
    fetched_count = 0

    while start_index < max_results:
        page = await fetch_page(
            session,
            keyword=keyword,
            start_index=start_index,
            results_per_page=results_per_page,
            last_modified_start=last_modified_start,
            last_modified_end=last_modified_end,
        )

        yield page

        items = page.vulnerabilities or []
        fetched_count += len(items)

        if not items:
            break

        start_index += results_per_page

        if total_results is None:
            total_results = getattr(page, "total_results", None) or getattr(page, "totalResults", 0)

        if total_results and start_index >= total_results:
            break

        if start_index >= max_results:
            break


async def fetch_vulnerabilities_flat(
        session: aiohttp.ClientSession,
        *,
        keyword: Optional[str] = None,
        max_results: int = 1000,
        results_per_page: int = 200,
        last_modified_start: Optional[str] = None,
        last_modified_end: Optional[str] = None,
) -> List[NvdVulnerability]:
    """Flatten all pages into a single list."""
    all_items: List[NvdVulnerability] = []

    async for page in iter_vulnerabilities(
            session,
            keyword=keyword,
            max_results=max_results,
            results_per_page=results_per_page,
            last_modified_start=last_modified_start,
            last_modified_end=last_modified_end,
    ):
        items = page.vulnerabilities or []
        all_items.extend(items)

        if len(all_items) >= max_results:
            all_items = all_items[:max_results]
            break

    return all_items
