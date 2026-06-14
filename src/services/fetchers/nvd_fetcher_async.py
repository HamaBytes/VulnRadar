"""NVD fetch service."""

from __future__ import annotations

from typing import AsyncIterator, Optional
from urllib.parse import urlencode

import aiohttp

from src.models.nvd import NvdApiResponse
from src.config.config import Config


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

    try:
        async with session.get(request_url, headers=headers, timeout=30) as resp:
            resp.raise_for_status()
            payload = await resp.json()
    except aiohttp.ClientError as exc:
        # TODO: replace with your logging framework
        # logger.exception("Error fetching NVD page", extra={"url": request_url})
        raise RuntimeError(f"Failed to fetch NVD data: {exc}") from exc

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

    while start_index < max_results:
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
                # If your model uses a different field name, adjust here
                total_results = getattr(page, "total_results", 0)

        # No results on this page → stop
        if not getattr(page, "vulnerabilities", None):
            break

        start_index += results_per_page

        # Stop if we reached NVD total
        if total_results is not None and start_index >= total_results:
            break

        # Stop if we reached our own max_results cap
        if start_index >= max_results:
            break


async def fetch_vulnerabilities_flat(
    session: aiohttp.ClientSession,
    *,
    keyword: Optional[str] = None,
    max_results: int = 1000,
    results_per_page: int = 200,
):
    """
    Convenience helper that flattens all pages into a single list of
    vulnerability items (not NvdApiResponse objects).

    Returns the combined list of `vulnerabilities` entries.
    """
    all_items: list[dict] = []

    async for page in iter_vulnerabilities(
        session,
        keyword=keyword,
        max_results=max_results,
        results_per_page=results_per_page,
    ):
        items = getattr(page, "vulnerabilities", []) or []
        all_items.extend(items)

        if len(all_items) >= max_results:
            break

    return all_items