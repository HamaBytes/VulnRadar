"""NVD API 2.0 fetcher with pagination and date-range support."""

from __future__ import annotations

from typing import Any, AsyncIterator
from urllib.parse import urlencode

import aiohttp

from src.fetchers.base import AsyncFetcher
from src.schemas.nvd import NvdApiResponse, NvdVulnerability
from src.utils.rate_limiter import RateLimitConfig


class NvdFetcher(AsyncFetcher[NvdVulnerability]):
    """Fetches CVEs from NVD API 2.0."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, session: aiohttp.ClientSession, api_key: str | None = None):
        super().__init__(
            session,
            rate_limit=RateLimitConfig(requests_per_second=0.6, burst_size=1),
        )
        self.api_key = api_key

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": "VulnRadar/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    async def _fetch_page(
            self,
            start_index: int = 0,
            results_per_page: int = 200,
            keyword: str | None = None,
            cve_id: str | None = None,
            last_mod_start: str | None = None,
            last_mod_end: str | None = None,
    ) -> NvdApiResponse:
        params: dict[str, str | int] = {
            "resultsPerPage": min(results_per_page, 200),
            "startIndex": start_index,
        }
        if keyword:
            params["keywordSearch"] = keyword
        if cve_id:
            params["cveId"] = cve_id
        if last_mod_start:
            params["lastModStartDate"] = last_mod_start
        if last_mod_end:
            params["lastModEndDate"] = last_mod_end

        url = f"{self.BASE_URL}?{urlencode(params)}"
        data = await self._fetch(url, headers=self._headers())
        return NvdApiResponse.model_validate(data)

    async def iter_pages(
            self,
            max_results: int = 10_000,
            keyword: str | None = None,
            last_mod_start: str | None = None,
            last_mod_end: str | None = None,
    ) -> AsyncIterator[NvdApiResponse]:
        """Iterate all pages with automatic pagination."""
        start_index = 0
        total_results: int | None = None

        while start_index < max_results:
            page = await self._fetch_page(
                start_index=start_index,
                keyword=keyword,
                last_mod_start=last_mod_start,
                last_mod_end=last_mod_end,
            )

            yield page

            items = page.vulnerabilities or []
            if not items:
                break

            start_index += len(items)

            if total_results is None:
                total_results = getattr(page, "totalResults", 0)
            if total_results and start_index >= total_results:
                break
            if start_index >= max_results:
                break

    async def fetch_all(self) -> list[NvdVulnerability]:
        """Fetch all CVEs (use carefully — millions of records)."""
        all_items: list[NvdVulnerability] = []
        async for page in self.iter_pages(max_results=100_000):
            all_items.extend(page.vulnerabilities or [])
        return all_items

    async def fetch_incremental(self, since: str | None = None) -> list[NvdVulnerability]:
        """Fetch CVEs modified since watermark date."""
        if since is None:
            return await self.fetch_all()

        from datetime import datetime, timedelta
        end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000")
        return [
            v
            async for page in self.iter_pages(
                last_mod_start=since,
                last_mod_end=end,
            )
            for v in (page.vulnerabilities or [])
        ]

    async def fetch_by_cve_ids(self, cve_ids: list[str]) -> list[NvdVulnerability]:
        """Fetch specific CVEs by ID (batch if needed)."""
        results: list[NvdVulnerability] = []
        for cve_id in cve_ids:
            try:
                page = await self._fetch_page(cve_id=cve_id)
                results.extend(page.vulnerabilities or [])
            except Exception:
                continue  # Log and continue
        return results

    def transform(self, raw: NvdVulnerability) -> dict[str, Any]:
        """Transform NVD vulnerability to unified enrichment record."""
        cve = raw.cve
        score, severity, version = cve.best_score()

        return {
            "cve_id": cve.cve_id,
            "source_identifier": cve.source_identifier,
            "title": cve.descriptions[0].value if cve.descriptions else None,
            "description": cve.descriptions[0].value if cve.descriptions else None,
            "published_date": cve.published,
            "last_modified_date": cve.last_modified,
            "vuln_status": cve.vuln_status,
            "severity": severity,
            "cvss_v2_score": score if version and version.startswith("2") else None,
            "cvss_v3_score": score if version and version.startswith("3") else None,
            "cvss_v40_score": score if version and version.startswith("4") else None,
            "nvd_cve_obj": cve,
        }