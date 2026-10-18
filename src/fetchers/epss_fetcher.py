"""FIRST EPSS score fetcher."""

from __future__ import annotations

from typing import Any

import aiohttp

from src.fetchers.base import AsyncFetcher
from src.utils.rate_limiter import RateLimitConfig


class EpssFetcher(AsyncFetcher[dict[str, Any]]):
    """Fetches EPSS scores from FIRST."""

    EPSS_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, session: aiohttp.ClientSession):
        super().__init__(
            session,
            rate_limit=RateLimitConfig(requests_per_second=2.0, burst_size=5),
        )

    async def fetch_all(self) -> list[dict[str, Any]]:
        """Fetch all EPSS scores (paginated)."""
        all_scores: list[dict[str, Any]] = []
        offset = 0
        limit = 1000

        while True:
            params = {"offset": offset, "limit": limit, "sort": "-epss"}
            url = f"{self.EPSS_URL}?{__import__('urllib.parse').parse.urlencode(params)}"
            data = await self._fetch(url)

            scores = data.get("data", [])
            if not scores:
                break

            all_scores.extend(scores)
            offset += len(scores)

            if len(scores) < limit:
                break

        return all_scores

    async def fetch_incremental(self, since: str | None = None) -> list[dict[str, Any]]:
        # EPSS is daily snapshot — always fetch all
        return await self.fetch_all()

    async def fetch_by_cve_ids(self, cve_ids: list[str]) -> list[dict[str, Any]]:
        """Fetch EPSS for specific CVEs."""
        if not cve_ids:
            return []

        # EPSS API supports comma-separated CVE IDs
        chunk_size = 100
        all_results: list[dict[str, Any]] = []

        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i + chunk_size]
            cve_param = ",".join(chunk)
            url = f"{self.EPSS_URL}?cve={cve_param}"
            data = await self._fetch(url)
            all_results.extend(data.get("data", []))

        return all_results

    def transform(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "cve_id": raw.get("cve"),
            "epss_score": raw.get("epss"),
            "epss_percentile": raw.get("percentile"),
            "epss_date": raw.get("date"),
        }