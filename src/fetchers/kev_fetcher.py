"""CISA KEV catalog fetcher."""

from __future__ import annotations

from typing import Any

import aiohttp

from src.fetchers.base import AsyncFetcher
from src.utils.rate_limiter import RateLimitConfig


class KevFetcher(AsyncFetcher[dict[str, Any]]):
    """Fetches CISA Known Exploited Vulnerabilities catalog."""

    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, session: aiohttp.ClientSession):
        super().__init__(
            session,
            rate_limit=RateLimitConfig(requests_per_second=1.0, burst_size=2),
        )

    async def fetch_all(self) -> list[dict[str, Any]]:
        data = await self._fetch(self.CISA_KEV_URL)
        return data.get("vulnerabilities", [])

    async def fetch_incremental(self, since: str | None = None) -> list[dict[str, Any]]:
        # KEV has no incremental API — fetch all and filter
        all_kevs = await self.fetch_all()
        if since is None:
            return all_kevs

        from datetime import datetime
        since_date = datetime.strptime(since, "%Y-%m-%d").date()
        return [
            k for k in all_kevs
            if datetime.strptime(k.get("dateAdded", "1970-01-01"), "%Y-%m-%d").date() >= since_date
        ]

    def transform(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "cve_id": raw.get("cveID"),
            "vulnerability_name": raw.get("vulnerabilityName"),
            "vendor_project": raw.get("vendorProject"),
            "product": raw.get("product"),
            "date_added": raw.get("dateAdded"),
            "due_date": raw.get("dueDate"),
            "known_ransomware_campaign_use": raw.get("knownRansomwareCampaignUse"),
            "notes": raw.get("notes"),
            "kev": True,
        }