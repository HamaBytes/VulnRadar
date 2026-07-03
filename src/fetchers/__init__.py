# src/fetchers/__init__.py
#
# FIX: Avoid name shadowing by using explicit aliases for NVD parsing dataclasses.
# The NVD parsing dataclasses (from nvd.py) and ORM models (from cve_details.py)
# share names like CpeMatch, CveWeakness, CveReference, CveDescription.
# We import the NVD parsing versions with explicit aliases to prevent shadowing.

from .nvd_fetcher_async import fetch_page
from .epss_fetcher_async import download_epss_scores, enrich_records_with_epss
from .kev_fetcher_async import get_kev_cves
from .exploit_fetcher_async import fetch_exploit_intel_for_cves, enrich_records_with_exploit_intel
from .osv_fetcher_async import fetch_osv_for_cves, enrich_records_with_osv
from .github_advisory_fetcher_async import fetch_github_advisory_for_cves, enrich_records_with_github_advisory
from .vendor_advisory_fetcher_async import fetch_vendor_advisory_for_cves, enrich_records_with_vendor_advisory

# NOTE: If you need to import NVD parsing dataclasses in other modules,
# import them directly from src.models.nvd to avoid confusion:
#   from src.models.nvd import NvdCve, NvdVulnerability, CveDescription as NvdCveDescription
#   from src.models.cve_details import CveDescription as OrmCveDescription

__all__ = [
    "fetch_page",
    "download_epss_scores",
    "enrich_records_with_epss",
    "get_kev_cves",
    "fetch_exploit_intel_for_cves",
    "enrich_records_with_exploit_intel",
    "fetch_osv_for_cves",
    "enrich_records_with_osv",
    "fetch_github_advisory_for_cves",
    "enrich_records_with_github_advisory",
    "fetch_vendor_advisory_for_cves",
    "enrich_records_with_vendor_advisory",
]
