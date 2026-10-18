"""Async bulk import service for scrapers and fetchers.

Replaces the old synchronous DatabaseStorage with async bulk operations.
All database writes from fetchers happen through this layer.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.cve import Cve
from src.models.cve_details import CveDescription, CveTag
from src.models.cvss import (
    CvssDataV2, CvssDataV31, CvssDataV40,
    CvssMetricV2, CvssMetricV31, CvssMetricV40,
)
from src.models.weakness import CveWeakness, CveWeaknessDescription
from src.models.configuration import CveConfiguration, CveNode, CpeMatch
from src.models.reference import CveReference
from src.models.epss import Epss
from src.models.exploit import ExploitReference
from src.models.osv import OsvRecord, OsvReference
from src.models.github_advisory import GithubAdvisory, GithubAdvisoryReference
from src.models.vendor_advisory import VendorAdvisory
from src.models.sync_state import SyncState

logger = logging.getLogger(__name__)


class CveBulkImporter:
    """Async bulk importer for CVE data from fetchers.

    Usage:
        importer = CveBulkImporter(session)
        await importer.upsert_cves_batch(records)
        await session.commit()
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_datetime(date_str: Optional[str]) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00").replace("+00:00", ""))
        except ValueError:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
        return None

    async def _get_cve_id_map(self, cve_ids: list[str]) -> dict[str, int]:
        """Bulk lookup: {cve_id: db_id} for existing CVEs."""
        if not cve_ids:
            return {}
        stmt = select(Cve.cve_id, Cve.id).where(Cve.cve_id.in_(cve_ids))
        result = await self.session.execute(stmt)
        return {row[0]: row[1] for row in result.all()}

    # ------------------------------------------------------------------
    # CVE Core — UPSERT with ON CONFLICT
    # ------------------------------------------------------------------
    async def upsert_cves(self, records: list[dict[str, Any]]) -> dict[str, int]:
        """Bulk upsert CVEs. Returns {cve_id: db_id} mapping.

        Uses PostgreSQL INSERT ... ON CONFLICT DO UPDATE.
        """
        if not records:
            return {}

        cve_values = []
        for r in records:
            cve_id = r.get("cveID") or r.get("cve_id")
            if not cve_id:
                continue

            # Extract best score from NVD object if present
            nvd_cve = r.get("nvd_cve_obj")
            cvss_v2_score = None
            cvss_v3_score = None
            cvss_v40_score = None
            severity = None

            if nvd_cve:
                score, sev, version = nvd_cve.best_score()
                if version:
                    if version.startswith("4"):
                        cvss_v40_score = score
                    elif version.startswith("3"):
                        cvss_v3_score = score
                    elif version.startswith("2"):
                        cvss_v2_score = score
                severity = sev

            # Fallback to record-level values
            cvss_v3_score = r.get("nvd_base_score") or r.get("cvss_v3_score") or cvss_v3_score
            severity = r.get("nvd_base_severity") or r.get("severity") or severity

            description = (
                    r.get("description")
                    or r.get("shortDescription")
                    or r.get("vulnerabilityName")
                    or r.get("summary")
                    or r.get("osv_summary")
                    or ""
            )
            title = (
                    r.get("vulnerabilityName")
                    or r.get("title")
                    or r.get("shortDescription")
                    or description[:500]
            )
            if len(title) > 500:
                title = title[:497] + "..."

            cve_values.append({
                "cve_id": cve_id,
                "source_identifier": r.get("vendorProject") or r.get("source_identifier"),
                "title": title or None,
                "description": description or None,
                "cvss_v2_score": cvss_v2_score,
                "cvss_v3_score": cvss_v3_score,
                "cvss_v40_score": cvss_v40_score,
                "severity": severity,
                "published_date": self._parse_datetime(
                    r.get("nvd_published") or r.get("dateAdded") or r.get("published_date")
                ),
                "last_modified_date": self._parse_datetime(
                    r.get("nvd_last_modified") or r.get("last_modified_date")
                ),
                "vuln_status": r.get("nvd_vuln_status") or r.get("vuln_status"),
            })

        if not cve_values:
            return {}

        stmt = insert(Cve).values(cve_values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={
                "source_identifier": stmt.excluded.source_identifier,
                "title": stmt.excluded.title,
                "description": stmt.excluded.description,
                "cvss_v2_score": stmt.excluded.cvss_v2_score,
                "cvss_v3_score": stmt.excluded.cvss_v3_score,
                "cvss_v40_score": stmt.excluded.cvss_v40_score,
                "severity": stmt.excluded.severity,
                "last_modified_date": stmt.excluded.last_modified_date,
                "vuln_status": stmt.excluded.vuln_status,
                "updated_at": datetime.utcnow(),
            },
        ).returning(Cve.id, Cve.cve_id)

        result = await self.session.execute(stmt)
        await self.session.flush()
        return {row.cve_id: row.id for row in result.all()}

    # ------------------------------------------------------------------
    # Child Tables — DELETE + INSERT pattern for clean updates
    # ------------------------------------------------------------------
    async def _delete_children(self, cve_db_ids: list[int]) -> None:
        """Delete all child records for given CVE db IDs."""
        if not cve_db_ids:
            return

        tables = [
            CveTag, CveDescription, CveReference, Epss, ExploitReference,
            CvssMetricV2, CvssMetricV31, CvssMetricV40,
            CveWeakness, CveConfiguration,
            OsvRecord, GithubAdvisory, VendorAdvisory,
        ]
        for table in tables:
            await self.session.execute(
                table.__table__.delete().where(table.cve_db_id.in_(cve_db_ids))
            )

    async def insert_tags(self, tags: list[dict]) -> None:
        if tags:
            await self.session.execute(insert(CveTag).values(tags))

    async def insert_descriptions(self, descriptions: list[dict]) -> None:
        if descriptions:
            await self.session.execute(insert(CveDescription).values(descriptions))

    async def insert_references(self, refs: list[dict]) -> None:
        if refs:
            await self.session.execute(insert(CveReference).values(refs))

    async def insert_epss(self, epss_records: list[dict]) -> None:
        if epss_records:
            await self.session.execute(insert(Epss).values(epss_records))

    async def insert_exploits(self, exploits: list[dict]) -> None:
        if exploits:
            await self.session.execute(insert(ExploitReference).values(exploits))

    # ------------------------------------------------------------------
    # CVSS Metrics — INSERT metric + data
    # ------------------------------------------------------------------
    async def insert_cvss_v2(self, metrics: list[dict], data: list[dict]) -> None:
        if not metrics:
            return
        await self.session.execute(insert(CvssMetricV2).values(metrics))
        # Get the inserted metric IDs to link data
        # For simplicity, we assume order is preserved and fetch back
        # In production, use RETURNING or handle this in the caller
        if data:
            await self.session.execute(insert(CvssDataV2).values(data))

    async def insert_cvss_v31(self, metrics: list[dict], data: list[dict]) -> None:
        if not metrics:
            return
        await self.session.execute(insert(CvssMetricV31).values(metrics))
        if data:
            await self.session.execute(insert(CvssDataV31).values(data))

    async def insert_cvss_v40(self, metrics: list[dict], data: list[dict]) -> None:
        if not metrics:
            return
        await self.session.execute(insert(CvssMetricV40).values(metrics))
        if data:
            await self.session.execute(insert(CvssDataV40).values(data))

    # ------------------------------------------------------------------
    # Weaknesses & Configurations
    # ------------------------------------------------------------------
    async def insert_weaknesses(self, weaknesses: list[dict]) -> None:
        if weaknesses:
            await self.session.execute(insert(CveWeakness).values(weaknesses))

    async def insert_weakness_descriptions(self, descriptions: list[dict]) -> None:
        if descriptions:
            await self.session.execute(insert(CveWeaknessDescription).values(descriptions))

    async def insert_configurations(self, configs: list[dict]) -> None:
        if configs:
            await self.session.execute(insert(CveConfiguration).values(configs))

    async def insert_nodes(self, nodes: list[dict]) -> None:
        if nodes:
            await self.session.execute(insert(CveNode).values(nodes))

    async def insert_cpe_matches(self, matches: list[dict]) -> None:
        if matches:
            await self.session.execute(insert(CpeMatch).values(matches))

    # ------------------------------------------------------------------
    # Enrichment Tables
    # ------------------------------------------------------------------
    async def insert_osv_records(self, records: list[dict]) -> None:
        if records:
            await self.session.execute(insert(OsvRecord).values(records))

    async def insert_osv_references(self, refs: list[dict]) -> None:
        if refs:
            await self.session.execute(insert(OsvReference).values(refs))

    async def insert_github_advisories(self, advisories: list[dict]) -> None:
        if advisories:
            await self.session.execute(insert(GithubAdvisory).values(advisories))

    async def insert_github_references(self, refs: list[dict]) -> None:
        if refs:
            await self.session.execute(insert(GithubAdvisoryReference).values(refs))

    async def insert_vendor_advisories(self, advisories: list[dict]) -> None:
        if advisories:
            await self.session.execute(insert(VendorAdvisory).values(advisories))

    # ------------------------------------------------------------------
    # Sync State
    # ------------------------------------------------------------------
    async def update_kev_watermark(self, latest_date: datetime) -> None:
        """Update KEV sync watermark."""
        stmt = select(SyncState).where(SyncState.sync_type == "kev_enrichment")
        result = await self.session.execute(stmt)
        sync_state = result.scalar_one_or_none()

        if not sync_state:
            sync_state = SyncState(
                sync_type="kev_enrichment",
                status="completed",
                last_sync_date=latest_date,
            )
            self.session.add(sync_state)
        else:
            current = sync_state.last_sync_date
            if current is None or latest_date > current:
                sync_state.last_sync_date = latest_date
                sync_state.status = "completed"

    # ------------------------------------------------------------------
    # High-Level: Process Enriched Records
    # ------------------------------------------------------------------
    async def process_enriched_records(self, records: list[dict[str, Any]]) -> int:
        """Process a batch of enriched records: upsert CVEs + all children.

        This is the main entry point replacing DatabaseStorage.save_enriched_cves().
        """
        if not records:
            return 0

        # 1. Upsert CVEs
        cve_id_map = await self.upsert_cves(records)
        if not cve_id_map:
            return 0

        existing_ids = list(cve_id_map.values())

        # 2. Delete old children for existing CVEs (clean update)
        await self._delete_children(existing_ids)
        await self.session.flush()

        # 3. Build batch inserts for all child tables
        tags_batch = []
        descriptions_batch = []
        refs_batch = []
        epss_batch = []
        exploits_batch = []
        cvss_v2_metrics = []
        cvss_v2_data = []
        cvss_v31_metrics = []
        cvss_v31_data = []
        cvss_v40_metrics = []
        cvss_v40_data = []
        weaknesses_batch = []
        weakness_desc_batch = []
        configs_batch = []
        nodes_batch = []
        cpe_matches_batch = []
        osv_batch = []
        osv_refs_batch = []
        github_batch = []
        github_refs_batch = []
        vendor_batch = []

        import re

        for record in records:
            cve_id = record.get("cveID") or record.get("cve_id")
            db_id = cve_id_map.get(cve_id)
            if not db_id:
                continue

            # Tags
            if record.get("vendorProject"):
                tags_batch.append({"cve_db_id": db_id, "value": f"vendor:{record['vendorProject']}"})
            if record.get("product"):
                tags_batch.append({"cve_db_id": db_id, "value": f"product:{record['product']}"})
            if record.get("knownRansomwareCampaignUse"):
                tags_batch.append({"cve_db_id": db_id, "value": f"ransomware:{record['knownRansomwareCampaignUse']}"})
            if record.get("has_exploit"):
                tags_batch.append({"cve_db_id": db_id, "value": "exploit:available"})
            if record.get("epss_score") is not None:
                tags_batch.append({"cve_db_id": db_id, "value": "epss:available"})
            if record.get("kev"):
                tags_batch.append({"cve_db_id": db_id, "value": "kev:listed"})
            if record.get("osv_summary"):
                tags_batch.append({"cve_db_id": db_id, "value": "osv:enriched"})
            if record.get("github_advisory_summary"):
                tags_batch.append({"cve_db_id": db_id, "value": "github_advisory:enriched"})
            if record.get("vendor_advisory_available"):
                tags_batch.append({"cve_db_id": db_id, "value": "vendor_advisory:available"})
            for src in record.get("exploit_sources", []):
                if isinstance(src, str) and src.strip():
                    tags_batch.append({"cve_db_id": db_id, "value": f"exploit:source:{src.strip()}"})
            for tag in record.get("additional_tags", []):
                if isinstance(tag, str) and tag.strip():
                    tags_batch.append({"cve_db_id": db_id, "value": tag.strip()})

            # EPSS
            if record.get("epss_score") is not None:
                epss_batch.append({
                    "cve_db_id": db_id,
                    "epss_score": record["epss_score"],
                    "percentile": record.get("epss_percentile"),
                })

            # Exploit References
            for exp in record.get("exploit_references", []):
                if isinstance(exp, dict):
                    url = exp.get("url") or exp.get("link")
                    if url:
                        exploits_batch.append({
                            "cve_db_id": db_id,
                            "source": exp.get("source") or "unknown",
                            "url": url,
                            "exploit_id": exp.get("exploit_id") or exp.get("id"),
                            "title": exp.get("title") or exp.get("name"),
                        })

            # External References from notes
            notes = record.get("notes") or record.get("notes_text") or ""
            urls = set(re.findall(r"https?://[^\s,;)\]\}]+", notes)) if notes else set()
            for u in urls:
                refs_batch.append({"cve_db_id": db_id, "url": u, "source": "notes"})

            for ext_ref in record.get("external_references", []):
                if isinstance(ext_ref, dict) and ext_ref.get("url"):
                    refs_batch.append({
                        "cve_db_id": db_id,
                        "url": ext_ref["url"],
                        "source": ext_ref.get("source") or "external",
                    })

            # NVD Data
            nvd_cve = record.get("nvd_cve_obj")
            if nvd_cve:
                # Descriptions
                for desc in nvd_cve.descriptions:
                    descriptions_batch.append({
                        "cve_db_id": db_id,
                        "lang": desc.lang,
                        "value": desc.value,
                    })

                # References
                for ref in nvd_cve.references:
                    refs_batch.append({
                        "cve_db_id": db_id,
                        "url": ref.url,
                        "source": ref.source,
                    })

                # CVSS v2
                for metric in nvd_cve.metrics_v2:
                    cvss_v2_metrics.append({
                        "cve_db_id": db_id,
                        "source": metric.source,
                        "metric_type": metric.metric_type,
                        "base_severity": metric.base_severity,
                        "exploitability_score": metric.exploitability_score,
                        "impact_score": metric.impact_score,
                        "ac_insuf_info": metric.ac_insuf_info,
                        "obtain_all_privilege": metric.obtain_all_privilege,
                        "obtain_user_privilege": metric.obtain_user_privilege,
                        "obtain_other_privilege": metric.obtain_other_privilege,
                        "user_interaction_required": metric.user_interaction_required,
                    })
                    if metric.cvss_data:
                        cvss_v2_data.append({
                            "version": metric.cvss_data.version,
                            "vector_string": metric.cvss_data.vector_string,
                            "base_score": metric.cvss_data.base_score,
                            "access_vector": metric.cvss_data.access_vector,
                            "access_complexity": metric.cvss_data.access_complexity,
                            "authentication": metric.cvss_data.authentication,
                            "confidentiality_impact": metric.cvss_data.confidentiality_impact,
                            "integrity_impact": metric.cvss_data.integrity_impact,
                            "availability_impact": metric.cvss_data.availability_impact,
                        })

                # CVSS v3.1
                for metric in getattr(nvd_cve, "metrics_v31", []) or []:
                    cvss_v31_metrics.append({
                        "cve_db_id": db_id,
                        "source": metric.source,
                        "metric_type": metric.metric_type,
                        "exploitability_score": metric.exploitability_score,
                        "impact_score": metric.impact_score,
                    })
                    if metric.cvss_data:
                        cvss_v31_data.append({
                            "version": metric.cvss_data.version,
                            "vector_string": metric.cvss_data.vector_string,
                            "base_score": metric.cvss_data.base_score,
                            "base_severity": metric.cvss_data.base_severity,
                            "attack_vector": metric.cvss_data.attack_vector,
                            "attack_complexity": metric.cvss_data.attack_complexity,
                            "privileges_required": metric.cvss_data.privileges_required,
                            "user_interaction": metric.cvss_data.user_interaction,
                            "scope": metric.cvss_data.scope,
                            "confidentiality_impact": metric.cvss_data.confidentiality_impact,
                            "integrity_impact": metric.cvss_data.integrity_impact,
                            "availability_impact": metric.cvss_data.availability_impact,
                        })

                # CVSS v4.0
                for metric in getattr(nvd_cve, "metrics_v40", []) or []:
                    cvss_v40_metrics.append({
                        "cve_db_id": db_id,
                        "source": metric.source,
                        "metric_type": metric.metric_type,
                    })
                    if metric.cvss_data:
                        cvss_v40_data.append({
                            "version": metric.cvss_data.version,
                            "vector_string": metric.cvss_data.vector_string,
                            "base_score": metric.cvss_data.base_score,
                            "base_severity": metric.cvss_data.base_severity,
                            "attack_vector": metric.cvss_data.attack_vector,
                            "attack_complexity": metric.cvss_data.attack_complexity,
                            "attack_requirements": metric.cvss_data.attack_requirements,
                            "privileges_required": metric.cvss_data.privileges_required,
                            "user_interaction": metric.cvss_data.user_interaction,
                            "vuln_confidentiality_impact": metric.cvss_data.vuln_confidentiality_impact,
                            "vuln_integrity_impact": metric.cvss_data.vuln_integrity_impact,
                            "vuln_availability_impact": metric.cvss_data.vuln_availability_impact,
                            "sub_confidentiality_impact": metric.cvss_data.sub_confidentiality_impact,
                            "sub_integrity_impact": metric.cvss_data.sub_integrity_impact,
                            "sub_availability_impact": metric.cvss_data.sub_availability_impact,
                        })

                # Weaknesses
                for weak in nvd_cve.weaknesses:
                    weaknesses_batch.append({
                        "cve_db_id": db_id,
                        "source": weak.source,
                        "weakness_type": weak.weakness_type,
                    })
                    for desc in weak.description:
                        weakness_desc_batch.append({
                            "lang": desc.lang,
                            "value": desc.value,
                        })

                # Configurations
                for config in nvd_cve.configurations:
                    configs_batch.append({"cve_db_id": db_id})
                    for node in config.nodes:
                        nodes_batch.append({
                            "operator": node.operator,
                            "negate": node.negate,
                        })
                        for cpe in node.cpe_match:
                            cpe_matches_batch.append({
                                "vulnerable": cpe.vulnerable,
                                "criteria": cpe.criteria,
                                "match_criteria_id": cpe.match_criteria_id,
                            })

                # KEV CWEs fallback
                if not getattr(nvd_cve, "weaknesses", []) and record.get("cwes"):
                    for cwe in record["cwes"]:
                        if cwe:
                            weaknesses_batch.append({
                                "cve_db_id": db_id,
                                "source": "KEV",
                                "weakness_type": cwe,
                            })
                            weakness_desc_batch.append({
                                "lang": "en",
                                "value": cwe,
                            })

            # OSV Enrichment
            if record.get("osv_summary") or record.get("osv_references") or record.get("osv_severities"):
                osv_batch.append({
                    "cve_db_id": db_id,
                    "osv_id": record.get("osv_id"),
                    "summary": record.get("osv_summary"),
                    "severities": record.get("osv_severities") or [],
                })
                for ref in record.get("osv_references", []):
                    if isinstance(ref, dict) and ref.get("url"):
                        osv_refs_batch.append({
                            "url": ref["url"],
                            "source_id": ref.get("id"),
                            "title": ref.get("title"),
                        })

            # GitHub Advisory
            if record.get("github_advisory_summary") or record.get("github_advisory_severity"):
                github_batch.append({
                    "cve_db_id": db_id,
                    "summary": record.get("github_advisory_summary"),
                    "severity": record.get("github_advisory_severity"),
                    "package_name": record.get("github_advisory_package"),
                })
                for ref in record.get("github_advisory_references", []):
                    if isinstance(ref, dict) and ref.get("url"):
                        github_refs_batch.append({
                            "url": ref["url"],
                            "source": ref.get("source", "GitHub Advisory"),
                        })

            # Vendor Advisory
            if record.get("vendor_advisory_available") or record.get("vendor_advisory_sources"):
                vendor_batch.append({
                    "cve_db_id": db_id,
                    "vendor": record.get("vendor_advisory_vendor"),
                    "is_available": bool(record.get("vendor_advisory_available", False)),
                    "sources": record.get("vendor_advisory_sources") or [],
                    "details": record.get("vendor_advisory_details"),
                })

        # 4. Execute all bulk inserts
        await self.insert_tags(tags_batch)
        await self.insert_descriptions(descriptions_batch)
        await self.insert_references(refs_batch)
        await self.insert_epss(epss_batch)
        await self.insert_exploits(exploits_batch)
        await self.insert_cvss_v2(cvss_v2_metrics, cvss_v2_data)
        await self.insert_cvss_v31(cvss_v31_metrics, cvss_v31_data)
        await self.insert_cvss_v40(cvss_v40_metrics, cvss_v40_data)
        await self.insert_weaknesses(weaknesses_batch)
        await self.insert_weakness_descriptions(weakness_desc_batch)
        await self.insert_configurations(configs_batch)
        await self.insert_nodes(nodes_batch)
        await self.insert_cpe_matches(cpe_matches_batch)
        await self.insert_osv_records(osv_batch)
        await self.insert_osv_references(osv_refs_batch)
        await self.insert_github_advisories(github_batch)
        await self.insert_github_references(github_refs_batch)
        await self.insert_vendor_advisories(vendor_batch)

        # 5. Update KEV watermark if applicable
        latest_date = None
        for r in records:
            date_str = r.get("dateAdded")
            if date_str:
                try:
                    d = datetime.strptime(date_str, "%Y-%m-%d").date()
                    if latest_date is None or d > latest_date:
                        latest_date = d
                except ValueError:
                    continue
        if latest_date:
            await self.update_kev_watermark(
                datetime.combine(latest_date, datetime.min.time())
            )

        return len(records)
