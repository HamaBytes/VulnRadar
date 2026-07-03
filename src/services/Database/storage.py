"""Database storage service for VulnRadar.

Persists enriched CVE data into relational database tables using SQLAlchemy.
Uses an Object-Oriented approach.
"""

import logging
import re
from datetime import datetime
from typing import Any, List, Optional
from sqlalchemy.orm import Session

from src.models.cve import Cve
from src.models.cve_details import CveTag, CveDescription
from src.models.cvss import CvssMetricV2, CvssDataV2
from src.models.cvss_models import (
    CvssMetricV31,
    CvssDataV31,
    CvssMetricV40,
    CvssDataV40,
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


class DatabaseStorage:
    """Service class for persisting enriched CVE records to PostgreSQL."""

    def __init__(self, db: Session) -> None:
        """Initialize the storage service with a SQLAlchemy Session."""
        self.db = db

    def _parse_datetime(self, date_str: Optional[str]) -> Optional[datetime]:
        """Safely parse ISO datetime string into datetime object."""
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except ValueError:
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
        return None

    def _update_kev_sync_watermark(self, kevs: List[dict[str, Any]]) -> None:
        """Update the KEV enrichment sync watermark to the latest dateAdded.

        This ensures incremental syncs only process new KEV entries.
        """
        if not kevs:
            return

        latest_date = None
        for k in kevs:
            date_added_str = k.get("dateAdded")
            if date_added_str:
                try:
                    date_added = datetime.strptime(date_added_str, "%Y-%m-%d").date()
                    if latest_date is None or date_added > latest_date:
                        latest_date = date_added
                except ValueError:
                    continue

        if latest_date:
            sync_state = self.db.query(SyncState).filter(
                SyncState.sync_type == "kev_enrichment"
            ).first()

            if not sync_state:
                sync_state = SyncState(
                    sync_type="kev_enrichment",
                    status="completed",
                )
                self.db.add(sync_state)

            # Only update if this watermark is newer
            current_watermark = sync_state.last_sync_date.date() if sync_state.last_sync_date else None
            if current_watermark is None or latest_date > current_watermark:
                sync_state.last_sync_date = datetime.combine(latest_date, datetime.min.time())
                sync_state.status = "completed"
                logger.info(f"Updated KEV sync watermark to {latest_date}")

    def _save_osv_data(self, cve_record: Cve, record: dict[str, Any]) -> None:
        """Persist OSV enrichment data to dedicated tables."""
        if not any(record.get(k) for k in ("osv_summary", "osv_references", "osv_severities")):
            return

        osv = OsvRecord(
            cve_db_id=cve_record.id,
            cve_id=cve_record.cve_id,
            osv_id=record.get("osv_id"),
            summary=record.get("osv_summary"),
            severities=record.get("osv_severities") or [],
        )
        cve_record.osv_records.append(osv)
        self.db.flush()  # Get OSV record ID for references

        for ref in record.get("osv_references", []):
            if isinstance(ref, dict) and ref.get("url"):
                osv.references.append(OsvReference(
                    url=ref["url"],
                    source_id=ref.get("id"),
                    title=ref.get("title"),
                ))

    def _save_github_advisory_data(self, cve_record: Cve, record: dict[str, Any]) -> None:
        """Persist GitHub Advisory enrichment data to dedicated tables."""
        if not any(record.get(k) for k in ("github_advisory_summary", "github_advisory_severity",
                                           "github_advisory_package", "github_advisory_references")):
            return

        advisory = GithubAdvisory(
            cve_db_id=cve_record.id,
            cve_id=cve_record.cve_id,
            summary=record.get("github_advisory_summary"),
            severity=record.get("github_advisory_severity"),
            package_name=record.get("github_advisory_package"),
        )
        cve_record.github_advisories.append(advisory)
        self.db.flush()

        for ref in record.get("github_advisory_references", []):
            if isinstance(ref, dict) and ref.get("url"):
                advisory.references.append(GithubAdvisoryReference(
                    url=ref["url"],
                    source=ref.get("source", "GitHub Advisory"),
                ))

    def _save_vendor_advisory_data(self, cve_record: Cve, record: dict[str, Any]) -> None:
        """Persist Vendor Advisory enrichment data to dedicated tables."""
        if not any(record.get(k) for k in ("vendor_advisory_available", "vendor_advisory_sources", "vendor_advisory_details", "vendor_advisory_vendor")):
            return

        vendor = VendorAdvisory(
            cve_db_id=cve_record.id,
            cve_id=cve_record.cve_id,
            vendor=record.get("vendor_advisory_vendor"),
            is_available=bool(record.get("vendor_advisory_available", False)),
            sources=record.get("vendor_advisory_sources") or [],
            details=record.get("vendor_advisory_details"),
        )
        cve_record.vendor_advisories.append(vendor)

    def save_enriched_cve(self, record: dict[str, Any]) -> Cve:
        """Save or update a single enriched CVE record and all its child relations."""
        cve_id = record.get("cveID")
        if not cve_id:
            raise ValueError("Record does not contain a valid cveID")

        # 1. Fetch or create the Cve record
        cve_record = self.db.query(Cve).filter(Cve.cve_id == cve_id).first()
        if cve_record:
            logger.info(f"Updating existing CVE record: {cve_id}")
            # Clear existing child records for clean update
            self.db.query(CveTag).filter(CveTag.cve_db_id == cve_record.id).delete()
            self.db.query(CveDescription).filter(CveDescription.cve_db_id == cve_record.id).delete()
            self.db.query(CveReference).filter(CveReference.cve_db_id == cve_record.id).delete()
            self.db.query(Epss).filter(Epss.cve_db_id == cve_record.id).delete()
            self.db.query(ExploitReference).filter(ExploitReference.cve_db_id == cve_record.id).delete()
            self.db.query(CvssMetricV2).filter(CvssMetricV2.cve_db_id == cve_record.id).delete()
            self.db.query(CveWeakness).filter(CveWeakness.cve_db_id == cve_record.id).delete()
            self.db.query(CveConfiguration).filter(CveConfiguration.cve_db_id == cve_record.id).delete()

            # NEW: Clear enrichment data tables
            self.db.query(OsvRecord).filter(OsvRecord.cve_db_id == cve_record.id).delete()
            self.db.query(GithubAdvisory).filter(GithubAdvisory.cve_db_id == cve_record.id).delete()
            self.db.query(VendorAdvisory).filter(VendorAdvisory.cve_db_id == cve_record.id).delete()
        else:
            logger.info(f"Creating new CVE record: {cve_id}")
            cve_record = Cve(cve_id=cve_id)
            self.db.add(cve_record)
            self.db.flush()

        # 2. Update parent columns
        description = (
                record.get("description")
                or record.get("shortDescription")
                or record.get("vulnerabilityName")
                or record.get("summary")
                or record.get("osv_summary")
        )
        title = (
                record.get("vulnerabilityName")
                or record.get("title")
                or record.get("shortDescription")
                or description
        )
        if title and len(title) > 500:
            title = title[:497] + "..."
        cve_record.title = title

        cve_record.description = description
        cve_record.cvss_v3_score = (
                record.get("nvd_base_score")
                or record.get("cvss_v3_score")
                or record.get("base_score")
        )
        cve_record.severity = (
                record.get("nvd_base_severity")
                or record.get("severity")
                or record.get("base_severity")
                or record.get("github_advisory_severity")
        )
        cve_record.published_date = self._parse_datetime(
            record.get("nvd_published") or record.get("dateAdded") or record.get("published_date")
        )
        cve_record.last_modified_date = self._parse_datetime(
            record.get("nvd_last_modified") or record.get("last_modified_date")
        )
        cve_record.vuln_status = record.get("nvd_vuln_status") or record.get("vuln_status")
        cve_record.source_identifier = record.get("vendorProject") or record.get("source_identifier")

        # 3. Add Tags
        tags = []
        if record.get("vendorProject"):
            tags.append(CveTag(cve_db_id=cve_record.id, value=f"vendor:{record['vendorProject']}"))
        if record.get("product"):
            tags.append(CveTag(cve_db_id=cve_record.id, value=f"product:{record['product']}"))
        if record.get("knownRansomwareCampaignUse"):
            tags.append(CveTag(cve_db_id=cve_record.id, value=f"ransomware:{record['knownRansomwareCampaignUse']}"))
        if record.get("has_exploit"):
            tags.append(CveTag(cve_db_id=cve_record.id, value="exploit:available"))
        if record.get("epss_score") is not None:
            tags.append(CveTag(cve_db_id=cve_record.id, value="epss:available"))
        if record.get("kev"):
            tags.append(CveTag(cve_db_id=cve_record.id, value="kev:listed"))
        if record.get("osv_summary"):
            tags.append(CveTag(cve_db_id=cve_record.id, value="osv:enriched"))
        if record.get("github_advisory_summary"):
            tags.append(CveTag(cve_db_id=cve_record.id, value="github_advisory:enriched"))
        if record.get("vendor_advisory_available"):
            tags.append(CveTag(cve_db_id=cve_record.id, value="vendor_advisory:available"))
        if record.get("exploit_sources"):
            for src in record["exploit_sources"]:
                if isinstance(src, str) and src.strip():
                    tags.append(CveTag(cve_db_id=cve_record.id, value=f"exploit:source:{src.strip()}"))

        for tag in record.get("additional_tags", []):
            if isinstance(tag, str) and tag.strip():
                tags.append(CveTag(cve_db_id=cve_record.id, value=tag.strip()))

        cve_record.tags.extend(tags)

        # 4. Add EPSS data
        if record.get("epss_score") is not None:
            cve_record.epss.append(Epss(
                cve_db_id=cve_record.id,
                cve_id=cve_id,
                epss_score=record.get("epss_score"),
                percentile=record.get("epss_percentile"),
            ))

        # 5. Add Exploit References
        for exp_ref in record.get("exploit_references", []):
            if not isinstance(exp_ref, dict):
                continue
            url = exp_ref.get("url") or exp_ref.get("link")
            if not url:
                continue
            cve_record.exploit_references.append(ExploitReference(
                cve_db_id=cve_record.id,
                cve_id=cve_id,
                source=exp_ref.get("source") or "unknown",
                url=url,
                exploit_id=exp_ref.get("exploit_id") or exp_ref.get("id"),
                title=exp_ref.get("title") or exp_ref.get("name"),
            ))

        # 6. Add external references
        # Extract URLs from KEV notes field and add as external references
        notes = record.get("notes") or record.get("notes_text") or ""
        urls = set(re.findall(r"https?://[^\s,;)\]\}]+", notes)) if notes else set()
        for u in urls:
            cve_record.references.append(CveReference(
                cve_db_id=cve_record.id,
                url=u,
                source="notes",
            ))

        for ext_ref in record.get("external_references", []):
            if isinstance(ext_ref, dict) and ext_ref.get("url"):
                cve_record.references.append(CveReference(
                    cve_db_id=cve_record.id,
                    url=ext_ref.get("url"),
                    source=ext_ref.get("source") or "external",
                ))

        # 7. Add NVD data
        nvd_cve = record.get("nvd_cve_obj")
        if nvd_cve:
            if nvd_cve.source_identifier:
                cve_record.source_identifier = nvd_cve.source_identifier

            for desc in nvd_cve.descriptions:
                cve_record.descriptions.append(
                    CveDescription(cve_db_id=cve_record.id, lang=desc.lang, value=desc.value)
                )

            for ref in nvd_cve.references:
                cve_record.references.append(
                    CveReference(cve_db_id=cve_record.id, url=ref.url, source=ref.source)
                )

            for metric in nvd_cve.metrics_v2:
                db_metric = CvssMetricV2(
                    cve_db_id=cve_record.id,
                    source=metric.source,
                    metric_type=metric.metric_type,
                    base_severity=metric.base_severity,
                    exploitability_score=metric.exploitability_score,
                    impact_score=metric.impact_score,
                    ac_insuf_info=metric.ac_insuf_info,
                    obtain_all_privilege=metric.obtain_all_privilege,
                    obtain_user_privilege=metric.obtain_user_privilege,
                    obtain_other_privilege=metric.obtain_other_privilege,
                    user_interaction_required=metric.user_interaction_required,
                )
                if metric.cvss_data:
                    db_metric.cvss_data = CvssDataV2(
                        version=metric.cvss_data.version,
                        vector_string=metric.cvss_data.vector_string,
                        base_score=metric.cvss_data.base_score,
                        access_vector=metric.cvss_data.access_vector,
                        access_complexity=metric.cvss_data.access_complexity,
                        authentication=metric.cvss_data.authentication,
                        confidentiality_impact=metric.cvss_data.confidentiality_impact,
                        integrity_impact=metric.cvss_data.integrity_impact,
                        availability_impact=metric.cvss_data.availability_impact,
                    )
                cve_record.cvss_v2_metrics.append(db_metric)

            # Persist CVSS v3.1 metrics
            for metric in getattr(nvd_cve, "metrics_v31", []):
                db_metric31 = CvssMetricV31(
                    cve_db_id=cve_record.id,
                    source=metric.source,
                    metric_type=metric.metric_type,
                    exploitability_score=metric.exploitability_score,
                    impact_score=metric.impact_score,
                )
                if metric.cvss_data:
                    db_metric31.cvss_data = CvssDataV31(
                        version=metric.cvss_data.version,
                        vector_string=metric.cvss_data.vector_string,
                        base_score=metric.cvss_data.base_score,
                        base_severity=metric.cvss_data.base_severity,
                        attack_vector=metric.cvss_data.attack_vector,
                        attack_complexity=metric.cvss_data.attack_complexity,
                        privileges_required=metric.cvss_data.privileges_required,
                        user_interaction=metric.cvss_data.user_interaction,
                        scope=metric.cvss_data.scope,
                        confidentiality_impact=metric.cvss_data.confidentiality_impact,
                        integrity_impact=metric.cvss_data.integrity_impact,
                        availability_impact=metric.cvss_data.availability_impact,
                    )
                cve_record.cvss_v31_metrics.append(db_metric31)

            # Persist CVSS v4.0 metrics
            for metric in getattr(nvd_cve, "metrics_v40", []):
                db_metric40 = CvssMetricV40(
                    cve_db_id=cve_record.id,
                    source=metric.source,
                    metric_type=metric.metric_type,
                )
                if metric.cvss_data:
                    db_metric40.cvss_data = CvssDataV40(
                        version=metric.cvss_data.version,
                        vector_string=metric.cvss_data.vector_string,
                        base_score=metric.cvss_data.base_score,
                        base_severity=metric.cvss_data.base_severity,
                        attack_vector=metric.cvss_data.attack_vector,
                        attack_complexity=metric.cvss_data.attack_complexity,
                        attack_requirements=metric.cvss_data.attack_requirements,
                        privileges_required=metric.cvss_data.privileges_required,
                        user_interaction=metric.cvss_data.user_interaction,
                        vuln_confidentiality_impact=metric.cvss_data.vuln_confidentiality_impact,
                        vuln_integrity_impact=metric.cvss_data.vuln_integrity_impact,
                        vuln_availability_impact=metric.cvss_data.vuln_availability_impact,
                        sub_confidentiality_impact=metric.cvss_data.sub_confidentiality_impact,
                        sub_integrity_impact=metric.cvss_data.sub_integrity_impact,
                        sub_availability_impact=metric.cvss_data.sub_availability_impact,
                    )
                cve_record.cvss_v40_metrics.append(db_metric40)

            for weak in nvd_cve.weaknesses:
                db_weak = CveWeakness(
                    cve_db_id=cve_record.id,
                    source=weak.source,
                    weakness_type=weak.weakness_type,
                )
                for desc in weak.description:
                    db_weak.descriptions.append(
                        CveWeaknessDescription(lang=desc.lang, value=desc.value)
                    )
                cve_record.weaknesses.append(db_weak)

            # If NVD weaknesses absent but KEV provides CWE identifiers, map them
            if not getattr(nvd_cve, "weaknesses", []) and record.get("cwes"):
                for cwe in record.get("cwes", []):
                    if not cwe:
                        continue
                    kev_weak = CveWeakness(
                        cve_db_id=cve_record.id,
                        source="KEV",
                        weakness_type=cwe,
                    )
                    kev_weak.descriptions.append(CveWeaknessDescription(lang="en", value=cwe))
                    cve_record.weaknesses.append(kev_weak)

            for config in nvd_cve.configurations:
                db_config = CveConfiguration(cve_db_id=cve_record.id)
                for node in config.nodes:
                    db_node = CveNode(operator=node.operator, negate=node.negate)
                    for cpe in node.cpe_match:
                        db_node.cpe_matches.append(
                            CpeMatch(
                                vulnerable=cpe.vulnerable,
                                criteria=cpe.criteria,
                                match_criteria_id=cpe.match_criteria_id,
                            )
                        )
                    db_config.nodes.append(db_node)
                cve_record.configurations.append(db_config)

        # 8. NEW: Save enrichment data to dedicated tables
        self._save_osv_data(cve_record, record)
        self._save_github_advisory_data(cve_record, record)
        self._save_vendor_advisory_data(cve_record, record)

        return cve_record

    def save_enriched_cves(self, records: List[dict[str, Any]], update_watermark: bool = True) -> int:
        """Save a list of enriched CVE records.

        :param records: List of enriched CVE dicts to persist.
        :param update_watermark: Whether to update the KEV sync watermark after saving.
        :returns: Number of successfully saved records.
        """
        saved_count = 0
        for record in records:
            try:
                self.save_enriched_cve(record)
                saved_count += 1
            except Exception as e:
                logger.error(f"Failed to save CVE {record.get('cveID')}: {e}")
                self.db.rollback()
                raise e

        if update_watermark:
            try:
                self._update_kev_sync_watermark(records)
            except Exception as e:
                logger.warning(f"Failed to update KEV sync watermark: {e}")

        self.db.commit()
        logger.info(f"Saved {saved_count} CVE records to database")
        return saved_count
