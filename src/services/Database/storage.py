"""Database storage service for VulnRadar.

Persists enriched CVE data into relational database tables using SQLAlchemy.
Uses an Object-Oriented approach.
"""

import logging
from datetime import datetime
from typing import Any, List, Optional
from sqlalchemy.orm import Session

from src.models.cve import Cve
from src.models.cve_details import CveTag, CveDescription
from src.models.cvss import CvssMetricV2, CvssDataV2
from src.models.weakness import CveWeakness, CveWeaknessDescription
from src.models.configuration import CveConfiguration, CveNode, CpeMatch
from src.models.reference import CveReference
from src.models.epss import Epss
from src.models.exploit import ExploitReference

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

    def save_enriched_cve(self, record: dict[str, Any]) -> Cve:
        """Save or update a single enriched CVE record and all its child relations."""
        cve_id = record.get("cveID")
        if not cve_id:
            raise ValueError("Record does not contain a valid cveID")

        # 1. Fetch or create the Cve record
        cve_record = self.db.query(Cve).filter(Cve.cve_id == cve_id).first()
        if cve_record:
            logger.info(f"Updating existing CVE record: {cve_id}")
            # Clear existing child records to allow clean updates of collections
            self.db.query(CveTag).filter(CveTag.cve_db_id == cve_record.id).delete()
            self.db.query(CveDescription).filter(CveDescription.cve_db_id == cve_record.id).delete()
            self.db.query(CveReference).filter(CveReference.cve_db_id == cve_record.id).delete()
            self.db.query(Epss).filter(Epss.cve_db_id == cve_record.id).delete()
            self.db.query(ExploitReference).filter(ExploitReference.cve_db_id == cve_record.id).delete()
            
            # Delete cvss metrics (cascades to CvssDataV2)
            self.db.query(CvssMetricV2).filter(CvssMetricV2.cve_db_id == cve_record.id).delete()
            
            # Delete weaknesses (cascades to CveWeaknessDescription)
            self.db.query(CveWeakness).filter(CveWeakness.cve_db_id == cve_record.id).delete()
            
            # Delete configurations (cascades to nodes -> cpe_matches)
            self.db.query(CveConfiguration).filter(CveConfiguration.cve_db_id == cve_record.id).delete()
        else:
            logger.info(f"Creating new CVE record: {cve_id}")
            cve_record = Cve(cve_id=cve_id)
            self.db.add(cve_record)
            # Flush to generate the primary key ID
            self.db.flush()

        # 2. Update parent columns
        cve_record.title = record.get("vulnerabilityName")
        cve_record.description = record.get("shortDescription")
        cve_record.cvss_v3_score = record.get("nvd_base_score")
        cve_record.severity = record.get("nvd_base_severity")
        cve_record.published_date = self._parse_datetime(record.get("nvd_published") or record.get("dateAdded"))
        cve_record.last_modified_date = self._parse_datetime(record.get("nvd_last_modified"))
        cve_record.vuln_status = record.get("nvd_vuln_status")
        cve_record.source_identifier = record.get("vendorProject")

        # 3. Add Tags (from KEV details)
        tags = []
        if record.get("vendorProject"):
            tags.append(CveTag(cve_db_id=cve_record.id, value=f"vendor:{record['vendorProject']}"))
        if record.get("product"):
            tags.append(CveTag(cve_db_id=cve_record.id, value=f"product:{record['product']}"))
        if record.get("knownRansomwareCampaignUse"):
            tags.append(CveTag(cve_db_id=cve_record.id, value=f"ransomware:{record['knownRansomwareCampaignUse']}"))
        cve_record.tags.extend(tags)

        # 4. Add EPSS data
        if record.get("epss_score") is not None:
            epss_obj = Epss(
                cve_db_id=cve_record.id,
                cve_id=cve_id,
                epss_score=record["epss_score"],
                percentile=record.get("epss_percentile"),
            )
            cve_record.epss.append(epss_obj)

        # 5. Add Exploit References
        for exp_ref in record.get("exploit_references", []):
            exploit_obj = ExploitReference(
                cve_db_id=cve_record.id,
                cve_id=cve_id,
                source=exp_ref.get("source"),
                url=exp_ref.get("url"),
                exploit_id=exp_ref.get("exploit_id"),
                title=exp_ref.get("title"),
                module=exp_ref.get("module"),
            )
            cve_record.exploit_references.append(exploit_obj)

        # 6. Add detailed NVD data if nvd_cve_obj is attached
        nvd_cve = record.get("nvd_cve_obj")
        if nvd_cve:
            # Set NVD source identifier if present
            if nvd_cve.source_identifier:
                cve_record.source_identifier = nvd_cve.source_identifier

            # NVD Descriptions (multi-lingual)
            for desc in nvd_cve.descriptions:
                cve_record.descriptions.append(
                    CveDescription(cve_db_id=cve_record.id, lang=desc.lang, value=desc.value)
                )

            # NVD References
            for ref in nvd_cve.references:
                cve_record.references.append(
                    CveReference(cve_db_id=cve_record.id, url=ref.url, source=ref.source)
                )

            # NVD CVSS V2 Metrics
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

            # NVD Weaknesses (CWEs)
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

            # NVD Configurations (CPE matches)
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

        return cve_record

    def save_enriched_cves(self, records: List[dict[str, Any]]) -> int:
        """Save a list of enriched CVE records.
        
        Commits the transaction and returns the number of successfully saved records.
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
        self.db.commit()
        return saved_count