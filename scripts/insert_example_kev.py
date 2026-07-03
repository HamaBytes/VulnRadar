import sys
from pathlib import Path
from types import SimpleNamespace

# Ensure project root is on sys.path when running this script directly
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config.database import init_db, db_session
from src.services.Database.storage import DatabaseStorage
import uuid

init_db()

example = {
    "cveID": "CVE-2026-0001",
    "vulnerabilityName": "Example KEV Vulnerability",
    "shortDescription": "Example KEV entry used for testing persistence of enrichment fields.",
    "dateAdded": "2026-07-01",
    "notes": "See vendor advisory at https://example.com/advisory/12345 and mitigation at https://example.com/mitigation",
    "cwes": ["CWE-79"],
}

# Create fake NVD object with CVSS v3.1 and v4.0 metrics to exercise persistence
cvss_v31_data = SimpleNamespace(
    version="3.1",
    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    base_score=9.8,
    base_severity="CRITICAL",
    attack_vector="NETWORK",
    attack_complexity="LOW",
    privileges_required="NONE",
    user_interaction="NONE",
    scope="UNCHANGED",
    confidentiality_impact="HIGH",
    integrity_impact="HIGH",
    availability_impact="HIGH",
)

metric_v31 = SimpleNamespace(
    source="NVD",
    metric_type="base",
    exploitability_score=3.9,
    impact_score=5.9,
    cvss_data=cvss_v31_data,
)

cvss_v40_data = SimpleNamespace(
    version="4.0",
    vector_string="CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    base_score=10.0,
    base_severity="CRITICAL",
    attack_vector="NETWORK",
    attack_complexity="LOW",
    attack_requirements="NONE",
    privileges_required="NONE",
    user_interaction="NONE",
    vuln_confidentiality_impact="HIGH",
    vuln_integrity_impact="HIGH",
    vuln_availability_impact="HIGH",
    sub_confidentiality_impact=None,
    sub_integrity_impact=None,
    sub_availability_impact=None,
)

metric_v40 = SimpleNamespace(
    source="NVD",
    metric_type="base",
    cvss_data=cvss_v40_data,
)

nvd_obj = SimpleNamespace(
    source_identifier="NVD",
    descriptions=[],
    references=[],
    metrics_v2=[],
    metrics_v31=[metric_v31],
    metrics_v40=[metric_v40],
    weaknesses=[],
    configurations=[],
)

example["nvd_cve_obj"] = nvd_obj

with db_session() as db:
    storage = DatabaseStorage(db)
    cve = storage.save_enriched_cve(example)
    # commit happens in db_session context
    print("Inserted CVE:", cve.cve_id, "id=", cve.id)
