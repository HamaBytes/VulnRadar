from src.schemas.base import BaseSchema
from src.schemas.cve import CveDetailSchema, CveListItemSchema
from src.schemas.cve_details import CveDescriptionSchema, CveTagSchema
from src.schemas.cvss import (
    CvssDataV2Schema,
    CvssDataV31Schema,
    CvssDataV40Schema,
    CvssMetricV2Schema,
    CvssMetricV31Schema,
    CvssMetricV40Schema,
)
from src.schemas.weakness import CveWeaknessSchema, CveWeaknessDescriptionSchema
from src.schemas.configuration import CpeMatchSchema, CveConfigurationSchema, CveNodeSchema
from src.schemas.reference import CveReferenceSchema
from src.schemas.exploit import ExploitReferenceSchema
from src.schemas.epss import EpssSchema
from src.schemas.osv import OsvRecordSchema, OsvReferenceSchema
from src.schemas.github_advisory import GithubAdvisorySchema, GithubAdvisoryReferenceSchema
from src.schemas.vendor_advisory import VendorAdvisorySchema
from src.schemas.users import UserSchema
from src.schemas.projects import ProjectSchema, ProjectItemSchema
from src.schemas.sync_state import SyncStateSchema, SyncRunSchema

__all__ = [
    "BaseSchema",
    "CpeMatchSchema",
    "CveConfigurationSchema",
    "CveDescriptionSchema",
    "CveDetailSchema",
    "CveListItemSchema",
    "CveNodeSchema",
    "CveReferenceSchema",
    "CveTagSchema",
    "CveWeaknessDescriptionSchema",
    "CveWeaknessSchema",
    "CvssDataV2Schema",
    "CvssDataV31Schema",
    "CvssDataV40Schema",
    "CvssMetricV2Schema",
    "CvssMetricV31Schema",
    "CvssMetricV40Schema",
    "EpssSchema",
    "ExploitReferenceSchema",
    "GithubAdvisoryReferenceSchema",
    "GithubAdvisorySchema",
    "OsvRecordSchema",
    "OsvReferenceSchema",
    "ProjectItemSchema",
    "ProjectSchema",
    "SyncRunSchema",
    "SyncStateSchema",
    "UserSchema",
    "VendorAdvisorySchema",
]