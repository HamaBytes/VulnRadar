from typing import Sequence

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from src.models.cve import Cve
from src.repositories.base import BaseRepository


class CveRepository(BaseRepository[Cve]):
    def __init__(self, session: AsyncSession):
        super().__init__(Cve, session)

    async def get_by_cve_id(self, cve_id: str) -> Cve | None:
        stmt = select(Cve).where(Cve.cve_id == cve_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_cve_ids(self, cve_ids: list[str]) -> Sequence[Cve]:
        if not cve_ids:
            return []
        stmt = select(Cve).where(Cve.cve_id.in_(cve_ids))
        result = await self.session.execute(stmt)
        return result.scalars().all()

    async def get_detail_by_cve_id(self, cve_id: str) -> Cve | None:
        """Load CVE with all relationships for detail view."""
        stmt = (
            select(Cve)
            .where(Cve.cve_id == cve_id)
            .options(
                selectinload(Cve.tags),
                selectinload(Cve.descriptions),
                selectinload(Cve.cvss_v2_metrics).selectinload(Cve.cvss_v2_metrics.cvss_data),
                selectinload(Cve.cvss_v31_metrics).selectinload(Cve.cvss_v31_metrics.cvss_data),
                selectinload(Cve.cvss_v40_metrics).selectinload(Cve.cvss_v40_metrics.cvss_data),
                selectinload(Cve.weaknesses).selectinload(Cve.weaknesses.descriptions),
                selectinload(Cve.configurations).selectinload(Cve.configurations.nodes).selectinload(Cve.configurations.nodes.cpe_matches),
                selectinload(Cve.references),
                selectinload(Cve.epss),
                selectinload(Cve.exploit_references),
                selectinload(Cve.osv_records).selectinload(Cve.osv_records.references),
                selectinload(Cve.github_advisories).selectinload(Cve.github_advisories.references),
                selectinload(Cve.vendor_advisories),
            )
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_paginated(
            self,
            severity: str | None = None,
            vuln_status: str | None = None,
            search: str | None = None,
            offset: int = 0,
            limit: int = 50,
    ) -> tuple[Sequence[Cve], int]:
        """Paginated list with optional filters."""
        base_stmt = select(Cve)
        count_stmt = select(func.count(Cve.id))

        if severity:
            base_stmt = base_stmt.where(Cve.severity == severity)
            count_stmt = count_stmt.where(Cve.severity == severity)
        if vuln_status:
            base_stmt = base_stmt.where(Cve.vuln_status == vuln_status)
            count_stmt = count_stmt.where(Cve.vuln_status == vuln_status)
        if search:
            base_stmt = base_stmt.where(Cve.cve_id.ilike(f"%{search}%") | Cve.title.ilike(f"%{search}%"))
            count_stmt = count_stmt.where(Cve.cve_id.ilike(f"%{search}%") | Cve.title.ilike(f"%{search}%"))

        base_stmt = base_stmt.order_by(Cve.published_date.desc()).offset(offset).limit(limit)

        result = await self.session.execute(base_stmt)
        count_result = await self.session.execute(count_stmt)

        return result.scalars().all(), count_result.scalar_one()

    async def get_cve_ids_to_db_ids(self, cve_ids: list[str]) -> dict[str, int]:
        """Bulk mapping for sync jobs."""
        if not cve_ids:
            return {}
        stmt = select(Cve.cve_id, Cve.id).where(Cve.cve_id.in_(cve_ids))
        result = await self.session.execute(stmt)
        return {row[0]: row[1] for row in result.all()}