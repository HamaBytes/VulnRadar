from typing import Any, Generic, TypeVar

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.base import Base

ModelType = TypeVar("ModelType", bound=Base)


class BaseRepository(Generic[ModelType]):
    def __init__(self, model: type[ModelType], session: AsyncSession):
        self.model = model
        self.session = session

    async def get(self, id: int) -> ModelType | None:
        return await self.session.get(self.model, id)

    async def get_by_ids(self, ids: list[int]) -> list[ModelType]:
        if not ids:
            return []
        stmt = select(self.model).where(self.model.id.in_(ids))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def create(self, obj: ModelType) -> ModelType:
        self.session.add(obj)
        await self.session.flush()
        await self.session.refresh(obj)
        return obj

    async def create_many(self, objs: list[ModelType]) -> list[ModelType]:
        self.session.add_all(objs)
        await self.session.flush()
        return objs

    async def update(self, obj: ModelType, data: dict[str, Any]) -> ModelType:
        for key, value in data.items():
            setattr(obj, key, value)
        await self.session.flush()
        await self.session.refresh(obj)
        return obj

    async def delete(self, obj: ModelType) -> None:
        await self.session.delete(obj)
        await self.session.flush()

    async def count(self) -> int:
        stmt = select(func.count()).select_from(self.model)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def exists(self, id: int) -> bool:
        stmt = select(self.model.id).where(self.model.id == id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none() is not None