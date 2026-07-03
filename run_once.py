# run_once.py
import asyncio
from src.jobs.scheduler import SchedulerManager

async def main():
    manager = SchedulerManager()
    await manager.run_sync_job()

if __name__ == "__main__":
    asyncio.run(main())