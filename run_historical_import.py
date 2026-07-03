"""Script to run historical NVD CVE import from 2023 to today."""

import asyncio
from datetime import date
import logging
import sys

from src.fetchers.pipelines import run_historical_import

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def main():
    """Run historical import from 2023-01-01 to today."""
    start_date = date(2023, 1, 1)
    end_date = date.today()
    
    logger.info(f"Starting historical import from {start_date} to {end_date}")
    
    def progress_callback(current: int, total: int, stage: str):
        """Progress callback for import."""
        logger.info(f"Progress: {current}/{total} - {stage}")
    
    try:
        result = await run_historical_import(
            start_date=start_date,
            end_date=end_date,
            chunk_days=30,
            include_epss=True,  # Disable EPSS for faster historical import
            include_nvd=True,
            include_exploits=True,  # Disable exploits for faster historical import
            on_progress=progress_callback,
        )
        
        logger.info(f"Historical import completed:")
        logger.info(f"  Total CVEs fetched: {result['total_cves_fetched']}")
        logger.info(f"  Total CVEs saved: {result['total_cves_saved']}")
        logger.info(f"  Total chunks processed: {result['total_chunks']}")
        logger.info(f"  Date range: {result['start_date']} to {result['end_date']}")
        
    except Exception as e:
        logger.error(f"Historical import failed: {e}")
        logger.info("Import is resumable - run the script again to continue from where it left off.")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
