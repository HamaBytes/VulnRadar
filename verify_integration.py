import asyncio
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
from fetchers import run_enrichment_pipeline
async def main():
    print("=" * 70)
    print("Running enrichment pipeline (KEV + EPSS + NVD) for top 3 CVEs...")
    print("=" * 70)
    enriched_data = await run_enrichment_pipeline(
        limit=3,
        include_epss=True,
        include_nvd=True,
    )
    print(enriched_data)
    print("=" * 70)
    for record in enriched_data:
        print("\n" + "-" * 60)
        print(f"  CVE ID:           {record.get('cveID')}")
        print(f"  Vendor:           {record.get('vendorProject')}")
        print(f"  Product:          {record.get('product')}")
        print(f"  EPSS Score:       {record.get('epss_score')}")
        print(f"  EPSS Percentile:  {record.get('epss_percentile')}")
        print(f"  NVD Base Score:   {record.get('nvd_base_score')}")
        print(f"  NVD Severity:     {record.get('nvd_base_severity')}")
        print(f"  NVD CVSS Version: {record.get('nvd_cvss_version')}")
        print(f"  NVD Status:       {record.get('nvd_vuln_status')}")
        print("-" * 60)

    print(f"\nTotal enriched records: {len(enriched_data)}")
    print("\nFull JSON output:")
    print(json.dumps(enriched_data, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())
