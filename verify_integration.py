import asyncio
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

from src.fetchers.pipelines import run_enrichment_pipeline

async def main():
    print("=" * 70)
    print("Running enrichment pipeline (KEV + EPSS + NVD) for top 3 CVEs...")
    print("=" * 70)

    # Run pipeline WITHOUT saving to DB (just test enrichment)
    enriched_data = await run_enrichment_pipeline(
        limit=3,
        include_epss=True,
        include_nvd=True,
        include_exploits=True,
        include_osv=True,
        include_github_advisories=True,
        include_vendor_advisories=True,
        incremental=False,  # <-- Force full fetch, skip DB watermark logic
    )

    print(f"\nTotal enriched records: {len(enriched_data)}")

    for record in enriched_data:
        print("\n" + "-" * 60)
        print(f"  CVE ID:                  {record.get('cveID')}")
        print(f"  Vendor:                  {record.get('vendorProject')}")
        print(f"  Product:                 {record.get('product')}")
        print(f"  EPSS Score:              {record.get('epss_score')}")
        print(f"  EPSS Percentile:         {record.get('epss_percentile')}")
        print(f"  NVD Base Score:          {record.get('nvd_base_score')}")
        print(f"  NVD Severity:            {record.get('nvd_base_severity')}")
        print(f"  NVD CVSS Version:        {record.get('nvd_cvss_version')}")
        print(f"  NVD Status:              {record.get('nvd_vuln_status')}")
        print(f"  Has Exploit:             {record.get('has_exploit')}")
        print(f"  Exploit Sources:         {record.get('exploit_sources')}")
        print(f"  Exploit Refs Count:      {len(record.get('exploit_references', []))}")
        print(f"  OSV Summary:             {record.get('osv_summary')}")
        print(f"  OSV Severities:          {record.get('osv_severities')}")
        print(f"  GitHub Advisory Summary: {record.get('github_advisory_summary')}")
        print(f"  GitHub Advisory Severity:{record.get('github_advisory_severity')}")
        print(f"  GitHub Advisory Package: {record.get('github_advisory_package')}")
        print(f"  Vendor Advisory Avail:   {record.get('vendor_advisory_available')}")
        print("-" * 60)

    print("\nFull JSON output:")
    print(json.dumps(enriched_data, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(main())