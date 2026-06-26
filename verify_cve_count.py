"""Script to verify CVE count in vulnradar schema."""

from src.config.database import SessionLocal
from src.models.cve import Cve

def verify_cve_count():
    """Query the database to count CVEs in the vulnradar schema."""
    db = SessionLocal
    try:
        count = db.query(Cve).count()
        print(f"Total CVEs in vulnradar.cves table: {count}")
        
        if count >= 30000:
            print("✓ Verification passed: 30K+ CVEs present")
        else:
            print(f"✗ Verification failed: Only {count} CVEs present (expected 30K+)")
            
        return count
    finally:
        db.close()

if __name__ == "__main__":
    verify_cve_count()
