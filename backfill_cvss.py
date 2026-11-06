"""
Backfill CVSS data for CVEs that have cvss_score = 0.0
This script fetches CVSS from NVD API for all CVEs missing CVSS data.
"""

import sys
import time
from app.core.database import SessionLocal
from app.models.cve import CVE
from app.services.nvd_service import NVDService

def flush_print(msg):
    print(msg)
    sys.stdout.flush()

def backfill_cvss():
    flush_print("Starting CVSS backfill...")
    db = SessionLocal()
    flush_print("Database session created")
    nvd_service = NVDService()
    flush_print("NVD service initialized")

    try:
        # Find all CVEs with cvss_score = 0.0 or None
        flush_print("Querying CVEs...")
        cves = db.query(CVE).filter(
            (CVE.cvss_score == 0.0) | (CVE.cvss_score.is_(None))
        ).all()

        flush_print(f"Found {len(cves)} CVEs missing CVSS data")

        updated_count = 0
        failed_count = 0

        for i, cve in enumerate(cves):
            flush_print(f"[{i+1}/{len(cves)}] Processing {cve.cve_id}")

            try:
                # Fetch CVSS from NVD
                nvd_data = nvd_service._fetch_cve_from_nvd_sync(cve.cve_id)

                if nvd_data:
                    cvss_score, cvss_vector, severity = nvd_service._extract_cvss(nvd_data)

                    if cvss_score > 0.0:
                        cve.cvss_score = cvss_score
                        cve.cvss_vector = cvss_vector
                        cve.severity = severity.lower()
                        flush_print(f"  ✓ Updated: CVSS {cvss_score} ({severity})")
                        updated_count += 1
                    else:
                        flush_print(f"  ✗ No CVSS data found in NVD")
                        failed_count += 1
                else:
                    flush_print(f"  ✗ Failed to fetch from NVD")
                    failed_count += 1

                # Commit every 10 CVEs to avoid long transactions
                if (i + 1) % 10 == 0:
                    db.commit()
                    flush_print(f"  Committed batch")

            except Exception as e:
                flush_print(f"  ✗ Error: {e}")
                failed_count += 1
                continue

        # Final commit
        db.commit()

        flush_print(f"\nBackfill complete:")
        flush_print(f"  Updated: {updated_count}")
        flush_print(f"  Failed: {failed_count}")
        flush_print(f"  Total: {len(cves)}")

    except Exception as e:
        flush_print(f"Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    backfill_cvss()
