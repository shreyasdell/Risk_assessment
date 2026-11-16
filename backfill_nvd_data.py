"""
Temporary script to backfill NVD data for existing CVEs.

This script:
1. Fetches all CVEs from the database
2. For each CVE, fetches NVD data
3. Updates the CVE record with NVD references and CWE data

Run this once to populate NVD data for existing CVEs, then delete the script.
"""

import sys
import time
from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.cve import CVE
from app.services.nvd_service import nvd_service

def backfill_nvd_data():
    """Backfill NVD data for all CVEs in the database."""
    db = SessionLocal()
    
    try:
        # Get all CVEs
        cves = db.query(CVE).all()
        total = len(cves)
        print(f"Found {total} CVEs in database")
        
        if total == 0:
            print("No CVEs found. Exiting.")
            return
        
        # Process each CVE
        for i, cve in enumerate(cves, 1):
            print(f"\n[{i}/{total}] Processing {cve.cve_id}...")
            
            try:
                # Fetch NVD data
                nvd_data = nvd_service._fetch_cve_from_nvd_sync(cve.cve_id)
                
                if not nvd_data:
                    print(f"  No NVD data found for {cve.cve_id}")
                    continue
                
                # Extract references
                references = []
                if "references" in nvd_data:
                    for ref_group in nvd_data["references"]:
                        source = ref_group.get("source", "")
                        for ref in ref_group.get("reference_data", []):
                            url = ref.get("url", "")
                            tags = ref.get("tags", [])
                            
                            # Filter out MISC tags
                            filtered_tags = [tag for tag in tags if tag != "MISC" and not tag.startswith("x_refsource_MISC")]
                            
                            references.append({
                                "url": url,
                                "source": source,
                                "tags": filtered_tags
                            })
                
                # Extract CWEs
                cwes = []
                if "weaknesses" in nvd_data:
                    for weakness in nvd_data["weaknesses"]:
                        source = weakness.get("source", "")
                        for desc in weakness.get("description", []):
                            cwe_id = desc.get("value", "")
                            if cwe_id.startswith("CWE-"):
                                cwes.append({
                                    "cwe_id": cwe_id,
                                    "cwe_name": "",
                                    "source": source
                                })
                
                # Update CVE with NVD data
                if references:
                    # Store as JSON
                    import json
                    cve.references = json.dumps(references)
                    print(f"  Updated {len(references)} references")
                
                if cwes:
                    # Store as comma-separated list
                    cwe_ids = [cwe["cwe_id"] for cwe in cwes]
                    cve.cwe_id = ",".join(cwe_ids)
                    print(f"  Updated {len(cwe_ids)} CWEs")
                
                db.commit()
                print(f"  ✓ Updated {cve.cve_id}")
                
                # Rate limiting
                time.sleep(0.6)
                
            except Exception as e:
                print(f"  ✗ Error processing {cve.cve_id}: {str(e)}")
                db.rollback()
                continue
        
        print(f"\n✓ Backfill complete. Processed {total} CVEs.")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    print("Starting NVD data backfill...")
    print("This will update all CVEs with NVD references and CWE data.")
    # Running automatically without confirmation
    backfill_nvd_data()
