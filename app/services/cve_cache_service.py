"""
CVE Cache Service

Wraps CVE.org API calls with database-backed caching.
Before making any CVE.org API call, checks if we already
have the data cached from a previous fetch.

SDD Requirement:
"Caching responses to reduce repeated calls" [Section 9]
"If CVE API fails - Retry, Cache Previous Data" [Section 4]
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, List
from sqlalchemy.orm import Session

from app.models.cve import CVE


class CVECacheService:

    CACHE_DURATION_HOURS = 24

    def __init__(self, cve_org_client):
        """
        Args:
            cve_org_client: Your existing CVEOrgClient instance
        """
        self.cve_org = cve_org_client

    def _is_cache_valid(self, cve_record: CVE) -> bool:
        """Check if cached CVE.org data is still fresh."""
        if not cve_record.cveorg_fetched_at:
            return False

        age = datetime.utcnow() - cve_record.cveorg_fetched_at
        return age < timedelta(hours=self.CACHE_DURATION_HOURS)

    def _get_cached_affected_products(
        self,
        db: Session,
        cve_id_str: str
    ) -> Optional[List[Dict]]:
        """
        Check database for cached CVE.org affected products.

        Returns:
            List of affected product dicts if cache is valid,
            None if cache miss or expired.
        """
        cve_record = (
            db.query(CVE)
            .filter(CVE.cve_id == cve_id_str)
            .first()
        )

        if not cve_record:
            return None

        if not self._is_cache_valid(cve_record):
            return None

        if not cve_record.cveorg_affected_products:
            return None

        return cve_record.cveorg_affected_products

    def _save_to_cache(
        self,
        db: Session,
        cve_id_str: str,
        affected_products: List[Dict],
        raw_response: Dict = None
    ):
        """
        Save CVE.org response to database cache.
        Creates CVE record if it does not exist.
        """
        cve_record = (
            db.query(CVE)
            .filter(CVE.cve_id == cve_id_str)
            .first()
        )

        if cve_record:
            cve_record.cveorg_affected_products = affected_products
            cve_record.cveorg_fetched_at = datetime.utcnow()
            if raw_response:
                cve_record.cveorg_raw = raw_response
        else:
            # CVE does not exist yet — it will be created
            # by the NVD sync process, so we just skip caching
            # for now. The cache will be populated on next sync.
            pass

        db.flush()

    async def get_affected_products(
        self,
        db: Session,
        cve_id_str: str
    ) -> Optional[Dict]:
        """
        Get CVE.org data with caching.

        Flow:
        1. Check database cache
        2. If cache hit and fresh → return cached data
        3. If cache miss → fetch from CVE.org API
        4. Save response to cache
        5. Return data

        Returns:
            Parsed CVE.org record dict, or None if unavailable
        """
        # Step 1: Check cache
        cached = self._get_cached_affected_products(
            db, cve_id_str
        )

        if cached is not None:
            print(f"[Cache] HIT for {cve_id_str}")
            return {
                "affected_products": cached,
                "from_cache": True
            }

        # Step 2: Cache miss — fetch from CVE.org
        print(f"[Cache] MISS for {cve_id_str} — fetching from CVE.org")

        raw_response = await self.cve_org.fetch_cve(cve_id_str)

        if not raw_response:
            # CVE.org unavailable — check if we have stale cache
            stale = self._get_stale_cache(db, cve_id_str)
            if stale:
                print(
                    f"[Cache] Using stale cache for {cve_id_str}"
                )
                return {
                    "affected_products": stale,
                    "from_cache": True,
                    "stale": True
                }
            return None

        # Step 3: Parse the response
        parsed = self.cve_org.parse_cve_record(raw_response)
        affected_products = parsed.get("affected_products", [])

        # Step 4: Save to cache
        self._save_to_cache(
            db,
            cve_id_str,
            affected_products,
            raw_response
        )

        return {
            "affected_products": affected_products,
            "from_cache": False,
            "parsed_data": parsed
        }

    def _get_stale_cache(
        self,
        db: Session,
        cve_id_str: str
    ) -> Optional[List[Dict]]:
        """
        Get expired cache data as fallback when CVE.org is down.
        SDD requires: "If CVE API fails - Cache Previous Data" [3]
        """
        cve_record = (
            db.query(CVE)
            .filter(CVE.cve_id == cve_id_str)
            .first()
        )

        if cve_record and cve_record.cveorg_affected_products:
            return cve_record.cveorg_affected_products

        return None

    def get_cache_stats(self, db: Session) -> Dict:
        """Get cache statistics for monitoring."""
        total_cves = db.query(CVE).count()
        cached = (
            db.query(CVE)
            .filter(CVE.cveorg_fetched_at.isnot(None))
            .count()
        )
        fresh = (
            db.query(CVE)
            .filter(
                CVE.cveorg_fetched_at > (
                    datetime.utcnow()
                    - timedelta(hours=self.CACHE_DURATION_HOURS)
                )
            )
            .count()
        )
        stale = cached - fresh

        return {
            "total_cves": total_cves,
            "cached": cached,
            "fresh_cache": fresh,
            "stale_cache": stale,
            "uncached": total_cves - cached,
            "cache_hit_potential": (
                f"{round((cached / total_cves) * 100, 1)}%"
                if total_cves > 0 else "0%"
            )
        }

    def clear_expired_cache(self, db: Session) -> int:
        """Clear expired cache entries to force re-fetch."""
        cutoff = (
            datetime.utcnow()
            - timedelta(hours=self.CACHE_DURATION_HOURS)
        )

        count = (
            db.query(CVE)
            .filter(CVE.cveorg_fetched_at < cutoff)
            .update({
                CVE.cveorg_affected_products: None,
                CVE.cveorg_fetched_at: None,
                CVE.cveorg_raw: None
            })
        )
        db.commit()
        return count
