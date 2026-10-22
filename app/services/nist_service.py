"""
NIST Recommendation Service
Maps CWE weaknesses to security recommendations.
"""

from typing import Optional, List
from sqlalchemy.orm import Session

from app.models.nist_recommendation import NistRecommendation


class NistService:

    def get_by_cwe(
        self,
        db: Session,
        cwe_id: str
    ) -> Optional[NistRecommendation]:
        """Look up recommendation by CWE ID."""
        return (
            db.query(NistRecommendation)
            .filter(NistRecommendation.cwe_id == cwe_id)
            .first()
        )

    def get_all(self, db: Session) -> List[NistRecommendation]:
        """Get all NIST recommendations."""
        return db.query(NistRecommendation).all()

    def get_for_cve(
        self,
        db: Session,
        cve_id: int
    ) -> Optional[dict]:
        """
        Get NIST recommendation for a specific CVE
        by looking up its CWE.
        """
        from app.models.cve import CVE

        cve = db.query(CVE).filter(CVE.id == cve_id).first()
        if not cve or not cve.cwe_id:
            return None

        rec = self.get_by_cwe(db, cve.cwe_id)
        if not rec:
            return {
                "cve_id": cve.cve_id,
                "cwe_id": cve.cwe_id,
                "recommendation": (
                    f"No specific NIST recommendation found "
                    f"for {cve.cwe_id}. Review NVD entry at "
                    f"{cve.nvd_url} for mitigation guidance."
                ),
                "source": "generic"
            }

        return {
            "cve_id": cve.cve_id,
            "cwe_id": rec.cwe_id,
            "cwe_name": rec.cwe_name,
            "nist_category": rec.nist_category,
            "nist_function": rec.nist_function,
            "recommendation": rec.recommendation,
            "detailed_guidance": rec.detailed_guidance,
            "source": "nist_database"
        }


nist_service = NistService()
