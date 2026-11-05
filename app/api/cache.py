"""
Cache management endpoints for monitoring and admin.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.auth.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/cache", tags=["Cache Management"])


@router.get("/stats", summary="Get cache statistics")
def get_cache_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Show how effective the cache is.
    Higher cache hit percentage = fewer API calls = faster syncs.
    """
    from app.services.cve_cache_service import CVECacheService
    from app.services.cve_org_service import cve_org_client

    cache = CVECacheService(cve_org_client)
    return cache.get_cache_stats(db)


@router.post(
    "/clear-expired",
    summary="Clear expired cache entries"
)
def clear_expired_cache(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Force re-fetch of expired CVE.org data on next sync."""
    from app.services.cve_cache_service import CVECacheService
    from app.services.cve_org_service import cve_org_client

    cache = CVECacheService(cve_org_client)
    cleared = cache.clear_expired_cache(db)
    return {
        "message": f"Cleared {cleared} expired cache entries"
    }
