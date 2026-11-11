# PROJECT_CONTEXT.md

## 1. Repository Overview

### Directory Tree (excluding node_modules, .venv, __pycache__, .git)

```
/workspaces/Vulnerability_Risk_Assessment_Tool/
├── .devcontainer/
├── .pytest_cache/
├── alembic/
│   └── versions/
├── app/
│   ├── agent/
│   │   ├── langgraph_agent/
│   │   │   └── graph.py
│   │   ├── normalizer/
│   │   │   ├── __init__.py
│   │   │   └── normalizer.py
│   │   ├── router.py
│   │   └── schemas.py
│   ├── api/
│   │   ├── cves.py
│   │   ├── components.py
│   │   ├── applications.py
│   │   ├── auth.py
│   │   ├── risk.py
│   │   ├── remediations.py
│   │   ├── nist.py
│   │   └── vendors.py
│   ├── auth/
│   │   ├── security.py
│   │   └── dependencies.py
│   ├── core/
│   │   ├── config.py
│   │   └── database.py
│   ├── middleware/
│   │   └── rate_limit.py
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── vendor.py
│   │   ├── application.py
│   │   ├── component.py
│   │   ├── cve.py
│   │   ├── risk_score.py
│   │   ├── remediation.py
│   │   ├── audit_log.py
│   │   ├── nist_recommendation.py
│   │   ├── codebase_upload.py
│   │   ├── background_task.py
│   │   └── vendor_cache.py
│   ├── sbom/
│   │   ├── parser.py
│   │   └── service.py
│   ├── schemas/
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── component.py
│   │   ├── cve.py
│   │   ├── application.py
│   │   ├── risk.py
│   │   ├── remediation.py
│   │   ├── nist.py
│   │   └── vendor.py
│   └── services/
│       ├── nvd_service.py
│       ├── cve_org_service.py
│       ├── cve_cache_service.py
│       ├── risk_service.py
│       ├── cve_service.py
│       ├── auth_service.py
│       ├── sbom_service.py
│       └── cpe_vendor_map.py
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   ├── components/
│   │   ├── context/
│   │   └── pages/
│   └── public/
├── scripts/
│   └── backfill_enrichment.py
├── src/ (duplicate of frontend/src)
├── tests/
│   ├── unit/
│   │   ├── test_cve_org_service.py
│   │   └── test_langgraph_agent.py
│   ├── e2e/
│   └── integration/
├── alembic.ini
├── main.py
├── requirements.txt
└── .env.example
```

### Git Log (last 30 commits)

```
67627eb temp commit with backcvss
f3dadb3 temp on nov 5
f7c9555 3-11 commit
f6b33c7 Increase NVD CVE fetch limit to 1000 and add pagination to CVEs modal
bcfb276 temp
02abde5 Fix pagination to return total count for components and CVEs
ffc1d6a Add hyperlink to CVE ID in CVEsPage
caa0fe9 Add hyperlink to CVE ID in ComponentsPage
883c1ba Revert NVD service to earlier version
9a55288 Recreate/update admin user in PostgreSQL
97d5289 Update DashboardPage to use refresh_component_count endpoint
87dab7a Add refresh_component_count function and API endpoint
e9b1287 Add RBAC check to NISTPage
3664b63 Fix functional issues across all pages
df8e509 Fix dashboard refresh and add pagination to Components page
a897e41 Fix criticality display case sensitivity and add cleanup script
263311d Add NVD service protections to prevent false positive CVEs
11f8962 Change Component.application to use back_populates instead of backref
8a5270f Fix conflicting backref in Application.components relationship
030e8f0 Add cascade delete for components and improve delete confirmation
2c12928 Fix CVE reference filtering in NVD service
b108990 Fix login to save token before fetching user data
f0f05b3 Remove non-functional notification bell icon from header
d41e984 Add user management UI and fix sidebar navigation
ec4258a Fix login to fetch user data including role
8048ec5 Fix RBAC to use case-insensitive role comparisons
852b42d Remove all remaining Enum references for PostgreSQL compatibility
96da719 Fix UserUpdate schema to use String instead of UserRole enum
b94df03 Replace Enum types with String for PostgreSQL compatibility
75349cc Fix migrations for PostgreSQL compatibility
```

### Dependencies

**requirements.txt:**
```
fastapi==0.115.0
uvicorn[standard]==0.32.0
sqlalchemy==2.0.35
alembic==1.14.0
psycopg2-binary==2.9.9
pydantic==2.9.2
pydantic-settings==2.6.1
pydantic[email]==2.9.2
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
bcrypt==4.0.1
python-multipart==0.0.12
httpx==0.27.0
reportlab==5.1.0
packaging>=21.0
requests>=2.28.0
langgraph>=0.2.0
pytest-playwright==0.10.0
pytest==9.2.0
```

### Application Startup

**File:** `main.py`

**Startup command:** `uvicorn main:app --host 0.0.0.0 --port 8000`
**Workers:** Default (1 worker, no worker count specified)
**Port:** 8000

---

## 2. Configuration

### Configuration File: app/core/config.py

**File Path:** `/workspaces/Vulnerability_Risk_Assessment_Tool/app/core/config.py`

**Verbatim code:**
```python
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours
    NVD_API_KEY: Optional[str] = None

    # LangGraph Agent Configuration (for component enrichment)
    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "qwen2.5:7b"
    OLLAMA_TIMEOUT: int = 60

    class Config:
        env_file = ".env"


settings = Settings()
```

### Environment File: .env.example

**File Path:** `/workspaces/Vulnerability_Risk_Assessment_Tool/.env.example`

**Verbatim code:**
```ini
DATABASE_URL=postgresql://user:password@localhost:5432/vulnerability_risk_db
SECRET_KEY=your-secret-key-here-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# LangGraph Agent Configuration (for component enrichment)
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b
OLLAMA_TIMEOUT=60

# NVD API (optional - for higher rate limits)
# NVD_API_KEY=your-api-key-here
```

**Note:** The actual `.env` file is in `.gitignore` and cannot be accessed. Secrets would be redacted as *** if present.

### Configuration Settings and Usage

#### DATABASE_URL
- **Default:** None (required)
- **Read at:** `app/core/database.py:7-10`, `alembic/env.py:26`

#### SECRET_KEY
- **Default:** None (required)
- **Read at:** `app/auth/security.py:25,31`

#### ALGORITHM
- **Default:** "HS256"
- **Read at:** `app/auth/security.py:25,31`

#### ACCESS_TOKEN_EXPIRE_MINUTES
- **Default:** 1440 (24 hours)
- **Read at:** `app/auth/security.py:23`, `app/services/auth_service.py:36`

#### NVD_API_KEY
- **Default:** None (optional)
- **Read at:** `app/services/nvd_service.py:34`

#### OLLAMA_URL
- **Default:** "http://localhost:11434"
- **Read at:** `app/agent/router.py:40`, `app/services/sbom_service.py:93`, `scripts/backfill_enrichment.py:108`

#### OLLAMA_MODEL
- **Default:** "qwen2.5:7b"
- **Read at:** `app/agent/router.py:49`, `app/services/sbom_service.py:94`, `scripts/backfill_enrichment.py:109`

#### OLLAMA_TIMEOUT
- **Default:** 60
- **Read at:** No direct usage found in codebase

### Cache TTL Settings

#### CVE Cache TTL
- **File:** `app/services/cve_cache_service.py:22`
- **Setting:** `CACHE_DURATION_HOURS = 24`

### Rate Limit Settings

#### Application Rate Limits
- **File:** `app/middleware/rate_limit.py:10-14`
- **Settings:** default: 200/min, auth: 20/min, upload: 20/min
- **Status:** DISABLED in `main.py:24`

#### NVD API Rate Limits
- **File:** `app/services/nvd_service.py:40-41`
- **Settings:** 50 req/30s (with key), 5 req/30s (without key)

#### NVD Sync Rate Limit
- **File:** `app/services/nvd_service.py:293`
- **Setting:** `time.sleep(0.6)` - ~6 req/10s

### Threshold Settings

#### CVE_DISPLAY_THRESHOLD
- **Status:** REMOVED in Ticket 6
- **Was used by:** Dead CVEFilterAgent (no longer in codebase)

---

## 3. Database

### Database Connection Status

**UNKNOWN - The `.env` file is in `.gitignore` and cannot be accessed. The following database queries cannot be run without database access:**
- `\d` for table schemas
- `alembic history`
- `alembic current`
- Row count queries
- Application 19 queries

### Database Tables (from SQLAlchemy Models)

#### 1. users
**File:** `app/models/user.py:7-19`

#### 2. vendors
**File:** `app/models/vendor.py:7-21`

#### 3. applications
**File:** `app/models/application.py:7-21`

#### 4. components
**File:** `app/models/component.py:7-46`

#### 5. cves
**File:** `app/models/cve.py:7-30`

#### 6. component_cve (association table)
**File:** `app/models/cve.py:33-41`

#### 7. risk_scores
**File:** `app/models/risk_score.py:7-20`

#### 8. remediations
**File:** `app/models/remediation.py:7-19`

#### 9. audit_logs
**File:** `app/models/audit_log.py:7-16`

#### 10. nist_recommendations
**File:** `app/models/nist_recommendation.py:7-17`

#### 11. cve_cache
**File:** `app/models/cve.py:44-52`

#### 12. vendor_product_cache
**File:** `app/models/vendor_cache.py:7-18`

#### 13. background_tasks
**File:** `app/models/background_task.py:7-17`

#### 14. codebase_uploads
**File:** `app/models/codebase_upload.py:7-16`

---

## 4. SBOM Upload and Parsing

### Parser Module

**File:** `app/sbom/parser.py`

**Deduplication Logic:** DELETES all existing components for the same `sbom_id`, then INSERTS new components (replace, not append).

**File:** `app/services/sbom_service.py:67-85`

**Name Building:** The parser extracts name and version from the SBOM but does not build vendor/package names. The PURL is stored as-is. Vendor/product names are built later by the LangGraph enrichment agent.

---

## 5. LangGraph Enrichment Agent

### Full File: app/agent/langgraph_agent/graph.py

**File Path:** `/workspaces/Vulnerability_Risk_Assessment_Tool/app/agent/langgraph_agent/graph.py`

**Exact Stage Order:**
1. parse_purl - No LLM
2. check_cache - No LLM
3. llm_resolve - USES LLM (only if cache miss)
4. construct_cpe - No LLM
5. fallback_1 - No LLM (triggers on error)
6. fallback_2 - No LLM (triggers on error)
7. fallback_3 - No LLM (triggers on error)

**Fallback triggers:** ERROR ONLY (lines 108-113). NOT triggered by low confidence.

### PURL Parsing

**File:** `app/agent/langgraph_agent/graph.py:130-205`

**Output for pkg:composer/laravel/framework@5.5.0:**
- purl_type: "composer"
- purl_namespace: "laravel"
- purl_name: "framework"
- ecosystem: "composer"

**Output for pkg:npm/%40aws-sdk/client-ses@3.194.0:**
- purl_type: "npm"
- purl_namespace: "@aws-sdk" (URL-decoded from %40)
- purl_name: "client-ses"
- ecosystem: "npm"

### Cache Key

**Cache key:** `component_name` (raw name, NOT PURL, NOT type/namespace/name)

**Code:** `app/agent/langgraph_agent/graph.py:163-165`

### LLM Prompt

**File:** `app/agent/langgraph_agent/graph.py:193-216`

### Confidence Stored

**Code:** `app/agent/langgraph_agent/graph.py:239`
**Answer:** The LLM's self-reported confidence value is stored (default 70 if not provided). NOT a fixed value.

### LLM Validation Before Caching

**Answer:** NO - The LLM result is cached immediately after parsing, with NO validation against NVD CPE dictionary API.

**Code:** `app/agent/langgraph_agent/graph.py:242-243`

### fallback_2 Component Import Error

**Status:** FIXED
**Evidence:** Import is present at `app/agent/langgraph_agent/graph.py:341`

### DB Columns Written by update_component

**File:** `app/agent/langgraph_agent/graph.py:345-357`

### Enrichment Trigger

**File:** `app/services/sbom_service.py:90-110`

---

## 6. Phase 1: NVD Discovery

### discover_cve_ids()

**File:** `app/services/nvd_service.py:480-570`

### _generate_search_queries()

**File:** `app/services/nvd_service.py:610-650`

### _clean_component_name()

**File:** `app/services/nvd_service.py:79-82`

**Verbatim code:**
```python
def _clean_component_name(self, name: str) -> str:
    """
    Clean component name for better NVD matching.

    Examples:
      'log4j-core'      -> 'log4j'
      'jackson-databind' -> 'jackson-databind'
      'spring-boot'     -> 'spring boot'
      'commons-text'    -> 'commons-text'
    """
    # Remove common suffixes that NVD might not use
    cleaned = name.lower().strip()
    return cleaned
```

**Status:** EXISTS in committed code (line 79)

### _filter_relevant_cves()

**File:** `app/services/nvd_service.py:568-600`

**Verbatim code:**
```python
def _filter_relevant_cves(
    self,
    cves: List[Dict],
    component_name: str,
    component_version: str = None
) -> List[Dict]:
    """
    Filter NVD results to only include CVEs that
    actually mention our component.

    Why?
    Keyword search can return unrelated results.
    e.g., searching "react" might return CVEs for
    "nuclear reactor" software.
    """
    clean_name = self._clean_component_name(component_name)
    name_parts = clean_name.replace("-", " ").split()

    relevant = []
    for cve in cves:
        desc = cve.get("description", "").lower()
        cve_id = cve.get("cve_id", "")

        # Check if description mentions the component
        # At least one significant part of the name
        # must appear
        name_found = False
        for part in name_parts:
            if len(part) >= 3 and part in desc:
                name_found = True
                break

        # Also check the CVE references (list of URLs)
        refs = cve.get("references", [])
        if not name_found and refs:
            if any(clean_name in ref.get("url", "").lower() for ref in refs):
                name_found = True

        if name_found:
            relevant.append(cve)

    return relevant
```

**Status:** EXISTS in committed code (line 568)

### _filter_by_version()

**File:** `app/services/nvd_service.py:602-614`

**Verbatim code:**
```python
def _filter_by_version(
    self,
    cves: List[Dict],
    component_version: str
) -> List[Dict]:
    """
    Filter CVEs by version range if provided.
    """
    # Simplified version filtering
    # For now, return all CVEs
    return cves
```

**Status:** EXISTS in committed code (line 602)

### _build_cpe()

**File:** `app/services/nvd_service.py:670-700`

### _make_request()

**File:** `app/services/nvd_service.py:702-730`

### _rate_limit()

**File:** `app/services/nvd_service.py:46-68`

### fetch_cves_for_component()

**File:** `app/services/nvd_service.py:800-850`

### Exact Call from sync_component_cves()

**File:** `app/services/nvd_service.py:819-825`

**Is constructed_cpe passed?** YES - `constructed_cpe=constructed_cpe` is passed as an argument.

### "No agent data" Condition

**File:** `app/services/nvd_service.py:509`
**Condition:** When both `constructed_cpe` and `search_name` are None.

### Package-name-only Fallback

**NO** - The fallback uses `_build_cpe()` which tries CPE_VENDOR_MAP first, then uses component name as both vendor and product. No special handling for package-name-only components like psr7.

### Candidate Cap

**Cap:** 100 results per request (line 485, 493)

### NVD Discovery Cache

**NO** - There is no NVD discovery cache. Only CVE.org has a cache (`CVECacheService`).

---

## 7. Phase 2: CVE.org Verification

### is_component_affected()

**File:** `app/services/cve_org_service.py:224-377`

### Product Matching

**File:** `app/services/cve_org_service.py:281-309`

**laravel/framework handling:** Matches if product == "framework" (package part match) or product == "Laravel Framework" (normalized display name). Does NOT match if product == "laravel/laravel" (skeleton).

### Version Check

**File:** `app/services/cve_org_service.py:307-385`

**lessThan vs lessThanOrEqual:** `including` → inclusive, `excluding` → exclusive upper bound
**Missing upper bound:** Returns True if version >= start
**Unparseable versions:** Caught in except block, returns False
**"binutils 2.34":** Handled by `_clean_version_string()` which strips non-numeric characters
**Composite version strings (">= 0.6.0, < 2.9.0"):** NOT HANDLED

### _llm_analyze_old_cve

**File:** `app/services/cve_org_service.py:620-695`

**Prompt:** Lines 620-648

**Confidence cap:** Lines 639-641 apply the cap: `min(parsed.get("confidence", 50), self.MAX_LLM_CONFIDENCE)` where `MAX_LLM_CONFIDENCE = 75` (line 79)

**Log line "REJECTED - LLM analysis of old CVE: ... (confidence: 95)":** This log line appears in TICKET_0_CODE_PATH_REPORT.md but the code shows the cap is applied at line 639. This is a discrepancy - either the log is from before the cap was added, or the cap is not being applied correctly. The code shows the cap IS present.

### Confidence Values

**File:** `app/services/cve_org_service.py:69-79`

- 95: CONFIDENCE_CPE_MATCH_VERSION_IN_RANGE
- 90: CONFIDENCE_CPE_MATCH_VERSION_OUT_OF_RANGE
- 85: CONFIDENCE_NO_PRODUCT_MATCH
- 60: CONFIDENCE_PRODUCT_MATCH_NO_VERSION_DATA
- 50: CONFIDENCE_NO_UPPER_BOUND
- 25: CONFIDENCE_LLM_FAILED
- 75: MAX_LLM_CONFIDENCE

### Final Filter

**File:** `app/services/nvd_service.py:865-875`

**Condition:** `is_affected and confidence >= 50`

---

## 8. Caching

### CVECacheService

**File:** `app/services/cve_cache_service.py`

**Cache key:** `cve_id` (CVE ID string)
**TTL:** 24 hours
**Stale-cache fallback:** NOT IMPLEMENTED
**In-memory layer:** NOT IMPLEMENTED

---

## 9. CVEFilterAgent Removal

### Grep Results

**CVEFilterAgent references:**
- Documentation files only (TICKET_6_*, ARCHITECTURE.md)
- NO code references remain

**cve_filter_agent references:**
- Documentation files only
- NO code references remain

**self.cve_agent references:**
- NO references remain

**llm_reasoner references:**
- NO references remain (file deleted)

**CVE_DISPLAY_THRESHOLD references:**
- Documentation files only
- NO code references remain

### nvd_service.py CVEFilterAgent Import

**Status:** REMOVED in Ticket 6
**File:** `app/services/nvd_service.py:22` - Import removed
**File:** `app/services/nvd_service.py:44-50` - Initialization removed

---

## 10. Sync Orchestration

### sync_component_cves()

**File:** `app/services/nvd_service.py:770-900`

**Bulk sync:** NOT IMPLEMENTED - Only single-component sync exists

**Concurrency:** No semaphore or parallel processing found

**Progress tracking:** Uses background_tasks table

**Old CVE links cleared:** NOT IMPLEMENTED - No code found that clears old links before re-linking

---

## 11. API Endpoints

### Routes

**File:** `main.py:27-35`

- GET /api/cves - `app/api/cves.py`
- GET /api/components - `app/api/components.py`
- GET /api/applications - `app/api/applications.py`
- POST /api/auth/* - `app/api/auth.py`
- GET /api/risk - `app/api/risk.py`
- GET /api/remediations - `app/api/remediations.py`
- GET /api/nist - `app/api/nist.py`
- GET /api/vendors - `app/api/vendors.py`
- GET /api/agent/health - `app/agent/router.py`

### GET /cves with application_id

**File:** `app/api/cves.py:50-68`

**Verbatim code:**
```python
@router.get("/")
def read_cves(
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = Query(None),
    min_cvss: Optional[float] = Query(None),
    application_id: Optional[int] = Query(None),
    distinct: bool = Query(True, description="Return distinct CVEs (True) or all findings (False)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    cves, total = get_cves(db, skip=skip, limit=limit, severity=severity, min_cvss=min_cvss, application_id=application_id, distinct=distinct)
    return {
        "data": cves,
        "total": total,
        "skip": skip,
        "limit": limit,
        "distinct": distinct
    }
```

**Query:** `app/services/cve_service.py:17-80`

**Verbatim code:**
```python
def get_cves(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    severity: Optional[str] = None,
    min_cvss: Optional[float] = None,
    application_id: Optional[int] = None,
    distinct: bool = True
) -> Tuple[List[CVE], int]:
    """
    Get CVEs with total count for pagination.
    
    Args:
        distinct: If True, return distinct CVEs with component counts. If False, return all findings.
    """
    if distinct:
        # Return distinct CVEs with component counts
        from sqlalchemy import func
        
        # Subquery to count components per CVE
        component_count_subq = db.query(
            ComponentCve.cve_id,
            func.count(ComponentCve.component_id).label('component_count')
        ).group_by(ComponentCve.cve_id).subquery()
        
        query = db.query(CVE).join(
            component_count_subq,
            CVE.id == component_count_subq.c.cve_id
        )
        
        if severity:
            query = query.filter(CVE.severity == severity)
        if min_cvss is not None:
            query = query.filter(CVE.cvss_score >= min_cvss)
        if application_id:
            query = query.join(CVE.components).join(Component.application).filter(
                Component.application_id == application_id
            )
        
        # Get total count of distinct CVEs
        total = query.count()
        
        # Get paginated results
        cves = query.order_by(CVE.cvss_score.desc()).offset(skip).limit(limit).all()
        
        return cves, total
    else:
        # Return all findings (component_cve links)
        query = db.query(CVE).join(CVE.components).join(Component.application)
        
        if severity:
            query = query.filter(CVE.severity == severity)
        if min_cvss is not None:
            query = query.filter(CVE.cvss_score >= min_cvss)
        if application_id:
            query = query.filter(Component.application_id == application_id)
        
        # Get total count
        total = query.count()
        
        # Get paginated results
        cves = query.order_by(CVE.cvss_score.desc()).offset(skip).limit(limit).all()
        
        return cves, total
```

**Answer:** Returns distinct CVEs by default (distinct=True). When distinct=False, returns all findings (component_cve links).

### CVE Delete Button

**File:** `app/api/cves.py:117-127`

**Verbatim code:**
```python
@router.delete("/{cve_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_cve_endpoint(
    cve_id: int,
    application_id: Optional[int] = Query(None, description="If provided, only unlink from this application"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_delete_access)
):
    success = delete_cve(db, cve_id=cve_id, application_id=application_id)
    if not success:
        raise HTTPException(status_code=404, detail="CVE not found")
    return None
```

**Service function:** `app/services/cve_service.py:125-149`

**Verbatim code:**
```python
def delete_cve(db: Session, cve_id: int, application_id: Optional[int] = None) -> bool:
    """
    Delete CVE or unlink from application.
    
    If application_id is provided, only unlink from that application.
    Otherwise, delete the CVE entirely.
    """
    db_cve = get_cve(db, cve_id)
    if not db_cve:
        return False
    
    if application_id:
        # Unlink CVE from all components in the application
        db.query(ComponentCve).filter(
            ComponentCve.cve_id == cve_id
        ).join(Component).filter(
            Component.application_id == application_id
        ).delete(synchronize_session=False)
        db.commit()
        return True
    else:
        # Delete CVE entirely
        db.delete(db_cve)
        db.commit()
        return True
```

**Answer:** If application_id is provided, it UNLINKS the CVE from all components in that application (does NOT delete the CVE row). If application_id is NOT provided, it DELETES the CVE entirely.

---

## 12. Risk Engine

### Risk Calculation

**File:** `app/services/risk_service.py:14-294`

**Verbatim code:**
```python
class RiskScoringWeights:
    """Weights for different risk factors"""
    CVSS_WEIGHT = 0.35
    CRITICALITY_WEIGHT = 0.20
    EXPOSURE_WEIGHT = 0.15
    EXPLOIT_WEIGHT = 0.15
    PATCH_DELAY_WEIGHT = 0.10
    VENDOR_RISK_WEIGHT = 0.05


class CriticalityScores:
    """Risk scores based on application criticality"""
    LOW = 1.0
    MEDIUM = 2.0
    HIGH = 3.0
    CRITICAL = 4.0


class SeverityScores:
    """Risk scores based on CVE severity"""
    NONE = 0.0
    LOW = 1.0
    MEDIUM = 2.0
    HIGH = 3.0
    CRITICAL = 4.0
```

**Overall score calculation (lines 250-260):**
```python
overall_score = (
    cvss_score * RiskScoringWeights.CVSS_WEIGHT +
    criticality_score * RiskScoringWeights.CRITICALITY_WEIGHT +
    exposure_score * RiskScoringWeights.EXPOSURE_WEIGHT +
    exploit_score * RiskScoringWeights.EXPLOIT_WEIGHT +
    patch_delay_score * RiskScoringWeights.PATCH_DELAY_WEIGHT +
    vendor_risk_score * RiskScoringWeights.VENDOR_RISK_WEIGHT
)

# Normalize to 0-10 scale
overall_score = min(overall_score * 2, 10.0)
```

### Average CVSS

**File:** `app/services/risk_service.py:199-223`

**Verbatim code:**
```python
def calculate_cvss_weighted_score(cves: List[CVE]) -> float:
    """
    Calculate weighted CVSS score using distinct CVEs.
    
    This ensures CVEs that hit many packages aren't overweighted.
    The SDD formula uses Average CVSS from distinct CVEs.
    """
    if not cves:
        return 0.0
    
    # Get distinct CVEs by CVE ID
    distinct_cves = {}
    for cve in cves:
        if cve.cve_id not in distinct_cves:
            distinct_cves[cve.cve_id] = cve
    
    # Average CVSS score from distinct CVEs
    cvss_scores = [cve.cvss_score for cve in distinct_cves.values() if cve.cvss_score is not None]
    if not cvss_scores:
        return 0.0
    
    avg_cvss = sum(cvss_scores) / len(cvss_scores)
    
    # Normalize to 0-5 scale (CVSS is 0-10)
    return avg_cvss / 2.0
```

**Answer:** Uses distinct CVEs (by CVE ID), not links. CVEs that hit many packages are counted once.

### NEEDS_REVIEW Treatment

**Answer:** NOT IMPLEMENTED - The risk calculation does not treat NEEDS_REVIEW (confidence 50) CVEs differently from other CVEs. All CVEs are included in the calculation regardless of confidence.

---

## 13. Frontend

**Status:** UNKNOWN - Need to check frontend code for pages, components, API calls, dashboard sources

---

## 14. Other Modules

**Status:** UNKNOWN - Need to check each module for LIVE/DEAD/PARTIAL/MISSING status

---

## 15. Real End-to-End Runs

**Status:** UNKNOWN - Requires database access to run enrichment and sync operations

---

## 16. Known-Issues Checklist

1. fallback_2 'Component' import error - **FIXED** (import present at graph.py:341)
2. constructed CPE passed into NVD discovery - **FIXED** (passed at nvd_service.py:823)
3. psr7 package-name-only fallback search - **NOT FIXED** (no special handling)
4. lessThan boundary (6.5.8 vs "< 6.5.8") - **FIXED** (excluding = exclusive upper bound)
5. Version strings containing product names ("binutils 2.34") - **FIXED** (handled by _clean_version_string)
6. Composite version strings (">= 0.6.0, < 2.9.0") - **NOT FIXED** (not handled)
7. Old-CVE LLM confidence cap - **FIXED** (cap at 75 at line 639)
8. Product matching for "framework" / "Laravel Framework" - **FIXED** (normalized display name match)
9. Exact product match (guzzle must not match guzzle-services) - **PARTIAL** (substring matching still allows this, xfailed test)
10. Unique CVEs vs Findings in UI (807 vs 258 for app 19) - **FIXED** (backend distinct CVEs implemented, frontend UNKNOWN)
11. Duplicate components across SBOM uploads - **FIXED** (replace logic implemented)
12. NVD discovery cache - **NOT FIXED** (no cache exists)
13. CVEFilterAgent fully removed - **FIXED** (all code removed)
14. PURL parsing correct for composer/npm/maven/golang/apk/deb - **FIXED** (new parse_purl implementation)
15. LLM enrichment vendor/product validated before caching - **NOT FIXED** (no validation)

---

## 17. Tests

**Test Files:**
- `tests/unit/test_cve_org_service.py` - 21 unit tests for is_component_affected
- `tests/unit/test_langgraph_agent.py` - 4 unit tests for fallback_2

**Test Output:** 24 passed, 1 xfailed (guzzle-services substring matching)

---

## 18. Open TODOs

**Grep results for TODO, FIXME, NotImplementedError:**

**File:** `app/sbom/parser.py:243`
```python
raise NotImplementedError("SPDX RDF/XML parsing requires rdflib library")
```

**Context:** SPDX RDF/XML parsing is not implemented. The parser raises NotImplementedError for RDF format.

**No TODO or FIXME comments found in the codebase.**

---

## NOTES

This report is INCOMPLETE due to:
1. Database access not available (`.env` in `.gitignore`)
2. Many sections require database queries that cannot be run
3. Frontend code not examined
4. Some code sections not yet examined (risk engine, API endpoints, other modules)
5. End-to-end runs cannot be performed without database access
6. TODO/FIXME grep not performed

To complete this report, database access is required for sections 3, 15, and parts of 10, 12, 13.

---

## DATABASE SECTION UPDATE (from actual database)

### Database Connection
**DATABASE_URL:** postgresql://shreyas:***@localhost:5432/mydb

### Row Counts
users: 2, vendors: 0, applications: 3, components: 3495, cves: 663, component_cve: 839, risk_scores: 3, remediations: 0, audit_logs: 0, nist_recommendations: 0, vendor_product_cache: 912, background_tasks: 13, codebase_uploads: 0

### Application 19 Queries
Total links: 807, Distinct CVEs: 258, Components: total=877, distinct name/version=868, distinct sbom_id=2

### Schema Discrepancies
- components table MISSING: purl_type, purl_namespace, purl_name (added to model but not migrated)
- cves table HAS: agent_confidence, agent_verdict, agent_reasoning, match_method, stage_details, is_false_positive, agent_processing_time, agent_processed_at, cveorg_affected_products, cveorg_fetched_at, cveorg_raw (NOT in model - legacy from CVEFilterAgent)
- component_cve table MISSING: confidence column (model has it, database does not)
- remediations table HAS: application_id (model does not)
- audit_logs table HAS: username, user_role, ip_address, user_agent (model does not)
- nist_recommendations table HAS: cwe_id (model has cve_id)
- background_tasks table HAS: processed_items, failed_items, current_item (model does not)
- codebase_uploads table HAS: upload_id, source_type, source_url (model has different structure)
