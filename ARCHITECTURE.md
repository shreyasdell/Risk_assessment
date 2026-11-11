# Vulnerability Risk Assessment Tool - Architecture Documentation

## Overview

This document describes the current production architecture of the Vulnerability Risk Assessment Tool, focusing on the CVE (Common Vulnerabilities and Exposures) discovery and verification pipeline.

## System Architecture

### High-Level Pipeline

```
SBOM Upload
    ↓
Component Extraction
    ↓
LangGraph Enrichment (Agent)
    ↓
Component Normalization
    ↓
CPE Construction
    ↓
NVD Discovery
    ├─ CPE Search (constructed_cpe)
    ├─ Search Name Search (search_name)
    └─ Keyword Fallback
    ↓
Candidate CVEs
    ↓
CVE.org Verification
    ↓
Version Range Validation
    ↓
Confidence Scoring
    ↓
CVE Storage
    ↓
Risk Engine
```

## Detailed Pipeline Documentation

### Phase 1: SBOM Upload and Component Extraction

**Location:** `app/sbom/parser.py`, `app/services/sbom_service.py`

1. User uploads SBOM file (CycloneDX, SPDX, or other formats)
2. SBOMParser extracts components from the SBOM
3. Components are stored in database with:
   - `name`, `version`, `purl`
   - `application_id`, `sbom_id`
   - Initial enrichment status: `pending`

### Phase 2: LangGraph Enrichment (Agent)

**Location:** `app/agent/langgraph_agent/graph.py`

**Purpose:** Enrich components with NVD-specific metadata for accurate CVE discovery

**Agent Stages:**
1. **purl_cache** - Check if PURL was previously enriched (confidence: 80-90)
2. **llm** - Use LLM to resolve vendor/product from PURL (confidence: 70)
3. **fallback_1** - Use existing CPE from component (confidence: 60)
4. **fallback_2** - Use ComponentNormalizer (confidence: 40)
5. **fallback_3** - Basic name + CPE_VENDOR_MAP (confidence: 20-30)

**Enriched Fields:**
- `nvd_vendor` - NVD vendor name for CPE construction
- `nvd_product` - NVD product name for CPE construction
- `search_name` - Optimized search term for NVD keyword API
- `clean_version` - Cleaned version for CPE (no -r0, v prefix, etc.)
- `constructed_cpe` - Full CPE string constructed by agent
- `ecosystem` - Ecosystem (npm, pypi, maven, etc.)
- `enrichment_status` - pending, completed, failed
- `enrichment_confidence` - 0-100 confidence in enrichment
- `enrichment_method` - purl_only, purl_cache, llm, fallback_1, fallback_2, fallback_3

**Parallel Processing:** 10 concurrent LLM calls for performance

### Phase 3: NVD Discovery

**Location:** `app/services/nvd_service.py` - `discover_cve_ids()` method

**Purpose:** Fast, broad search to find candidate CVE IDs that *might* affect the component

**Rate Limiting:** 50 requests per 30 seconds (with API key), 5 per 30 seconds (without)

**Discovery Strategies:**

#### Strategy 0: CPE Search (Most Accurate)
- **Trigger:** Component has `constructed_cpe` from LangGraph agent
- **Query:** `{"cpeName": "cpe:2.3:a:oracle:jdk:11.0.21:*:*:*:*:*:*:*"}`
- **Accuracy:** Highest - CPE is a standardized identifier
- **Log:** `[NVD Discovery] Using CPE search path with agent-constructed CPE: cpe:2.3:a:...`

#### Strategy 1: Search Name Search
- **Trigger:** Component has `search_name` from LangGraph agent
- **Query:** `{"keywordSearch": "oracle jdk"}`
- **Accuracy:** Medium - broader but less precise than CPE
- **Log:** `[NVD Discovery] Using keyword search path with agent search name: oracle jdk`
- **Merging:** Results are merged with CPE search results

#### Fallback: Original Search (No Agent Data)
- **Trigger:** Component has no agent data (old components before agent deployment)
- **Query:** Build CPE using `_build_cpe()` + generate keyword queries using `_generate_search_queries()`
- **Accuracy:** Lowest - relies on heuristics
- **Log:** `[NVD Discovery] Using fallback search path (no agent data)`

**Output:** List of CVE IDs (e.g., `["CVE-2024-12345", "CVE-2023-67890"]`)

### Phase 4: CVE.org Verification

**Location:** `app/services/cve_org_service.py` - `is_component_affected()` method

**Purpose:** Precise verification to confirm if candidate CVEs actually affect the specific component version

**Rate Limiting:** ~5 req/s (unspecified by CVE.org)

**Caching Layer:** `app/services/cache_service.py` - `CVECacheService`
- Checks `cve_cache` table before calling CVE.org API
- Stores CVE.org responses with timestamp
- Dramatically reduces API calls
- Parallel verification with 10 concurrent requests

**Verification Steps:**

#### Step 1: Fetch CVE Data from CVE.org
- Check cache first
- If cache miss, call CVE.org API to get structured affected products data
- Cache is stored in `cve_cache` table in database

#### Step 2: Product Matching
- Iterates through `affected_products` from CVE.org
- Checks if component name matches product name
- **Matching Logic:**
  - Direct name match (exact match)
  - PURL match (word boundary, not substring)
  - CPE match (normalized names)
  - **Vendor/package format:** Matches full name, package part, and normalized display names
    - Example: `laravel/framework` matches product `framework` or `Laravel Framework`
    - Example: `laravel/laravel` (skeleton) does NOT match `framework`

#### Step 3: Version Range Validation
- If product matches, checks if component version is in affected range
- Uses `packaging.version.Version` for semantic version comparison
- **Handles:**
  - `lessThan` (excluding upper bound)
  - `lessThanOrEqual` (including upper bound)
  - Missing upper bounds (NEEDS_REVIEW)
  - Unparseable versions
  - Product names inside versions (e.g., "binutils 2.34")

#### Step 4: LLM Fallback for Old CVEs
- **Trigger:** All products are "n/a" (CVEs predating ~2020)
- **Location:** `_llm_analyze_old_cve()` method
- **LLM Prompt:** Extracts product, affected range, and determines if component is affected
- **Confidence Cap:** 75 (named constant `MAX_LLM_CONFIDENCE`)
- **Version Comparison:** LLM extracts range as JSON, code compares with packaging library
- **NEEDS_REVIEW:** If LLM can't determine version range, returns NEEDS_REVIEW instead of rejecting
- **Hard Rejection:** Only when LLM says product is different

**Output:** Tuple of `(is_affected: bool, confidence: int, reason: str)`

### Phase 5: Confidence Scoring

**Location:** `app/services/cve_org_service.py` - Confidence constants

**Confidence Levels and Sources:**

| Confidence | Source | Description |
|------------|--------|-------------|
| 95 | `CONFIDENCE_CPE_MATCH_VERSION_IN_RANGE` | CPE match + version in range (highest confidence) |
| 90 | `CONFIDENCE_CPE_MATCH_VERSION_OUT_OF_RANGE` | CPE match + version out of range |
| 85 | `CONFIDENCE_NO_PRODUCT_MATCH` | No product match |
| 60 | `CONFIDENCE_PRODUCT_MATCH_NO_VERSION_DATA` | Product match + no version data |
| 50 | `CONFIDENCE_NO_UPPER_BOUND` | Product match + no upper bound (NEEDS_REVIEW) |
| 25 | `CONFIDENCE_LLM_FAILED` | LLM analysis failed |
| 75 | `MAX_LLM_CONFIDENCE` | Maximum LLM confidence (capped) |

**Confidence Source Tags in Logs:**
- `[cve_org_deterministic]` - Deterministic version matching
- `[cve_org_no_upper_bound]` - Missing upper bound
- `[llm_old_cve]` - LLM analysis of old CVEs

**Filtering:** CVEs with confidence < 50 are filtered out during sync

### Phase 6: CVE Storage

**Location:** `app/services/nvd_service.py` - `verify_cve()` method

**Storage Logic:**
1. Check if CVE already exists in database
2. If exists, update CVSS data if needed
3. If not exists, create new CVE record
4. Link CVE to component via `component_cve` table
5. **CVSS Fallback:** If CVE.org doesn't have CVSS, fetch from NVD automatically

**CVSS Fetching Priority:**
1. CVE.org CVSS (primary source)
2. NVD CVSS (automatic fallback)
3. Existing CVSS (if NVD fetch fails)

### Phase 7: Risk Engine

**Location:** `app/services/risk_service.py`

**Risk Score Calculation:**
- **Average CVSS:** Computed from **distinct CVEs** (not links) to avoid overweighting CVEs that hit many packages
- **Formula:** `Average CVSS = sum(distinct_cvss_scores) / count(distinct_cvss)`
- **Components:** CVEs that hit many packages are counted once in risk calculation

**Risk Factors:**
- CVSS Weight: 35%
- Criticality Weight: 20%
- Exposure Weight: 15%
- Exploit Weight: 15%
- Patch Delay Weight: 10%
- Vendor Risk Weight: 5%

## NVD vs CVE.org Roles

### NVD (National Vulnerability Database)

**Purpose:** Discovery (find candidate CVEs)

**Characteristics:**
- Fast, broad search
- Returns CVE IDs only (minimal metadata)
- No caching (always fresh)
- Rate limited: 50 req/30s (with key), 5 req/30s (without)
- Used in Phase 1 of pipeline

**Why Required:**
- Broad coverage of CVEs
- Fast keyword and CPE search
- Good for initial discovery

### CVE.org (MITRE)

**Purpose:** Verification (confirm actual impact)

**Characteristics:**
- Precise verification with structured data
- Returns affected products, version ranges, CPEs
- Has caching layer (reduces API calls)
- Rate limited: ~5 req/s
- Used in Phase 2 of pipeline

**Why Required:**
- Structured affected products data
- Version range validation
- Product name matching
- More accurate than NVD for verification

**Why Both Are Required:**
- NVD is fast for discovery but lacks precise version data
- CVE.org is slower but provides accurate verification
- Combination provides both speed and accuracy

## Deprecated Components

### CVEFilterAgent (5-Stage Pipeline)

**Status:** ❌ REMOVED - Deleted in Ticket 6

**Why Removed:**
- Initialized in `NVDService.__init__` but never used in sync pipeline
- The actual pipeline uses `CVEOrgClient.is_component_affected()` directly
- The 5-stage agent was designed for filtering/display but was never integrated
- Zero functional impact - never executed in production

**Files Deleted:**
- `app/agent/cve_filter_agent.py` (381 lines)
- `app/agent/stages/cpe_matcher.py`
- `app/agent/stages/purl_resolver.py`
- `app/agent/stages/version_validator.py`
- `app/agent/stages/llm_reasoner.py`
- `app/agent/stages/confidence_aggregator.py`
- `app/agent/stages/__init__.py`

**Configuration Removed:**
- `CVE_DISPLAY_THRESHOLD` from `app/core/config.py`
- `CVE_DISPLAY_THRESHOLD` from `.env.example`

**Configuration Retained:**
- `OLLAMA_URL` - Used by LangGraph agent for enrichment
- `OLLAMA_MODEL` - Used by LangGraph agent for enrichment
- `OLLAMA_TIMEOUT` - Used by LangGraph agent for enrichment

**Router Changes:**
- Health check endpoint now checks Ollama directly instead of through CVEFilterAgent
- False positive marking endpoints retained (they don't use the agent's filtering logic)

## Data Flow Diagram

```
┌─────────────┐
│ SBOM Upload │
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│ Component       │
│ Extraction      │
└──────┬───────────┘
       │
       ▼
┌──────────────────┐
│ LangGraph Agent  │◄─────┐
│ (Enrichment)     │      │
└──────┬───────────┘      │
       │                  │
       │ constructed_cpe  │
       │ search_name       │
       ▼                  │
┌──────────────────┐      │
│ NVD Discovery    │      │
│ - CPE Search     │      │
│ - Keyword Search │      │
│ - Fallback       │      │
└──────┬───────────┘      │
       │                  │
       │ CVE IDs          │
       ▼                  │
┌──────────────────┐      │
│ CVE.org          │      │
│ Verification     │      │
│ - Product Match  │      │
│ - Version Check  │      │
│ - LLM Fallback   │      │
└──────┬───────────┘      │
       │                  │
       │ is_affected      │
       │ confidence        │
       ▼                  │
┌──────────────────┐      │
│ CVE Storage      │      │
│ - Create/Update  │      │
│ - Link to Comp   │      │
└──────┬───────────┘      │
       │                  │
       ▼                  │
┌──────────────────┐      │
│ Risk Engine      │      │
│ - Calculate Score│      │
└──────────────────┘      │
                          │
                          └─── Ollama (LLM for enrichment)
```

## Sequence Diagram: CVE Sync

```
User          SBOM Service    LangGraph Agent    NVD Service    CVE.org    Database
 │                 │                  │               │            │           │
 │ Upload SBOM     │                  │               │            │           │
 ├─────────────────>│                  │               │            │           │
 │                 │ Parse Components  │               │            │           │
 │                 ├──────────────────>│               │            │           │
 │                 │                  │               │            │           │
 │                 │                  │ Enrich        │            │           │
 │                 │                  ├──────────────>│            │           │
 │                 │                  │               │            │           │
 │                 │                  │ constructed_cpe│            │           │
 │                 │                  │ search_name   │            │           │
 │                 │<─────────────────┤               │            │           │
 │                 │                  │               │            │           │
 │                 │ Store Components  │               │            │           │
 │                 ├───────────────────────────────────>│            │           │
 │                 │                  │               │            │           │
 │                 │                  │               │            │           │
 │                 │ Sync CVEs        │               │            │           │
 │                 ├──────────────────>│               │            │           │
 │                 │                  │               │            │           │
 │                 │                  │ CPE Search    │            │           │
 │                 │                  ├──────────────>│            │           │
 │                 │                  │               │            │           │
 │                 │                  │ CVE IDs       │            │           │
 │                 │                  │<──────────────┤            │           │
 │                 │                  │               │            │           │
 │                 │                  │               │ Verify    │           │
 │                 │                  ├────────────────────────────>│           │
 │                 │                  │               │            │           │
 │                 │                  │               │ Affected?  │           │
 │                 │                  │               │<────────────│           │
 │                 │                  │               │            │           │
 │                 │                  │               │            │           │
 │                 │                  │               │            │ Store CVE │
 │                 │                  ├────────────────────────────────────────>│
 │                 │                  │               │            │           │
 │                 │                  │               │            │           │
 │                 │<─────────────────┤               │            │           │
 │                 │                  │               │            │           │
 │                 │                  │               │            │           │
 │                 │ Calculate Risk   │               │            │           │
 │                 ├──────────────────>│               │            │           │
 │                 │                  │               │            │           │
 │                 │<─────────────────┤               │            │           │
 │                 │                  │               │            │           │
```

## Developer Onboarding

### Adding New CVE Discovery Sources

To add a new vulnerability feed (e.g., GHSA, OSV):

1. Create a new service in `app/services/` (e.g., `ghsa_service.py`)
2. Implement discovery method similar to `discover_cve_ids()` in NVD service
3. Add verification logic or reuse CVE.org verification
4. Update `sync_component_cves()` to call new service
5. Add tests in `tests/unit/`
6. Document the new source in this architecture file

### Modifying CVE Matching Logic

**Version Matching:** Edit `app/services/cve_org_service.py` - `_check_version_in_range()` method

**Product Matching:** Edit `app/services/cve_org_service.py` - `is_component_affected()` method

**Confidence Levels:** Update constants in `CVEOrgClient` class

**Discovery Paths:** Edit `app/services/nvd_service.py` - `discover_cve_ids()` method

### Testing

**Unit Tests:** `tests/unit/test_cve_org_service.py` - Tests for `is_component_affected()`

**Integration Tests:** `tests/integration/` - End-to-end tests for sync pipeline

**Run Tests:**
```bash
pytest tests/unit/test_cve_org_service.py -v
pytest tests/integration/ -v
```

## Current-State Architecture

### Active Components

| Component | Status | Location | Purpose |
|-----------|--------|----------|---------|
| LangGraph Agent | ✅ Active | `app/agent/langgraph_agent/` | Component enrichment |
| NVD Service | ✅ Active | `app/services/nvd_service.py` | CVE discovery |
| CVE.org Client | ✅ Active | `app/services/cve_org_service.py` | CVE verification |
| CVE Cache Service | ✅ Active | `app/services/cache_service.py` | CVE.org caching |
| Risk Service | ✅ Active | `app/services/risk_service.py` | Risk score calculation |

### Deprecated Components

| Component | Status | Location | Reason |
|-----------|--------|----------|--------|
| CVEFilterAgent | ❌ Removed | Deleted in Ticket 6 | Never used in sync pipeline |
| LLM Reasoner (5-stage) | ❌ Removed | Deleted in Ticket 6 | Part of unused CVEFilterAgent |
| CPE Matcher (5-stage) | ❌ Removed | Deleted in Ticket 6 | Part of unused CVEFilterAgent |
| PURL Resolver (5-stage) | ❌ Removed | Deleted in Ticket 6 | Part of unused CVEFilterAgent |
| Version Validator (5-stage) | ❌ Removed | Deleted in Ticket 6 | Part of unused CVEFilterAgent |
| Confidence Aggregator (5-stage) | ❌ Removed | Deleted in Ticket 6 | Part of unused CVEFilterAgent |

### Settings

**Active Settings:**
- `OLLAMA_URL` - Used by LangGraph agent for enrichment
- `OLLAMA_MODEL` - Used by LangGraph agent for enrichment
- `OLLAMA_TIMEOUT` - Used by LangGraph agent for enrichment

**Removed Settings:**
- `CVE_DISPLAY_THRESHOLD` - Removed in Ticket 6 (was only used by dead CVEFilterAgent)

## Performance Optimizations

1. **Parallel Enrichment:** 10 concurrent LLM calls in LangGraph agent
2. **Parallel CVE Verification:** 10 concurrent CVE.org requests
3. **CVE.org Caching:** Reduces API calls by caching responses
4. **Distinct CVE Risk Calculation:** Avoids counting same CVE multiple times

## Security Considerations

1. **LLM Confidence Capping:** LLM analysis capped at 75 to prevent probabilistic decisions from overriding deterministic ones
2. **NEEDS_REVIEW:** Uncertain cases marked for manual review instead of automatic rejection
3. **CVSS Fallback:** Automatically fetches CVSS from NVD if CVE.org lacks it
4. **Data Source Disclaimer:** UI displays disclaimer about data sources (CVE.org for verification, NVD for CVSS)

## Future Enhancements

As documented in the SDD:
- Additional vulnerability feeds (GHSA, OSV)
- Enhanced version range parsing
- Improved product name normalization
- Real-time CVE monitoring
- Automated patch recommendations

## References

- **SDD (Software Design Document):** Original system design
- **TICKET_0_CODE_PATH_REPORT.md:** Detailed code path analysis
- **TICKET_4 Implementation:** LLM confidence capping and version comparison
- **TICKET_5 Implementation:** Vendor/package product matching
- **TICKET_8 Implementation:** Distinct CVE risk calculation
- **TICKET_9 Implementation:** Logging and confidence source tagging
