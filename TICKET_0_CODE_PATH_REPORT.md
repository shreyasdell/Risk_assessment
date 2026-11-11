# Ticket 0: Live Code Path Verification Report

## Executive Summary

This report traces every reference to `self.cve_agent`, `CVEFilterAgent`, `CVE_DISPLAY_THRESHOLD`, `OLLAMA_*`, and the old-CVE LLM function in `cve_org_service.py`. It identifies which code paths are live (actively used) and which are dead (initialized but never called).

---

## 1. CVEFilterAgent References

### 1.1 Definition and Initialization

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/agent/cve_filter_agent.py` | 36 | Live | Class definition |
| `app/agent/cve_filter_agent.py` | 41 | Live | `__init__` method |
| `app/agent/cve_filter_agent.py` | 87 | Live | Initialization log message |

### 1.2 Import Statements

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/agent/__init__.py` | 1 | Live | Export from package |
| `app/agent/__init__.py` | 3 | Live | `__all__` export |
| `app/agent/router.py` | 14 | Live | Import for API router |
| `app/services/nvd_service.py` | 22 | **DEAD** | Imported but never used |

### 1.3 Usage in NVDService

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/services/nvd_service.py` | 45 | **DEAD** | `self.cve_agent = CVEFilterAgent(...)` - Initialized but never used |
| `app/services/nvd_service.py` | 46-49 | **DEAD** | OLLAMA_* settings passed to dead agent |

**Analysis:** The `CVEFilterAgent` is initialized in `NVDService.__init__` (line 45) but is never referenced anywhere in the codebase. The agent instance is created and stored in `self.cve_agent` but no method ever calls it.

### 1.4 Usage in API Router

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/agent/router.py` | 31 | Live | Singleton instance variable |
| `app/agent/router.py` | 34-44 | Live | `get_agent()` function - creates singleton |
| `app/agent/router.py` | 56 | Live | Used in `/health` endpoint |
| `app/agent/router.py` | 59 | Live | Used to check Ollama health |

**Analysis:** The API router uses `CVEFilterAgent` for health checks only. The agent is NOT used for CVE filtering in the sync pipeline.

### 1.5 Usage in Tests

| Location | Status | Details |
|----------|--------|---------|
| `tests/` directory | **DEAD** | No references to `CVEFilterAgent` in any test files |

**Analysis:** No tests exist for the 5-stage CVEFilterAgent pipeline.

---

## 2. self.cve_agent References

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/services/nvd_service.py` | 45 | **DEAD** | `self.cve_agent = CVEFilterAgent(...)` - Never read or called |

**Analysis:** `self.cve_agent` is assigned once in `__init__` and never accessed again. This is dead code.

---

## 3. CVE_DISPLAY_THRESHOLD References

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/core/config.py` | 16 | Live | Configuration setting definition |
| `.env.example` | 10 | Live | Environment variable example |
| `app/agent/README.md` | 40 | Live | Documentation |
| `app/services/nvd_service.py` | 49 | **DEAD** | Passed to dead agent |
| `app/agent/router.py` | 42 | Live | Passed to agent in API router |

**Analysis:** The setting is live (used in API router) but the reference in `nvd_service.py` is dead because the agent is never used.

---

## 4. OLLAMA_* References

### 4.1 OLLAMA_URL

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/core/config.py` | 13 | Live | Configuration setting |
| `.env.example` | 7 | Live | Environment variable example |
| `app/agent/README.md` | 35 | Live | Documentation |
| `app/services/nvd_service.py` | 46 | **DEAD** | Passed to dead agent |
| `app/services/sbom_service.py` | 93 | Live | Used by LangGraph agent |
| `app/agent/router.py` | 39, 64 | Live | Used by API router |

### 4.2 OLLAMA_MODEL

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/core/config.py` | 14 | Live | Configuration setting |
| `.env.example` | 8 | Live | Environment variable example |
| `app/agent/README.md` | 36 | Live | Documentation |
| `app/services/nvd_service.py` | 47 | **DEAD** | Passed to dead agent |
| `app/services/sbom_service.py` | 94 | Live | Used by LangGraph agent |
| `app/agent/router.py` | 40, 65 | Live | Used by API router |

### 4.3 OLLAMA_TIMEOUT

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/core/config.py` | 15 | Live | Configuration setting |
| `app/services/nvd_service.py` | 48 | **DEAD** | Passed to dead agent |
| `app/services/sbom_service.py` | 95 | Live | Used by LangGraph agent |
| `app/agent/router.py` | 41 | Live | Used by API router |

**Analysis:** OLLAMA_* settings are live for the LangGraph agent (in `sbom_service.py`) and the API router, but the references in `nvd_service.py` are dead because the CVEFilterAgent is never used.

---

## 5. Old-CVE LLM Function (_llm_analyze_old_cve)

### 5.1 Definition

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/services/cve_org_service.py` | 565 | Live | Function definition |

### 5.2 Usage

| File | Line | Status | Details |
|------|------|--------|---------|
| `app/services/cve_org_service.py` | 258 | Live | Called from `is_component_affected` when all products are "n/a" |

**Analysis:** This is a LIVE code path. When CVE.org returns affected products with "n/a" (old CVEs predating ~2020), the system calls `_llm_analyze_old_cve` to use the LLM to analyze the CVE description.

**Important:** This LLM path has NO confidence cap (line 634 in `cve_org_service.py`), unlike the CVEFilterAgent's LLM Reasoner which is capped at 75.

---

## 6. Exact Call Chain from sync_component_cves to NVD Request

### 6.1 Entry Points

The `sync_component_cves` function is called from:

1. **API Route:** `app/api/cves.py` line 145 - POST `/cves/sync/{component_id}`
2. **API Route:** `app/api/cves.py` line 187 - POST `/cves/sync-all`
3. **Background Job:** `app/services/background_sync_service.py` line 126
4. **E2E Test:** `tests/e2e/test_components.py` line 63

### 6.2 Call Chain

```
sync_component_cves (nvd_service.py:768)
  ↓
  Check if component has enriched data (lines 785-816)
    - If component.constructed_cpe and component.search_name exist:
      - Use LangGraph agent enriched data
      - constructed_cpe = component.constructed_cpe
      - search_name = component.search_name
    - Else:
      - Fallback to ComponentNormalizer
      - constructed_cpe = None
      - search_name = component_normalizer.get_search_name(display_name)
  ↓
  discover_cve_ids (nvd_service.py:819-825)
    - Parameters passed:
      - component_name=search_name
      - component_version=clean_version
      - purl=component.purl
      - constructed_cpe=constructed_cpe  ← YES, CPE is passed!
      - search_name=search_name
  ↓
  discover_cve_ids implementation (nvd_service.py:503-552)
    - Strategy 0: If constructed_cpe exists (line 504)
      - Make NVD API request with cpeName parameter
      - Query: {"cpeName": constructed_cpe, "resultsPerPage": 100}
    - Strategy 1: If search_name exists and no results yet (line 518)
      - Make NVD API request with keywordSearch parameter
      - Query: {"keywordSearch": search_name, "resultsPerPage": 100}
    - Fallback: If no agent data (line 537)
      - Build CPE using _build_cpe
      - Make NVD API request with cpeName parameter
      - Generate keyword search queries
  ↓
  _make_request (nvd_service.py) - Makes HTTP request to NVD API
  ↓
  Returns list of CVE IDs
  ↓
  Phase 2: CVE.org Verification (nvd_service.py:845-872)
    - For each CVE ID:
      - Call cache_service.get_affected_products
      - Call cve_org_client.is_component_affected
        - If all products are "n/a": Call _llm_analyze_old_cve (LLM path)
        - Else: Use deterministic product/version matching
  ↓
  Store verified CVEs in database
```

### 6.3 CPE Passing Status

**YES, CPE is passed to discover_cve_ids.**

- **Location:** `nvd_service.py` line 823
- **Parameter:** `constructed_cpe=constructed_cpe`
- **Usage:** `discover_cve_ids` checks `if constructed_cpe:` at line 504 and uses it for NVD CPE search

**Why logs show "CPE: none":**
- Old components (created before LangGraph agent deployment) have `constructed_cpe = None` in the database
- The code DOES pass the CPE, but it's `None` for unenriched components
- After Ticket 3 (backfill enrichment), new logs should show CPE values

---

## 7. Summary of Live vs Dead Code

### 7.1 Dead Code (Should be removed)

| Component | Location | Reason |
|-----------|----------|--------|
| `self.cve_agent` | `nvd_service.py:45` | Initialized but never used |
| CVEFilterAgent import | `nvd_service.py:22` | Imported but never used |
| CVE_DISPLAY_THRESHOLD in nvd_service | `nvd_service.py:49` | Passed to dead agent |
| OLLAMA_* in nvd_service | `nvd_service.py:46-48` | Passed to dead agent |
| CVEFilterAgent 5-stage pipeline | `app/agent/cve_filter_agent.py` | Never called in sync pipeline |
| LLM Reasoner (75 cap) | `app/agent/stages/llm_reasoner.py` | Part of dead agent |

### 7.2 Live Code (Actively used)

| Component | Location | Usage |
|-----------|----------|-------|
| CVEFilterAgent | `app/agent/router.py` | Health check endpoint only |
| CVE_DISPLAY_THRESHOLD | `app/agent/router.py` | Health check endpoint |
| OLLAMA_URL | `sbom_service.py:93` | LangGraph agent for component enrichment |
| OLLAMA_MODEL | `sbom_service.py:94` | LangGraph agent for component enrichment |
| OLLAMA_TIMEOUT | `sbom_service.py:95` | LangGraph agent for component enrichment |
| _llm_analyze_old_cve | `cve_org_service.py:565` | Analyzes old CVEs with "n/a" products |
| LangGraph agent | `app/agent/langgraph_agent/` | Component enrichment at SBOM upload |

### 7.3 Critical Finding

**The 5-stage CVEFilterAgent is completely dead code in the CVE sync pipeline.**

The actual pipeline is:
1. LangGraph agent (enriches components at SBOM upload)
2. NVD discovery (CPE search OR keyword search)
3. CVE.org verification (deterministic matching OR LLM fallback for old CVEs)
4. Storage

The CVEFilterAgent with its 5-stage pipeline (CPE matcher, PURL resolver, version validator, LLM reasoner, confidence aggregator) is never called during CVE sync. It only exists for the API health check endpoint.

---

## 8. Recommendations

### Option A: Delete Dead Code (Recommended)

Delete the following:
- `app/agent/cve_filter_agent.py` (entire file)
- `app/agent/stages/` directory (entire directory)
- `app/agent/router.py` (or keep only if health check is needed)
- CVEFilterAgent import and initialization in `nvd_service.py`
- CVE_DISPLAY_THRESHOLD, OLLAMA_* references in `nvd_service.py`

### Option B: Wire In CVEFilterAgent (Not Recommended)

Integrate the 5-stage agent after CVE.org verification. However, this would:
- Add complexity to the pipeline
- Duplicate functionality (CVE.org already does product/version matching)
- Require extensive testing
- Likely not improve accuracy over current deterministic approach

---

## 9. Confidence Sources

| Source | Location | Confidence Range | Notes |
|--------|----------|------------------|-------|
| CVE.org deterministic (CPE match + version in range) | `cve_org_service.py:344` | 95 | High confidence |
| CVE.org deterministic (version out of range) | `cve_org_service.py:353` | 90 | High confidence |
| CVE.org deterministic (no product match) | `cve_org_service.py:374` | 85 | High confidence |
| CVE.org deterministic (product match, no version data) | `cve_org_service.py:362` | 60 | Medium confidence |
| CVE.org deterministic (no upper bound) | `cve_org_service.py:326` | 50 | Low confidence |
| **LLM old-CVE analysis** | `cve_org_service.py:634` | **UNCAPPED** | Can return 95+ (BUG) |
| CVEFilterAgent LLM Reasoner | `llm_reasoner.py:157` | Capped at 75 | Dead code |

---

## 10. Acceptance Criteria Verification

- ✅ Every claim backed by file and line reference
- ✅ Exact call chain from sync_component_cves to NVD request documented
- ✅ CPE passing status confirmed (YES, it is passed)
- ✅ Live vs dead code clearly identified
- ✅ API routes, background jobs, tests, and scripts covered
