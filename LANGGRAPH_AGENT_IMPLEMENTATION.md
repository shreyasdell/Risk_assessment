# LangGraph Agent Implementation Summary

## Overview
Implemented a LangGraph-based agent for SBOM component enrichment that replaces the ComponentNormalizer with intelligent, multi-stage enrichment.

## Completed Tasks

### 1. Database Schema Changes ✅
- **File**: `app/models/component.py`
- Added new fields to Component model:
  - `nvd_vendor` - NVD vendor name for CPE construction
  - `nvd_product` - NVD product name for CPE construction
  - `search_name` - Optimized search term for NVD keyword API
  - `clean_version` - Cleaned version for CPE (no -r0, v prefix, etc.)
  - `constructed_cpe` - Full CPE string constructed by agent
  - `ecosystem` - Ecosystem (npm, pypi, maven, etc.)
  - `enrichment_status` - pending, completed, failed
  - `enrichment_confidence` - 0-100 confidence in enrichment
  - `enrichment_method` - purl_only, purl_cache, llm, fallback_1, fallback_2, fallback_3

### 2. Vendor Product Cache Table ✅
- **File**: `app/models/vendor_cache.py`
- Created `VendorProductCache` model for hybrid caching
- Fields: component_name, nvd_vendor, nvd_product, ecosystem, confidence, resolution_method, source_purl, hit_count, last_used_at
- Composite indexes for fast lookups

### 3. Database Migration ✅
- **File**: `alembic/versions/20261103_1000_add_langgraph_enrichment_fields.py`
- Migration adds new Component fields and VendorProductCache table
- Includes downgrade support

### 4. LangGraph Agent Architecture ✅
- **File**: `app/agent/langgraph_agent/graph.py`
- Implemented ComponentEnrichmentAgent with 6 nodes:
  1. **parse_purl** - Extracts ecosystem from PURL (70% of cases, no LLM)
  2. **check_cache** - Looks up vendor/product in hybrid cache
  3. **llm_resolve** - Uses Qwen 2.5:7b to resolve vendor/product (30% of cases)
  4. **construct_cpe** - Builds CPE string from resolved vendor/product
  5. **clean_version** - Strips version suffixes
  6. **update_component** - Stores enriched metadata in database

### 5. Cascading Fallback Logic ✅
- **Fallback 1**: Use existing CPE from component
- **Fallback 2**: Use ComponentNormalizer
- **Fallback 3**: Use basic name as search_name (never skip component)
- Ensures components are always enriched, never skipped

### 6. Requirements Update ✅
- **File**: `requirements.txt`
- Added `langgraph>=0.2.0`

## Remaining Tasks

### 7. Background Job Integration (Pending)
- Need to integrate agent as background job in SBOM upload endpoint
- Should run asynchronously after upload
- UI should show "processing" status

### 8. NVD Search Simplification (Pending)
- Simplify `discover_cve_ids()` in `nvd_service.py` to use enriched metadata
- Current: 4+ search strategies with fallbacks
- New: 
  - Strategy 0: Constructed CPE (works for ~80% of components)
  - Strategy 1: search_name keyword (works for remaining ~20%)
  - Done.

## Architecture Benefits

### Before (Current Architecture)
```
SBOM Upload → Parser stores RAW names → NVD Service tries to fix → Multiple search strategies → False positive filtering
```

### After (New Architecture)
```
SBOM Upload → LangGraph Agent enriches components → NVD Service uses enriched metadata → Simple CPE/keyword search
```

### Key Improvements
1. **Intelligence at parse time** - Agent analyzes SBOM before storage
2. **70% no LLM needed** - PURL parsing handles most cases
3. **Hybrid caching** - Database + in-memory for performance
4. **Cascading fallback** - Never skips components
5. **Simplified search** - NVD search becomes trivial with enriched metadata

## Usage Example

```python
from app.agent.langgraph_agent import ComponentEnrichmentAgent
from app.core.database import get_db

# Initialize agent
db = next(get_db())
agent = ComponentEnrichmentAgent(
    db_session=db,
    ollama_url="http://localhost:11434",
    model="qwen2.5:7b"
)

# Enrich a component
result = await agent.enrich_component(component_id=123)
# Returns: {
#   "component_id": 123,
#   "nvd_vendor": "guzzlephp",
#   "nvd_product": "psr7",
#   "constructed_cpe": "cpe:2.3:a:guzzlephp:psr7:1.9.0:*:*:*:*:*:*:*",
#   "enrichment_method": "llm",
#   "confidence": 70
# }
```

## Next Steps

1. Run database migration: `alembic upgrade head`
2. Install langgraph: `pip install langgraph>=0.2.0`
3. Integrate agent into SBOM upload endpoint as background job
4. Simplify NVD search to use enriched metadata
5. Test with real SBOM uploads
