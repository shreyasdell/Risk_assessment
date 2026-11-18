# Agent System

## Overview

The agent system provides AI-powered component enrichment and CVE verification capabilities.

## Components

### 1. LangGraph Enrichment Agent

**Location:** `app/agent/langgraph_agent/graph.py`

**Purpose:** Enrich components with NVD-specific metadata for accurate CVE discovery

**Agent Stages:**
1. **parse_purl** - Parse PURL to extract type, namespace, and name
2. **check_cache** - Check if PURL was previously enriched
3. **llm_resolve** - Use LLM to resolve vendor/product from PURL (cache miss only)
4. **validate_vendor_product** - Validate vendor/product against NVD CPE dictionary
5. **construct_cpe** - Construct CPE string from enriched data
6. **fallback_1** - Use existing CPE from component (error fallback)
7. **fallback_2** - Use ComponentNormalizer (error fallback)
8. **fallback_3** - Basic name + CPE_VENDOR_MAP (error fallback)
9. **update_component** - Write enriched fields to database

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

### 2. Component Normalizer

**Location:** `app/agent/normalizer/normalizer.py`

**Purpose:** Normalize component names and versions for better NVD matching

**Features:**
- Component name normalization
- Version cleaning (removes -r0, v prefix, etc.)
- CPE construction
- Vendor/product mapping

## Quick Start

### 1. Install dependencies
```bash
pip install packaging>=21.0 requests>=2.28.0 langgraph>=0.2.0
```

### 2. Run database migration
```bash
alembic upgrade head
```

### 3. Configure environment variables
Add to your `.env` file:
```bash
# Ollama settings
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:7b
OLLAMA_TIMEOUT=60
```

### 4. Start Ollama (if not already running)
```bash
# Pull the model
ollama pull qwen2.5:7b

# Start Ollama server
ollama serve
```

### 5. Test the agent
```bash
curl http://localhost:8000/api/agent/health
```

## Integration

The LangGraph agent is integrated into the SBOM upload workflow:

1. User uploads SBOM file
2. Components are extracted from SBOM
3. LangGraph agent enriches each component with CPE and search metadata
4. Enriched components are stored in database
5. NVD service uses enriched data for accurate CVE discovery

## CVE Verification

CVE verification is handled by the CVE.org client, not the agent system:

**Location:** `app/services/cve_org_service.py`

**Purpose:** Precise verification to confirm if candidate CVEs actually affect the specific component version

**Verification Steps:**
1. Fetch CVE data from CVE.org (with caching)
2. Product matching (name, PURL, CPE)
3. Version range validation
4. LLM fallback for old CVEs (predating ~2020)
5. Confidence scoring

## API Endpoints

- `GET /api/agent/health` - Check agent and Ollama health
- `POST /api/agent/normalize` - Normalize a component (uses ComponentNormalizer)
- `POST /components/normalize` - Normalize component using LangGraph agent

## Performance Targets

- LangGraph enrichment: ~2-8s per component (LLM calls)
- Parallel enrichment: 10 concurrent LLM calls
- CVE verification: ~1-2s per CVE (with caching)
- Parallel verification: 10 concurrent CVE.org requests

## Deprecated Components

### CVE Filter Agent (5-Stage Pipeline)

**Status:** ❌ REMOVED - Deleted in Ticket 6

**Why Removed:**
- Initialized in `NVDService.__init__` but never used in sync pipeline
- The actual pipeline uses `CVEOrgClient.is_component_affected()` directly
- The 5-stage agent was designed for filtering/display but was never integrated
- Zero functional impact - never executed in production
