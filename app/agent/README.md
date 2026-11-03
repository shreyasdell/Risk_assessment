# CVE Filter Agent

## Overview

The CVE Filter Agent eliminates false positives from NVD vulnerability scanning by running each CVE through a multi-stage analysis pipeline.

## Architecture

The agent uses a 5-stage pipeline:

| Stage | Name | Type | Speed | Purpose |
|-------|------|------|-------|---------|
| 1 | CPE Matcher | Deterministic | ~1ms | Match CVE's CPE product against component |
| 2 | PURL Resolver | Deterministic | ~1ms | Detect ecosystem mismatches |
| 3 | Version Validator | Deterministic | ~1ms | Check version range |
| 4 | LLM Reasoner | AI (Qwen) | ~2-8s | Contextual analysis for ambiguous cases |
| 5 | Confidence Aggregator | Deterministic | <1ms | Final decision |

## Quick Start

### 1. Install dependencies
```bash
pip install packaging>=21.0 requests>=2.28.0
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

# Agent settings
CVE_DISPLAY_THRESHOLD=50
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

The agent is already integrated into the NVD service. When you sync CVEs for a component:

1. NVD API fetches raw CVEs
2. Agent filters them through the 5-stage pipeline
3. Only relevant CVEs are saved to the database with agent metadata

## Test Case

**Component:** npm package "carbon" version 2.1.1
**CVE:** CVE-2025-37881 (Linux kernel vulnerability)
**Expected:** REJECTED at Stage 1 (CPE mismatch)

The CVE description mentions "Lenovo ThinkPad X1 Carbon" (hardware), but the npm package "carbon" is completely unrelated. The agent correctly rejects this false positive.

## API Endpoints

- `GET /api/agent/health` - Check agent and Ollama health
- `POST /api/cves/{id}/false-positive` - Mark CVE as false positive (user override)
- `POST /api/cves/{id}/undo-false-positive` - Undo false positive marking

## Performance Targets

- ~60% of CVEs rejected at Stage 1 in < 5ms
- ~90% of CVEs resolved deterministically in < 20ms
- Only ~10% require LLM (2-8 seconds each)
- Total pipeline for 50 CVEs: < 30 seconds
