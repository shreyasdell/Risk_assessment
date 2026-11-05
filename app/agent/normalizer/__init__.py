"""
Component Name Normalization & Vendor Identification Agent

Normalizes component names from different ecosystems (Go, Maven, npm, etc.)
into canonical NVD-searchable names and identifies vendor organizations.

Three-tier approach:
- Tier 1: Deterministic PURL parsing (70% of cases, ~5ms)
- Tier 2: Static lookup table (top 200 common packages, ~1ms)
- Tier 3: LLM via Ollama (ambiguous cases, cached, ~2s first call)
"""

from app.agent.normalizer.normalizer import ComponentNormalizer

__all__ = ["ComponentNormalizer"]
