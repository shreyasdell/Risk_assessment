#!/usr/bin/env python3
"""
Verification script for identity-based enrichment caching.

This script tests the enrichment caching implementation and provides before/after metrics.
"""

import sys
import os
import asyncio
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg2
from app.core.config import settings
from app.agent.langgraph_agent.graph import ComponentEnrichmentAgent
from app.core.database import SessionLocal
from app.models.component import Component


def get_cache_stats():
    """Get current cache statistics."""
    conn = psycopg2.connect(settings.DATABASE_URL)
    cursor = conn.cursor()
    
    # Get vendor_product_cache stats
    cursor.execute('SELECT COUNT(*) FROM vendor_product_cache')
    cache_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT SUM(hit_count) FROM vendor_product_cache')
    total_hits = cursor.fetchone()[0] or 0
    
    # Get cpe_validation_cache stats
    cursor.execute('SELECT COUNT(*) FROM cpe_validation_cache')
    validation_cache_count = cursor.fetchone()[0]
    
    cursor.execute('SELECT SUM(hit_count) FROM cpe_validation_cache')
    validation_hits = cursor.fetchone()[0] or 0
    
    conn.close()
    
    return {
        "vendor_cache_count": cache_count,
        "vendor_cache_hits": total_hits,
        "validation_cache_count": validation_cache_count,
        "validation_cache_hits": validation_hits,
    }


def get_application_components(application_id):
    """Get components for an application."""
    db = SessionLocal()
    components = db.query(Component).filter(Component.application_id == application_id).all()
    db.close()
    return components


async def simulate_enrichment(components, agent):
    """Simulate enrichment to measure cache hit rate."""
    agent.reset_metrics()
    
    for component in components:
        try:
            await agent.enrich_component(component.id)
        except Exception as e:
            print(f"Error enriching component {component.id}: {e}")
    
    metrics = agent.get_metrics()
    return metrics


def main():
    print("=" * 80)
    print("Enrichment Caching Verification")
    print("=" * 80)
    
    # Get current cache stats
    cache_stats = get_cache_stats()
    print("\nCurrent Cache Statistics:")
    print(f"  Vendor Product Cache Entries: {cache_stats['vendor_cache_count']}")
    print(f"  Vendor Product Cache Hits: {cache_stats['vendor_cache_hits']}")
    print(f"  CPE Validation Cache Entries: {cache_stats['validation_cache_count']}")
    print(f"  CPE Validation Cache Hits: {cache_stats['validation_cache_hits']}")
    
    # Test with application 21 (Laravel SBOM)
    print("\n" + "=" * 80)
    print("Testing with Application 21 (Laravel SBOM)")
    print("=" * 80)
    
    components = get_application_components(21)
    print(f"\nTotal components: {len(components)}")
    
    # Count components with enrichment data
    enriched = sum(1 for c in components if c.nvd_vendor and c.nvd_product and c.search_name)
    print(f"Components with enrichment data: {enriched} ({enriched/len(components)*100:.1f}%)")
    
    # Count components that would be cached
    cacheable = sum(1 for c in components if c.enrichment_confidence and c.enrichment_confidence >= 60 and c.search_name and ' ' in c.search_name)
    print(f"Components cacheable (confidence >= 60, search_name has space): {cacheable} ({cacheable/len(components)*100:.1f}%)")
    
    # Simulate enrichment
    print("\nSimulating enrichment...")
    db = SessionLocal()
    agent = ComponentEnrichmentAgent(db)
    metrics = asyncio.run(simulate_enrichment(components, agent))
    db.close()
    
    print("\nEnrichment Metrics:")
    print(f"  Identity Cache Hits: {metrics['identity_cache_hits']}")
    print(f"  Identity Cache Misses: {metrics['identity_cache_misses']}")
    total_identity = metrics['identity_cache_hits'] + metrics['identity_cache_misses']
    if total_identity > 0:
        print(f"  Identity Cache Hit Rate: {metrics['identity_cache_hits']/total_identity*100:.1f}%")
    else:
        print(f"  Identity Cache Hit Rate: N/A (no cache activity)")
    print(f"  CPE Validated Count: {metrics['cpe_validated_count']}")
    print(f"  CPE Not Validated Count: {metrics['cpe_not_validated_count']}")
    print(f"  Validation Cache Hits: {metrics['validation_cache_hits']}")
    print(f"  Validation Cache Misses: {metrics['validation_cache_misses']}")
    total_validation = metrics['validation_cache_hits'] + metrics['validation_cache_misses']
    if total_validation > 0:
        print(f"  Validation Cache Hit Rate: {metrics['validation_cache_hits']/total_validation*100:.1f}%")
    else:
        print(f"  Validation Cache Hit Rate: N/A (no validation activity)")
    print(f"  LLM Calls Avoided: {metrics['llm_calls_avoided']}")
    print(f"  NVD Validation Calls Avoided: {metrics['nvd_validation_calls_avoided']}")
    
    # Calculate before/after metrics (theoretical)
    print("\n" + "=" * 80)
    print("Before/After Comparison (Theoretical)")
    print("=" * 80)
    
    total_components = len(components)
    cacheable_components = cacheable
    
    print("\nBefore (without caching):")
    print(f"  LLM calls: {total_components}")
    print(f"  NVD validation requests: {total_components}")
    
    print("\nAfter (with caching - first upload):")
    print(f"  LLM calls: {total_components} (cache is empty)")
    print(f"  NVD validation requests: {total_components} (cache is empty)")
    
    print("\nAfter (with caching - second upload):")
    print(f"  LLM calls: {total_components - cacheable_components} (cache hits)")
    print(f"  NVD validation requests: {total_components - cacheable_components} (cache hits)")
    
    print("\nImprovement (second upload):")
    if total_components > 0:
        llm_reduction = (1 - (total_components - cacheable_components)/total_components) * 100
        nvd_reduction = (1 - (total_components - cacheable_components)/total_components) * 100
        print(f"  LLM calls reduced: {cacheable_components} ({llm_reduction:.1f}%)")
        print(f"  NVD validation requests reduced: {cacheable_components} ({nvd_reduction:.1f}%)")
    else:
        print(f"  N/A (no components)")
    
    print("\n" + "=" * 80)
    print("Verification Complete")
    print("=" * 80)


if __name__ == "__main__":
    main()
