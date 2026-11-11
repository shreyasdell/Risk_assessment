"""
Measure enrichment performance.

After one full enrichment of the largest SBOM, report:
- total components
- % per method (cache / validated LLM / unvalidated LLM / fallback_1/2/3)
- LLM calls
- average seconds per LLM call
- total time
- number of components with a validated constructed_cpe
"""

import asyncio
import time
from app.core.database import SessionLocal
from app.models.component import Component
from app.agent.langgraph_agent.graph import ComponentEnrichmentAgent


async def measure_enrichment(application_id=None):
    """
    Measure enrichment performance.
    
    Args:
        application_id: If provided, only measure components for this application
    """
    db = SessionLocal()
    agent = ComponentEnrichmentAgent(db)
    
    # Build query
    query = db.query(Component)
    if application_id:
        query = query.filter(Component.application_id == application_id)
    
    total = query.count()
    print(f"Total components to enrich: {total}")
    
    # Statistics
    stats = {
        "cache": 0,
        "memory_cache": 0,
        "validated_llm": 0,
        "unvalidated_llm": 0,
        "fallback_1": 0,
        "fallback_2": 0,
        "fallback_3": 0,
        "purl_only": 0,
        "llm_calls": 0,
        "llm_total_time": 0,
        "validated_constructed_cpe": 0
    }
    
    start_time = time.time()
    
    for component in query.all():
        print(f"Enriching {component.name} {component.version}...")
        component_start = time.time()
        
        result = await agent.enrich_component(component.id)
        
        component_time = time.time() - component_start
        method = result.get("enrichment_method", "unknown")
        
        if method == "memory_cache":
            stats["memory_cache"] += 1
        elif method == "purl_cache":
            stats["cache"] += 1
        elif method == "llm":
            stats["llm_calls"] += 1
            stats["llm_total_time"] += component_time
            if result.get("validated"):
                stats["validated_llm"] += 1
            else:
                stats["unvalidated_llm"] += 1
        elif method == "fallback_1":
            stats["fallback_1"] += 1
        elif method == "fallback_2":
            stats["fallback_2"] += 1
        elif method == "fallback_3":
            stats["fallback_3"] += 1
        elif method == "purl_only":
            stats["purl_only"] += 1
        
        # Check for validated constructed_cpe
        if component.constructed_cpe and result.get("validated"):
            stats["validated_constructed_cpe"] += 1
    
    total_time = time.time() - start_time
    
    # Print report
    print("\n" + "="*60)
    print("ENRICHMENT MEASUREMENT REPORT")
    print("="*60)
    print(f"Total components: {total}")
    print(f"Total time: {total_time:.2f}s")
    print(f"\nMethod breakdown:")
    print(f"  Memory cache: {stats['memory_cache']} ({stats['memory_cache']/total*100:.1f}%)")
    print(f"  Database cache: {stats['cache']} ({stats['cache']/total*100:.1f}%)")
    print(f"  Validated LLM: {stats['validated_llm']} ({stats['validated_llm']/total*100:.1f}%)")
    print(f"  Unvalidated LLM: {stats['unvalidated_llm']} ({stats['unvalidated_llm']/total*100:.1f}%)")
    print(f"  Fallback 1: {stats['fallback_1']} ({stats['fallback_1']/total*100:.1f}%)")
    print(f"  Fallback 2: {stats['fallback_2']} ({stats['fallback_2']/total*100:.1f}%)")
    print(f"  Fallback 3: {stats['fallback_3']} ({stats['fallback_3']/total*100:.1f}%)")
    print(f"  PURL only: {stats['purl_only']} ({stats['purl_only']/total*100:.1f}%)")
    print(f"\nLLM statistics:")
    print(f"  LLM calls: {stats['llm_calls']}")
    print(f"  Average time per LLM call: {stats['llm_total_time']/stats['llm_calls']:.2f}s" if stats['llm_calls'] > 0 else "  N/A")
    print(f"\nValidated constructed_cpe: {stats['validated_constructed_cpe']}")
    print("="*60)
    
    db.close()


if __name__ == "__main__":
    import sys
    app_id = int(sys.argv[1]) if len(sys.argv) > 1 else None
    asyncio.run(measure_enrichment(application_id=app_id))
