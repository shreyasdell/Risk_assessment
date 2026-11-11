"""
Backfill enrichment for components that need it.

Idempotent job to re-run enrichment for components with:
- enrichment_status is null
- enrichment_status = 'failed'
- enrichment_status = 'unvalidated'
- constructed_cpe is null
"""

import asyncio
import sys
from app.core.database import SessionLocal
from app.models.component import Component
from app.agent.langgraph_agent.graph import ComponentEnrichmentAgent


async def backfill_enrichment(dry_run=False):
    """
    Backfill enrichment for components that need it.
    
    Args:
        dry_run: If True, only report what would be done without making changes
    """
    db = SessionLocal()
    agent = ComponentEnrichmentAgent(db)
    
    # Find components that need enrichment
    query = db.query(Component).filter(
        (Component.enrichment_status.is_(None)) |
        (Component.enrichment_status == 'failed') |
        (Component.enrichment_status == 'unvalidated') |
        (Component.constructed_cpe.is_(None))
    )
    
    total = query.count()
    print(f"Found {total} components needing enrichment")
    
    if dry_run:
        print("DRY RUN - No changes will be made")
        for component in query.limit(10).all():
            print(f"  - {component.name} {component.version} (status: {component.enrichment_status}, constructed_cpe: {component.constructed_cpe})")
        if total > 10:
            print(f"  ... and {total - 10} more")
        return
    
    # Process components
    processed = 0
    failed = 0
    for component in query.all():
        print(f"Processing {component.name} {component.version}...")
        result = await agent.enrich_component(component.id)
        if result.get("error"):
            print(f"  ERROR: {result['error']}")
            failed += 1
        else:
            print(f"  SUCCESS: {result.get('enrichment_method')}")
            processed += 1
    
    print(f"\nBackfill complete: {processed} succeeded, {failed} failed")
    db.close()


if __name__ == "__main__":
    dry_run = "--dry-run" in sys.argv
    asyncio.run(backfill_enrichment(dry_run=dry_run))
