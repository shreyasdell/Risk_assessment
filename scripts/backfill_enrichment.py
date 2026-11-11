#!/usr/bin/env python3
"""
Backfill enrichment for existing components.

This script re-runs the LangGraph agent enrichment on components that are missing
constructed_cpe or search_name fields. This is useful for components that were created
before the LangGraph agent was deployed.

Usage:
    python scripts/backfill_enrichment.py --dry-run
    python scripts/backfill_enrichment.py
"""

import argparse
import sys
import os
import asyncio

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session
from app.core.database import SessionLocal, engine
from app.models.component import Component
from app.agent.langgraph_agent.graph import ComponentEnrichmentAgent
from app.core.config import settings


def find_components_needing_enrichment(db: Session, limit: int = None) -> list:
    """
    Find components that are missing constructed_cpe or search_name.

    Args:
        db: Database session
        limit: Optional limit on number of components to process

    Returns:
        List of Component objects
    """
    query = db.query(Component).filter(
        (Component.constructed_cpe.is_(None)) | (Component.search_name.is_(None))
    )

    if limit:
        query = query.limit(limit)

    components = query.all()
    print(f"[Backfill] Found {len(components)} components needing enrichment")
    return components


async def backfill_component(component: Component, agent: ComponentEnrichmentAgent, dry_run: bool = False) -> dict:
    """
    Backfill enrichment for a single component.

    Args:
        component: Component to enrich
        agent: LangGraph agent instance
        dry_run: If True, don't actually update the database

    Returns:
        Dict with result status
    """
    try:
        if dry_run:
            print(f"[Backfill] DRY-RUN: Would enrich component {component.id}: {component.name} {component.version}")
            return {"status": "dry_run", "component_id": component.id}

        print(f"[Backfill] Enriching component {component.id}: {component.name} {component.version}")
        result = await agent.enrich_component(component.id)

        if result.get("error"):
            print(f"[Backfill] ERROR: Failed to enrich component {component.id}: {result.get('error')}")
            return {"status": "error", "component_id": component.id, "error": result.get("error")}

        print(f"[Backfill] SUCCESS: Enriched component {component.id}")
        return {"status": "success", "component_id": component.id}

    except Exception as e:
        print(f"[Backfill] ERROR: Exception enriching component {component.id}: {e}")
        return {"status": "error", "component_id": component.id, "error": str(e)}


async def main():
    parser = argparse.ArgumentParser(description="Backfill enrichment for existing components")
    parser.add_argument("--dry-run", action="store_true", help="Run without making changes")
    parser.add_argument("--limit", type=int, help="Limit number of components to process")
    args = parser.parse_args()

    print("[Backfill] Starting enrichment backfill")
    print(f"[Backfill] Dry-run: {args.dry_run}")
    print(f"[Backfill] Limit: {args.limit if args.limit else 'None (all components)'}")

    # Create database session
    db = SessionLocal()

    try:
        # Find components needing enrichment
        components = find_components_needing_enrichment(db, limit=args.limit)

        if not components:
            print("[Backfill] No components need enrichment. Exiting.")
            return

        # Initialize LangGraph agent
        agent = ComponentEnrichmentAgent(
            db_session=db,
            ollama_url=settings.OLLAMA_URL,
            model=settings.OLLAMA_MODEL
        )

        # Track results
        results = {
            "total": len(components),
            "success": 0,
            "error": 0,
            "dry_run": 0
        }

        # Process each component
        for component in components:
            result = await backfill_component(component, agent, dry_run=args.dry_run)
            results[result["status"]] += 1

        # Print summary
        print("\n[Backfill] Summary:")
        print(f"  Total components: {results['total']}")
        print(f"  Successful: {results['success']}")
        print(f"  Errors: {results['error']}")
        print(f"  Dry-run: {results['dry_run']}")

        if not args.dry_run:
            db.commit()
            print("[Backfill] Changes committed to database")
        else:
            print("[Backfill] Dry-run complete - no changes made")

    except Exception as e:
        print(f"[Backfill] FATAL ERROR: {e}")
        db.rollback()
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(main())
