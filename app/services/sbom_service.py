from sqlalchemy.orm import Session
from typing import List, Optional
import uuid
import asyncio
from app.schemas.component import ComponentCreate
from app.services.component_service import create_components_bulk, delete_components_by_sbom_id, delete_components_by_application_id
from app.sbom.parser import SBOMParser
from app.agent.langgraph_agent import ComponentEnrichmentAgent
from app.core.config import settings


def process_sbom_upload(
    db: Session,
    content: str,
    filename: str,
    application_id: Optional[int] = None,
    replace_existing: bool = False
) -> dict:
    """
    Process SBOM upload, parse it, and store components
    
    Args:
        db: Database session
        content: SBOM file content
        filename: Name of the uploaded file
        application_id: Optional application ID to associate components with
        replace_existing: If True, replace existing components for this application
    
    Returns:
        dict with upload results
    """
    print(f"DEBUG: process_sbom_upload - application_id: {application_id}")
    
    # Generate unique SBOM ID
    sbom_id = str(uuid.uuid4())
    print(f"DEBUG: Generated sbom_id: {sbom_id}")
    
    # If replace_existing and application_id provided, delete old components for this application
    if replace_existing and application_id:
        deleted_count = delete_components_by_application_id(db, application_id)
        print(f"[DEBUG] Deleted {deleted_count} existing components for application {application_id}")
    
    # Parse SBOM content
    try:
        components = SBOMParser.parse(content, filename, application_id, sbom_id)
        print(f"DEBUG: Parsed {len(components)} components")
        if components and len(components) > 0:
            print(f"DEBUG: First component application_id: {components[0].application_id}")
    except Exception as e:
        raise ValueError(f"Failed to parse SBOM: {str(e)}")
    
    if not components:
        raise ValueError("No components found in SBOM")
    
    # Store components in database (duplicates will be skipped)
    created_components = create_components_bulk(db, components)
    
    skipped_count = len(components) - len(created_components)
    
    # Trigger background enrichment job
    if created_components:
        print(f"[DEBUG] Triggering enrichment for {len(created_components)} created components")
        _trigger_enrichment_background(db, [comp.id for comp in created_components])
    else:
        print(f"[DEBUG] No new components created (all were duplicates), skipping enrichment")
    
    return {
        "sbom_id": sbom_id,
        "total_components": len(components),
        "created_components": len(created_components),
        "skipped_components": skipped_count,
        "components": [comp.id for comp in created_components]
    }


def _trigger_enrichment_background(db: Session, component_ids: List[int]):
    """
    Trigger background enrichment job for components.
    
    This runs asynchronously after SBOM upload to avoid blocking the upload response.
    """
    def enrichment_task():
        """Run enrichment in background thread."""
        try:
            # Create new session for background task
            from app.core.database import SessionLocal
            bg_db = SessionLocal()
            
            # Initialize agent
            agent = ComponentEnrichmentAgent(
                db_session=bg_db,
                ollama_url=settings.OLLAMA_URL,
                model=settings.OLLAMA_MODEL
            )
            
            # Enrich each component
            for component_id in component_ids:
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    result = loop.run_until_complete(agent.enrich_component(component_id))
                    loop.close()
                    print(f"[Enrichment] Component {component_id}: {result.get('enrichment_method', 'unknown')}")
                except Exception as e:
                    print(f"[Enrichment] Error enriching component {component_id}: {e}")
            
            bg_db.close()
        except Exception as e:
            print(f"[Enrichment] Background task error: {e}")
    
    # Run in background thread (non-daemon to ensure it completes)
    import threading
    thread = threading.Thread(target=enrichment_task, daemon=False)
    thread.start()
    print(f"[Enrichment] Background enrichment started for {len(component_ids)} components")


def get_sbom_components(db: Session, sbom_id: str) -> List:
    """Get all components for a specific SBOM upload"""
    from app.services.component_service import get_components
    components, _ = get_components(db, sbom_id=sbom_id)
    return components
