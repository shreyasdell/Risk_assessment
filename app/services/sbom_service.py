from sqlalchemy.orm import Session
from typing import List, Optional
import uuid
from app.schemas.component import ComponentCreate
from app.services.component_service import create_components_bulk, delete_components_by_sbom_id
from app.sbom.parser import SBOMParser


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
    # Generate unique SBOM ID
    sbom_id = str(uuid.uuid4())
    
    # If replace_existing and application_id provided, delete old components
    if replace_existing and application_id:
        delete_components_by_sbom_id(db, sbom_id)
    
    # Parse SBOM content
    try:
        components = SBOMParser.parse(content, filename, application_id, sbom_id)
    except Exception as e:
        raise ValueError(f"Failed to parse SBOM: {str(e)}")
    
    if not components:
        raise ValueError("No components found in SBOM")
    
    # Store components in database (duplicates will be skipped)
    created_components = create_components_bulk(db, components)
    
    skipped_count = len(components) - len(created_components)
    
    return {
        "sbom_id": sbom_id,
        "total_components": len(components),
        "created_components": len(created_components),
        "skipped_components": skipped_count,
        "components": [comp.id for comp in created_components]
    }


def get_sbom_components(db: Session, sbom_id: str) -> List:
    """Get all components for a specific SBOM upload"""
    from app.services.component_service import get_components
    return get_components(db, sbom_id=sbom_id)
