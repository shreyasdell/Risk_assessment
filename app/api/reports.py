"""
Reports API Router

Provides endpoints for generating PDF reports.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.auth.dependencies import get_current_active_user
from app.auth.rbac import require_write_access
from app.models.user import User
from app.services.pdf_report_service import pdf_report_service

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/generate-pdf", summary="Generate PDF vulnerability assessment report")
def generate_pdf_report(
    application_id: Optional[int] = Query(None, description="Filter by application ID"),
    sbom_id: Optional[str] = Query(None, description="Filter by SBOM ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    """
    Generate a PDF vulnerability assessment report.
    
    Query Parameters:
    - application_id: Optional application ID to filter components
    - sbom_id: Optional SBOM ID to filter components
    
    Returns:
    - PDF file as binary response
    """
    try:
        # Generate PDF
        pdf_buffer = pdf_report_service.generate_report(
            db=db,
            application_id=application_id,
            sbom_id=sbom_id
        )
        
        # Generate filename
        from datetime import datetime
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        app_name = ""
        if application_id:
            from app.models.application import Application
            app = db.query(Application).filter(Application.id == application_id).first()
            if app:
                app_name = f"_{app.name.replace(' ', '_')}"
        
        filename = f"vulnerability_report{app_name}_{timestamp}.pdf"
        
        # Return PDF as response
        return Response(
            content=pdf_buffer.getvalue(),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate PDF report: {str(e)}"
        )
