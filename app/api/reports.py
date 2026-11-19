"""
Reports API Router

Provides endpoints for generating PDF reports.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import get_db
from app.auth.dependencies import get_current_active_user
from app.auth.rbac import require_write_access
from app.models.user import User
from app.services.reporting.report_service import pdf_report_service
from app.services.audit_service import audit_service

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/generate-pdf", summary="Generate PDF vulnerability assessment report")
def generate_pdf_report(
    application_id: Optional[int] = Query(None, description="Filter by application ID"),
    sbom_id: Optional[str] = Query(None, description="Filter by SBOM ID"),
    report_type: str = Query("full", description="Report type: 'full' or 'executive'"),
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_write_access)
):
    """
    Generate a PDF vulnerability assessment report.
    
    Query Parameters:
    - application_id: Optional application ID to filter components
    - sbom_id: Optional SBOM ID to filter components
    - report_type: 'full' for complete report, 'executive' for summary only
    
    Returns:
    - PDF file as binary response
    """
    try:
        # Validate report_type
        if report_type not in ['full', 'executive']:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="report_type must be 'full' or 'executive'"
            )
        
        # Generate PDF
        pdf_buffer = pdf_report_service.generate_report(
            db=db,
            application_id=application_id,
            sbom_id=sbom_id,
            report_type=report_type
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
        
        # Log report generation
        audit_service.log(
            db=db,
            action="EXPORT",
            resource_type="report",
            description=f"PDF report generated: {report_type}",
            details={
                "application_id": application_id,
                "sbom_id": sbom_id,
                "report_type": report_type,
                "filename": filename
            },
            user_id=current_user.id,
            username=current_user.username,
            user_role=current_user.role,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent")
        )
        
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
