"""
Report Generation API Router
"""

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional
import io

from app.core.database import get_db
from app.auth.dependencies import get_current_user
from app.services.report_service import report_service

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get(
    "/executive-pdf",
    summary="Generate executive PDF report"
)
def generate_executive_report(
    application_id: Optional[int] = Query(
        None, description="Filter to specific application"
    ),
    vendor_id: Optional[int] = Query(
        None, description="Filter to specific vendor"
    ),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Generate a comprehensive PDF risk assessment report.

    The report includes:
    - Executive summary
    - Risk scores per application
    - Vulnerability findings
    - Remediation recommendations
    - Risk matrix

    Optionally filter by application or vendor.
    """
    pdf_bytes = report_service.generate_executive_report(
        db=db,
        application_id=application_id,
        vendor_id=vendor_id,
    )

    filename = "risk_assessment_report"
    if application_id:
        filename += f"_app_{application_id}"
    if vendor_id:
        filename += f"_vendor_{vendor_id}"
    filename += ".pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                f'attachment; filename="{filename}"'
        }
    )
