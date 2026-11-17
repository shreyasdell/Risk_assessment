"""
PDF Report Service

Main service for generating PDF vulnerability assessment reports.
"""

from datetime import datetime
from io import BytesIO
from typing import Optional
from sqlalchemy.orm import Session
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate

from app.models.component import Component
from app.models.application import Application
from app.services.reporting.builders.report_builder import ReportBuilder
from app.services.reporting.report_config import MARGINS


class PDFReportService:
    """Service for generating PDF vulnerability assessment reports."""
    
    def __init__(self):
        self.builder = ReportBuilder()
    
    def generate_report(
        self,
        db: Session,
        application_id: Optional[int] = None,
        sbom_id: Optional[str] = None,
        report_type: str = 'full'
    ) -> BytesIO:
        """
        Generate a complete vulnerability assessment PDF report.
        
        Args:
            db: Database session
            application_id: Optional application ID to filter by
            sbom_id: Optional SBOM ID to filter by
            report_type: 'full' or 'executive'
            
        Returns:
            BytesIO: PDF file as bytes
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=MARGINS['right']*inch,
            leftMargin=MARGINS['left']*inch,
            topMargin=MARGINS['top']*inch,
            bottomMargin=MARGINS['bottom']*inch
        )
        
        # Get data
        components = self._get_components(db, application_id, sbom_id)
        application = self._get_application(db, application_id) if application_id else None
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(components)
        
        # Prepare data for report
        report_data = {
            'components': components,
            'application': application,
            'sbom_id': sbom_id,
            'risk_score': risk_score,
            'generated_at': datetime.now(),
        }
        
        # Build report content
        story = self.builder.build_report(report_data, report_type)
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def _get_components(
        self,
        db: Session,
        application_id: Optional[int] = None,
        sbom_id: Optional[str] = None
    ) -> list:
        """Get components for the report with eager loading of CVEs."""
        from sqlalchemy.orm import joinedload
        
        query = db.query(Component).options(joinedload(Component.cves))
        
        if application_id:
            query = query.filter(Component.application_id == application_id)
        if sbom_id:
            query = query.filter(Component.sbom_id == sbom_id)
        
        return query.all()
    
    def _get_application(self, db: Session, application_id: int) -> Optional[Application]:
        """Get application by ID."""
        return db.query(Application).filter(Application.id == application_id).first()
    
    def _calculate_risk_score(self, components: list) -> int:
        """Calculate overall risk score for all components."""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for component in components:
            for cve in component.cves:
                severity = (cve.severity or '').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Weighted risk score
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 7 +
            severity_counts['medium'] * 4 +
            severity_counts['low'] * 1
        )
        
        return risk_score


# Singleton instance
pdf_report_service = PDFReportService()
