"""
PDF Report Generation Service

Generates professional vulnerability assessment reports using ReportLab.
"""

from datetime import datetime
from io import BytesIO
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak,
    KeepTogether, TableOfContents, Frame, PageTemplate
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from app.models.component import Component
from app.models.cve import CVE
from app.models.application import Application


class PDFReportService:
    """Service for generating PDF vulnerability assessment reports."""
    
    # Color scheme matching requirements
    COLORS = {
        'critical': colors.HexColor('#D13438'),
        'high': colors.HexColor('#FF8C00'),
        'medium': colors.HexColor('#F4B400'),
        'low': colors.HexColor('#107C10'),
        'header_bg': colors.HexColor('#202020'),
        'header_text': colors.HexColor('#FFFFFF'),
        'border': colors.HexColor('#D9D9D9'),
        'text': colors.HexColor('#202020'),
        'light_gray': colors.HexColor('#F5F5F5'),
    }
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.COLORS['text'],
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=self.COLORS['text'],
            spaceBefore=20,
            spaceAfter=10,
            fontName='Helvetica-Bold',
            backColor=self.COLORS['light_gray'],
            borderPadding=5
        ))
        
        # Subsection header
        self.styles.add(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading3'],
            fontSize=14,
            textColor=self.COLORS['text'],
            spaceBefore=15,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
        
        # Normal text
        self.styles.add(ParagraphStyle(
            name='BodyText',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLORS['text'],
            spaceAfter=6,
            leading=14
        ))
        
        # Small text for tables
        self.styles.add(ParagraphStyle(
            name='TableText',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=self.COLORS['text'],
            leading=12
        ))
        
        # Critical severity
        self.styles.add(ParagraphStyle(
            name='Critical',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLORS['critical'],
            fontName='Helvetica-Bold'
        ))
        
        # High severity
        self.styles.add(ParagraphStyle(
            name='High',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLORS['high'],
            fontName='Helvetica-Bold'
        ))
        
        # Medium severity
        self.styles.add(ParagraphStyle(
            name='Medium',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLORS['medium'],
            fontName='Helvetica-Bold'
        ))
        
        # Low severity
        self.styles.add(ParagraphStyle(
            name='Low',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=self.COLORS['low'],
            fontName='Helvetica-Bold'
        ))
    
    def _get_severity_style(self, severity: str) -> str:
        """Get paragraph style name based on severity."""
        severity_lower = (severity or '').lower()
        if severity_lower == 'critical':
            return 'Critical'
        elif severity_lower == 'high':
            return 'High'
        elif severity_lower == 'medium':
            return 'Medium'
        elif severity_lower == 'low':
            return 'Low'
        return 'BodyText'
    
    def _get_severity_color(self, severity: str) -> colors.Color:
        """Get color based on severity."""
        severity_lower = (severity or '').lower()
        if severity_lower == 'critical':
            return self.COLORS['critical']
        elif severity_lower == 'high':
            return self.COLORS['high']
        elif severity_lower == 'medium':
            return self.COLORS['medium']
        elif severity_lower == 'low':
            return self.COLORS['low']
        return self.COLORS['text']
    
    def generate_report(
        self,
        db: Session,
        application_id: int = None,
        sbom_id: str = None
    ) -> BytesIO:
        """
        Generate a complete vulnerability assessment PDF report.
        
        Args:
            db: Database session
            application_id: Optional application ID to filter by
            sbom_id: Optional SBOM ID to filter by
            
        Returns:
            BytesIO: PDF file as bytes
        """
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        # Build report content
        story = []
        
        # Get data
        components = self._get_components(db, application_id, sbom_id)
        application = self._get_application(db, application_id) if application_id else None
        
        # Add cover page
        story.extend(self._create_cover_page(application, sbom_id))
        story.append(PageBreak())
        
        # Add executive summary
        story.extend(self._create_executive_summary(components, application, sbom_id))
        story.append(PageBreak())
        
        # Add component inventory
        story.extend(self._create_component_inventory(components))
        story.append(PageBreak())
        
        # Add vulnerability details
        story.extend(self._create_vulnerability_details(components))
        story.append(PageBreak())
        
        # Add remediation recommendations
        story.extend(self._create_remediation_recommendations(components))
        story.append(PageBreak())
        
        # Add risk summary
        story.extend(self._create_risk_summary(components))
        story.append(PageBreak())
        
        # Add appendix
        story.extend(self._create_appendix(components))
        
        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer
    
    def _get_components(
        self,
        db: Session,
        application_id: int = None,
        sbom_id: str = None
    ) -> List[Component]:
        """Get components for the report."""
        query = db.query(Component)
        
        if application_id:
            query = query.filter(Component.application_id == application_id)
        if sbom_id:
            query = query.filter(Component.sbom_id == sbom_id)
        
        return query.all()
    
    def _get_application(self, db: Session, application_id: int) -> Application:
        """Get application by ID."""
        return db.query(Application).filter(Application.id == application_id).first()
    
    def _create_cover_page(
        self,
        application: Application = None,
        sbom_id: str = None
    ) -> List:
        """Create the cover page."""
        story = []
        
        # Add spacing
        story.append(Spacer(1, 2*inch))
        
        # Title
        story.append(Paragraph("Vulnerability Assessment Report", self.styles['ReportTitle']))
        story.append(Spacer(1, 0.5*inch))
        
        # Application/SBOM info
        if application:
            story.append(Paragraph(f"<b>Application:</b> {application.name}", self.styles['BodyText']))
            story.append(Spacer(1, 0.1*inch))
        
        if sbom_id:
            story.append(Paragraph(f"<b>SBOM ID:</b> {sbom_id}", self.styles['BodyText']))
            story.append(Spacer(1, 0.1*inch))
        
        # Generation timestamp
        story.append(Paragraph(
            f"<b>Generated On:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.styles['BodyText']
        ))
        
        # Add more spacing
        story.append(Spacer(1, 2*inch))
        
        # Footer
        story.append(Paragraph(
            "Confidential - For Internal Use Only",
            self.styles['BodyText']
        ))
        
        return story
    
    def _create_executive_summary(
        self,
        components: List[Component],
        application: Application = None,
        sbom_id: str = None
    ) -> List:
        """Create executive summary section."""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        
        # Summary stats
        total_components = len(components)
        total_cves = sum(len(c.cves) for c in components)
        
        # Count by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for component in components:
            for cve in component.cves:
                severity = (cve.severity or '').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        # Summary table
        summary_data = [
            ['Metric', 'Count'],
            ['Total Components', str(total_components)],
            ['Total Vulnerabilities', str(total_cves)],
            ['Critical Severity', str(severity_counts['critical'])],
            ['High Severity', str(severity_counts['high'])],
            ['Medium Severity', str(severity_counts['medium'])],
            ['Low Severity', str(severity_counts['low'])],
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['header_bg']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.COLORS['header_text']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, self.COLORS['border']),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLORS['light_gray']]),
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Severity distribution
        story.append(Paragraph("Severity Distribution", self.styles['SubsectionHeader']))
        
        severity_data = [
            ['Severity', 'Count', 'Percentage'],
            ['Critical', str(severity_counts['critical']), 
             f"{(severity_counts['critical']/total_cves*100) if total_cves > 0 else 0:.1f}%"],
            ['High', str(severity_counts['high']),
             f"{(severity_counts['high']/total_cves*100) if total_cves > 0 else 0:.1f}%"],
            ['Medium', str(severity_counts['medium']),
             f"{(severity_counts['medium']/total_cves*100) if total_cves > 0 else 0:.1f}%"],
            ['Low', str(severity_counts['low']),
             f"{(severity_counts['low']/total_cves*100) if total_cves > 0 else 0:.1f}%"],
        ]
        
        severity_table = Table(severity_data, colWidths=[1.5*inch, 1*inch, 1.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['header_bg']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.COLORS['header_text']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, self.COLORS['border']),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLORS['light_gray']]),
        ]))
        
        story.append(severity_table)
        
        return story
    
    def _create_component_inventory(self, components: List[Component]) -> List:
        """Create component inventory section."""
        story = []
        
        story.append(Paragraph("Component Inventory", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        # Table data
        table_data = [['Component Name', 'Version', 'Package Type', 'Supplier/Vendor', 'Total CVEs']]
        
        for component in components:
            table_data.append([
                component.name or '—',
                component.version or '—',
                component.component_type or '—',
                component.supplier or component.identified_vendor or '—',
                str(len(component.cves))
            ])
        
        # Create table with auto-pagination
        table = Table(table_data, colWidths=[2*inch, 1*inch, 1*inch, 1.5*inch, 0.8*inch], repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['header_bg']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.COLORS['header_text']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, self.COLORS['border']),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLORS['light_gray']]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(table)
        
        return story
    
    def _create_vulnerability_details(self, components: List[Component]) -> List:
        """Create vulnerability details section."""
        story = []
        
        story.append(Paragraph("Vulnerability Details", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        for component in components:
            if not component.cves:
                continue
            
            # Component header
            story.append(Paragraph(
                f"Component: {component.name} {component.version}",
                self.styles['SubsectionHeader']
            ))
            story.append(Spacer(1, 0.1*inch))
            
            # CVEs for this component
            for cve in component.cves:
                story.append(Paragraph(f"CVE ID: {cve.cve_id}", self.styles['BodyText']))
                story.append(Spacer(1, 0.05*inch))
                
                # Severity and CVSS
                severity_style = self._get_severity_style(cve.severity)
                story.append(Paragraph(
                    f"<b>Severity:</b> <span styleName='{severity_style}'>{cve.severity or 'Unknown'}</span>",
                    self.styles['BodyText']
                ))
                story.append(Paragraph(
                    f"<b>CVSS Score:</b> {cve.cvss_score or 'N/A'}",
                    self.styles['BodyText']
                ))
                story.append(Paragraph(
                    f"<b>Published:</b> {cve.published_date.strftime('%Y-%m-%d') if cve.published_date else 'N/A'}",
                    self.styles['BodyText']
                ))
                story.append(Spacer(1, 0.05*inch))
                
                # Description
                story.append(Paragraph("<b>Description:</b>", self.styles['BodyText']))
                story.append(Paragraph(
                    cve.description[:500] + '...' if len(cve.description or '') > 500 else (cve.description or 'N/A'),
                    self.styles['TableText']
                ))
                story.append(Spacer(1, 0.1*inch))
                
                # Separator
                story.append(Paragraph("—" * 50, self.styles['BodyText']))
                story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _create_remediation_recommendations(self, components: List[Component]) -> List:
        """Create remediation recommendations section."""
        story = []
        
        story.append(Paragraph("Remediation Recommendations", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        for component in components:
            if not component.cves:
                continue
            
            # Count severities
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for cve in component.cves:
                severity = (cve.severity or '').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Only show components with vulnerabilities
            if sum(severity_counts.values()) == 0:
                continue
            
            # Component header
            story.append(Paragraph(f"Component: {component.name}", self.styles['SubsectionHeader']))
            story.append(Spacer(1, 0.05*inch))
            
            # Recommended action
            story.append(Paragraph("<b>Recommended Action:</b>", self.styles['BodyText']))
            
            if severity_counts['critical'] > 0 or severity_counts['high'] > 0:
                story.append(Paragraph(
                    f"Priority: HIGH - Addresses {severity_counts['critical']} Critical and {severity_counts['high']} High severity vulnerabilities.",
                    self.styles['BodyText']
                ))
            else:
                story.append(Paragraph(
                    f"Priority: MEDIUM - Addresses {severity_counts['medium']} Medium and {severity_counts['low']} Low severity vulnerabilities.",
                    self.styles['BodyText']
                ))
            
            story.append(Spacer(1, 0.05*inch))
            
            # Current version
            story.append(Paragraph(
                f"<b>Current Version:</b> {component.version or 'N/A'}",
                self.styles['BodyText']
            ))
            
            # Affected CVEs (top 5)
            story.append(Paragraph("<b>Affected CVEs (Top 5):</b>", self.styles['BodyText']))
            sorted_cves = sorted(
                component.cves,
                key=lambda c: (c.cvss_score or 0),
                reverse=True
            )[:5]
            
            for cve in sorted_cves:
                severity_style = self._get_severity_style(cve.severity)
                story.append(Paragraph(
                    f"• {cve.cve_id} - <span styleName='{severity_style}'>{cve.severity or 'Unknown'}</span> (CVSS: {cve.cvss_score or 'N/A'})",
                    self.styles['TableText']
                ))
            
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph("—" * 50, self.styles['BodyText']))
            story.append(Spacer(1, 0.1*inch))
        
        return story
    
    def _create_risk_summary(self, components: List[Component]) -> List:
        """Create risk summary section."""
        story = []
        
        story.append(Paragraph("Risk Summary", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        # Calculate risk scores for each component
        component_risks = []
        for component in components:
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            for cve in component.cves:
                severity = (cve.severity or '').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Calculate risk score (weighted)
            risk_score = (
                severity_counts['critical'] * 10 +
                severity_counts['high'] * 7 +
                severity_counts['medium'] * 4 +
                severity_counts['low'] * 1
            )
            
            component_risks.append({
                'component': component,
                'risk_score': risk_score,
                'severity_counts': severity_counts
            })
        
        # Sort by risk score descending
        component_risks.sort(key=lambda x: x['risk_score'], reverse=True)
        
        # Table data
        table_data = [['Component', 'Critical', 'High', 'Medium', 'Low', 'Total']]
        
        for item in component_risks:
            table_data.append([
                item['component'].name,
                str(item['severity_counts']['critical']),
                str(item['severity_counts']['high']),
                str(item['severity_counts']['medium']),
                str(item['severity_counts']['low']),
                str(sum(item['severity_counts'].values()))
            ])
        
        # Create table
        table = Table(table_data, colWidths=[2*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch], repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['header_bg']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.COLORS['header_text']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, self.COLORS['border']),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLORS['light_gray']]),
        ]))
        
        story.append(table)
        
        return story
    
    def _create_appendix(self, components: List[Component]) -> List:
        """Create appendix with complete CVE reference table."""
        story = []
        
        story.append(Paragraph("Appendix: Complete CVE Reference", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        # Collect all CVEs
        all_cves = []
        for component in components:
            for cve in component.cves:
                all_cves.append({
                    'cve': cve,
                    'component': component
                })
        
        # Sort by severity (critical first)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        all_cves.sort(
            key=lambda x: (
                severity_order.get((x['cve'].severity or '').lower(), 99),
                -(x['cve'].cvss_score or 0)
            )
        )
        
        # Table data
        table_data = [['CVE ID', 'Severity', 'CVSS', 'Component', 'Version', 'Published Date']]
        
        for item in all_cves:
            cve = item['cve']
            component = item['component']
            
            table_data.append([
                cve.cve_id,
                cve.severity or 'Unknown',
                str(cve.cvss_score or 'N/A'),
                component.name,
                component.version or 'N/A',
                cve.published_date.strftime('%Y-%m-%d') if cve.published_date else 'N/A'
            ])
        
        # Create table with auto-pagination
        table = Table(table_data, colWidths=[1.5*inch, 0.8*inch, 0.6*inch, 1.5*inch, 0.8*inch, 0.8*inch], repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.COLORS['header_bg']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.COLORS['header_text']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, self.COLORS['border']),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.COLORS['light_gray']]),
        ]))
        
        story.append(table)
        
        return story


# Singleton instance
pdf_report_service = PDFReportService()
