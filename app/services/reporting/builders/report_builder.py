"""
Report Builder

Orchestrates the generation of PDF reports using modular sections.
"""

from typing import List, Optional
from reportlab.platypus import SimpleDocTemplate, PageBreak, Flowable
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import Paragraph, Spacer

from app.services.reporting.report_config import COLORS, MARGINS, PAGE_SIZE
from app.services.reporting.sections import (
    CoverSection,
    ExecutiveSummarySection,
    ComponentInventorySection,
    VulnerabilityDetailsSection,
    RemediationSection,
    RiskSummarySection,
    AppendixSection,
)


class ReportBuilder:
    """Builder class for generating PDF reports."""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        self.colors = COLORS
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles for the report."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=self.colors['text'],
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=self.colors['text'],
            spaceBefore=20,
            spaceAfter=10,
            fontName='Helvetica-Bold',
            backColor=self.colors['light_gray'],
            borderPadding=5
        ))
        
        # Subsection header
        self.styles.add(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading3'],
            fontSize=14,
            textColor=self.colors['text'],
            spaceBefore=15,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
        
        # Update existing BodyText style
        self.styles['BodyText'].fontSize = 10
        self.styles['BodyText'].textColor = self.colors['text']
        self.styles['BodyText'].spaceAfter = 6
        self.styles['BodyText'].leading = 14
        
        # Small text for tables
        self.styles.add(ParagraphStyle(
            name='TableText',
            parent=self.styles['Normal'],
            fontSize=9,
            textColor=self.colors['text'],
            leading=12
        ))
        
        # Severity styles
        for severity, color in COLORS.items():
            if severity in ['critical', 'high', 'medium', 'low']:
                self.styles.add(ParagraphStyle(
                    name=severity.capitalize(),
                    parent=self.styles['Normal'],
                    fontSize=10,
                    textColor=color,
                    fontName='Helvetica-Bold'
                ))
    
    def build_report(
        self,
        data: dict,
        report_type: str = 'full'
    ) -> List[Flowable]:
        """
        Build the report content based on report type.
        
        Args:
            data: Dictionary containing report data
            report_type: 'full' or 'executive'
            
        Returns:
            List of Flowable objects for the report
        """
        story = []
        
        # Initialize sections
        cover_section = CoverSection(self.styles, self.colors)
        executive_section = ExecutiveSummarySection(self.styles, self.colors)
        component_section = ComponentInventorySection(self.styles, self.colors)
        vuln_section = VulnerabilityDetailsSection(self.styles, self.colors)
        remediation_section = RemediationSection(self.styles, self.colors)
        risk_section = RiskSummarySection(self.styles, self.colors)
        appendix_section = AppendixSection(self.styles, self.colors)
        
        # Add cover page
        story.extend(cover_section.generate(data))
        story.append(PageBreak())
        
        # Add executive summary (always included)
        story.extend(executive_section.generate(data))
        
        if report_type == 'full':
            story.append(PageBreak())
            
            # Add component inventory
            story.extend(component_section.generate(data))
            story.append(PageBreak())
            
            # Add vulnerability details
            story.extend(vuln_section.generate(data))
            story.append(PageBreak())
            
            # Add remediation recommendations
            story.extend(remediation_section.generate(data))
            story.append(PageBreak())
            
            # Add risk summary
            story.extend(risk_section.generate(data))
            story.append(PageBreak())
            
            # Add appendix
            story.extend(appendix_section.generate(data))
        
        return story
