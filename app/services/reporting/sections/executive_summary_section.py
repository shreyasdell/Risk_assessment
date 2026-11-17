"""
Executive Summary Section

Generates the executive summary with key metrics and severity distribution.
"""

from typing import List
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from .base_section import BaseSection


class ExecutiveSummarySection(BaseSection):
    """Executive summary section."""
    
    def generate(self, data: dict) -> List:
        """Generate executive summary content."""
        story = []
        
        components = data.get('components', [])
        application = data.get('application')
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
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
        
        # Calculate risk score
        risk_score = (
            severity_counts['critical'] * 10 +
            severity_counts['high'] * 7 +
            severity_counts['medium'] * 4 +
            severity_counts['low'] * 1
        )
        
        # Summary table
        summary_data = [
            ['Metric', 'Count'],
            ['Total Components', str(total_components)],
            ['Total Vulnerabilities', str(total_cves)],
            ['Critical Severity', str(severity_counts['critical'])],
            ['High Severity', str(severity_counts['high'])],
            ['Medium Severity', str(severity_counts['medium'])],
            ['Low Severity', str(severity_counts['low'])],
            ['Overall Risk Score', str(risk_score)],
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['header_bg']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['header_text']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.colors['light_gray']]),
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
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['header_bg']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['header_text']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.colors['light_gray']]),
        ]))
        
        story.append(severity_table)
        
        return story
