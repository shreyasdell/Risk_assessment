"""
Risk Summary Section

Generates a risk summary table sorted by highest risk first.
"""

from typing import List
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from .base_section import BaseSection


class RiskSummarySection(BaseSection):
    """Risk summary section."""
    
    def generate(self, data: dict) -> List:
        """Generate risk summary content."""
        story = []
        
        components = data.get('components', [])
        
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
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['header_bg']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['header_text']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.colors['light_gray']]),
        ]))
        
        story.append(table)
        
        return story
