"""
Appendix Section

Generates a complete CVE reference table.
"""

from typing import List
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from .base_section import BaseSection


class AppendixSection(BaseSection):
    """Appendix section with complete CVE reference table."""
    
    def generate(self, data: dict) -> List:
        """Generate appendix content."""
        story = []
        
        components = data.get('components', [])
        
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
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['header_bg']),
            ('TEXTCOLOR', (0, 0), (-1, 0), self.colors['header_text']),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('GRID', (0, 0), (-1, -1), 1, self.colors['border']),
            ('FONTSIZE', (0, 1), (-1, -1), 7),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, self.colors['light_gray']]),
        ]))
        
        story.append(table)
        
        return story
