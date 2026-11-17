"""
Component Inventory Section

Generates a table of all components with their CVE counts.
"""

from typing import List
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from .base_section import BaseSection


class ComponentInventorySection(BaseSection):
    """Component inventory section."""
    
    def generate(self, data: dict) -> List:
        """Generate component inventory content."""
        story = []
        
        components = data.get('components', [])
        
        story.append(Paragraph("Component Inventory", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.1*inch))
        
        # Table data
        table_data = [['Component Name', 'Version', 'Ecosystem', 'Vendor', 'Total CVEs']]
        
        for component in components:
            table_data.append([
                component.name or '—',
                component.version or '—',
                component.component_type or '—',
                component.supplier or component.identified_vendor or component.nvd_vendor or '—',
                str(len(component.cves))
            ])
        
        # Create table with auto-pagination
        table = Table(table_data, colWidths=[2*inch, 1*inch, 1*inch, 1.5*inch, 0.8*inch], repeatRows=1)
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
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(table)
        
        return story
