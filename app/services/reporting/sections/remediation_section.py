"""
Remediation Recommendations Section

Generates prioritized remediation recommendations for each component.
"""

from typing import List
from reportlab.platypus import Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from .base_section import BaseSection


class RemediationSection(BaseSection):
    """Remediation recommendations section."""
    
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
    
    def generate(self, data: dict) -> List:
        """Generate remediation recommendations content."""
        story = []
        
        components = data.get('components', [])
        
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
            
            # Check for patch availability
            has_patch = any(cve.patch_available for cve in component.cves)
            if has_patch:
                story.append(Paragraph(
                    "<b>Remediation:</b> Patch Available - Upgrade to the latest patched version",
                    self.styles['BodyText']
                ))
            else:
                story.append(Paragraph(
                    "<b>Remediation:</b> Review vendor advisory and apply compensating controls",
                    self.styles['BodyText']
                ))
            
            story.append(Spacer(1, 0.05*inch))
            
            # Affected CVEs (top 5)
            story.append(Paragraph("<b>Affected CVEs (Top 5):</b>", self.styles['BodyText']))
            sorted_cves = sorted(
                component.cves,
                key=lambda c: (c.cvss_score or 0),
                reverse=True
            )[:5]
            
            for cve in sorted_cves:
                severity = cve.severity or 'Unknown'
                story.append(Paragraph(
                    f"• {cve.cve_id} - {severity} (CVSS: {cve.cvss_score or 'N/A'})",
                    self.styles['TableText']
                ))
            
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph("—" * 50, self.styles['BodyText']))
            story.append(Spacer(1, 0.1*inch))
        
        return story
