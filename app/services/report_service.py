"""
PDF Report Generation Service

Generates executive risk assessment reports containing:
1. Executive Summary
2. Risk Overview
3. Application Inventory
4. Vulnerability Findings
5. Remediation Recommendations
6. Risk Matrix
"""

import io
from datetime import datetime
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from app.models.vendor import Vendor
from app.models.application import Application
from app.models.component import Component
from app.models.cve import CVE
from app.models.risk_score import RiskScore
from app.models.remediation import Remediation


class ReportService:

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()

    def _create_custom_styles(self):
        """Define custom paragraph styles for the report."""
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1e40af'),
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.HexColor('#1e293b'),
            borderWidth=1,
            borderColor=colors.HexColor('#3b82f6'),
            borderPadding=5,
        ))
        self.styles.add(ParagraphStyle(
            name='SubHeader',
            parent=self.styles['Heading2'],
            fontSize=13,
            spaceBefore=12,
            spaceAfter=6,
            textColor=colors.HexColor('#334155'),
        ))
        self.styles.add(ParagraphStyle(
            name='BodyCustom',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            leading=14,
        ))
        self.styles.add(ParagraphStyle(
            name='SmallText',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#64748b'),
        ))

    def generate_executive_report(
        self,
        db: Session,
        application_id: int = None,
        vendor_id: int = None,
    ) -> bytes:
        """
        Generate a complete executive risk assessment PDF.

        Args:
            db: Database session
            application_id: Filter to specific app (optional)
            vendor_id: Filter to specific vendor (optional)

        Returns:
            PDF file as bytes
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=50,
            leftMargin=50,
            topMargin=60,
            bottomMargin=50,
        )

        elements = []

        # Gather data
        data = self._gather_data(
            db, application_id, vendor_id
        )

        # Build report sections
        elements.extend(self._build_cover_page(data))
        elements.append(PageBreak())
        elements.extend(self._build_executive_summary(data))
        elements.extend(self._build_risk_overview(data))
        elements.extend(
            self._build_application_inventory(data)
        )
        elements.extend(
            self._build_vulnerability_findings(data)
        )
        elements.extend(self._build_recommendations(data))
        elements.extend(self._build_risk_matrix(data))
        elements.extend(self._build_footer(data))

        doc.build(elements)
        buffer.seek(0)
        return buffer.read()

    def _gather_data(
        self,
        db: Session,
        application_id: int = None,
        vendor_id: int = None
    ) -> Dict:
        """Collect all data needed for the report."""

        # Base queries
        app_query = db.query(Application)
        if application_id:
            app_query = app_query.filter(
                Application.id == application_id
            )
        if vendor_id:
            app_query = app_query.filter(
                Application.vendor_id == vendor_id
            )

        applications = app_query.all()
        app_ids = [a.id for a in applications]

        vendors = db.query(Vendor).all()

        components = (
            db.query(Component)
            .filter(Component.application_id.in_(app_ids))
            .all()
            if app_ids else []
        )

        # Get all CVEs linked to these components
        comp_ids = [c.id for c in components]
        cves = (
            db.query(CVE)
            .join(Component.cves)
            .filter(Component.id.in_(comp_ids))
            .all()
            if comp_ids else []
        )

        # Risk scores (latest per app)
        risk_scores = []
        for app in applications:
            latest = (
                db.query(RiskScore)
                .filter(RiskScore.application_id == app.id)
                .order_by(RiskScore.calculated_at.desc())
                .first()
            )
            if latest:
                risk_scores.append(latest)

        # Remediations
        remediations = (
            db.query(Remediation)
            .filter(
                Remediation.application_id.in_(app_ids)
            )
            .all()
            if app_ids else []
        )

        # Severity counts
        severity_counts = {
            'critical': 0, 'high': 0,
            'medium': 0, 'low': 0,
        }
        for cve in cves:
            sev = (cve.severity or 'unknown').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {
            'applications': applications,
            'vendors': vendors,
            'components': components,
            'cves': cves,
            'risk_scores': risk_scores,
            'remediations': remediations,
            'severity_counts': severity_counts,
            'generated_at': datetime.utcnow(),
            'application_id': application_id,
            'vendor_id': vendor_id,
        }

    def _build_cover_page(self, data: Dict) -> list:
        """Build the report cover page."""
        elements = []

        elements.append(Spacer(1, 100))
        elements.append(Paragraph(
            'Third Party Risk Assessment Report',
            self.styles['ReportTitle']
        ))
        elements.append(Spacer(1, 20))
        elements.append(HRFlowable(
            width="80%",
            color=colors.HexColor('#3b82f6'),
            thickness=2,
        ))
        elements.append(Spacer(1, 30))

        # Scope
        scope = 'All Applications'
        if data['application_id']:
            app = next(
                (a for a in data['applications']
                 if a.id == data['application_id']),
                None
            )
            if app:
                scope = f'Application: {app.name}'
        elif data['vendor_id']:
            vendor = next(
                (v for v in data['vendors']
                 if v.id == data['vendor_id']),
                None
            )
            if vendor:
                scope = f'Vendor: {vendor.name}'

        info = [
            f'<b>Scope:</b> {scope}',
            f'<b>Generated:</b> '
            f'{data["generated_at"].strftime("%B %d, %Y %H:%M UTC")}',
            f'<b>Applications Assessed:</b> '
            f'{len(data["applications"])}',
            f'<b>Components Analyzed:</b> '
            f'{len(data["components"])}',
            f'<b>Vulnerabilities Found:</b> '
            f'{len(data["cves"])}',
        ]

        for line in info:
            elements.append(Paragraph(
                line, self.styles['BodyCustom']
            ))

        elements.append(Spacer(1, 50))
        elements.append(Paragraph(
            '<b>CONFIDENTIAL</b> — '
            'For authorized recipients only',
            self.styles['SmallText']
        ))

        return elements

    def _build_executive_summary(self, data: Dict) -> list:
        """Build the executive summary section."""
        elements = []

        elements.append(Paragraph(
            '1. Executive Summary',
            self.styles['SectionHeader']
        ))

        total_apps = len(data['applications'])
        total_cves = len(data['cves'])
        sev = data['severity_counts']
        avg_score = 0
        if data['risk_scores']:
            avg_score = round(
                sum(r.overall_score for r in data['risk_scores'])
                / len(data['risk_scores']),
                1
            )

        # Overall risk rating
        if avg_score >= 8:
            risk_level = 'CRITICAL'
        elif avg_score >= 6:
            risk_level = 'HIGH'
        elif avg_score >= 4:
            risk_level = 'MODERATE'
        else:
            risk_level = 'LOW'

        summary_text = (
            f'This assessment evaluated {total_apps} '
            f'application(s) containing '
            f'{len(data["components"])} third-party components. '
            f'A total of {total_cves} known vulnerabilities '
            f'(CVEs) were identified, including '
            f'{sev["critical"]} critical and '
            f'{sev["high"]} high severity findings. '
            f'The overall risk level is assessed as '
            f'<b>{risk_level}</b> with an average risk score '
            f'of <b>{avg_score}/10</b>.'
        )

        elements.append(Paragraph(
            summary_text, self.styles['BodyCustom']
        ))

        # Summary table
        summary_data = [
            ['Metric', 'Value'],
            ['Applications Assessed', str(total_apps)],
            ['Total Components', str(len(data['components']))],
            ['Total CVEs', str(total_cves)],
            ['Critical CVEs', str(sev['critical'])],
            ['High CVEs', str(sev['high'])],
            ['Medium CVEs', str(sev['medium'])],
            ['Low CVEs', str(sev['low'])],
            ['Average Risk Score', f'{avg_score} / 10'],
            ['Overall Rating', risk_level],
        ]

        table = Table(summary_data, colWidths=[250, 200])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0),
             colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 0.5,
             colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.HexColor('#f8fafc')]),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ]))

        elements.append(Spacer(1, 10))
        elements.append(table)

        return elements

    def _build_risk_overview(self, data: Dict) -> list:
        """Build risk scores section."""
        elements = []

        elements.append(Paragraph(
            '2. Risk Overview',
            self.styles['SectionHeader']
        ))

        if not data['risk_scores']:
            elements.append(Paragraph(
                'No risk scores have been calculated yet. '
                'Run risk assessment for each application.',
                self.styles['BodyCustom']
            ))
            return elements

        risk_data = [
            [
                'Application', 'Risk Score', 'Rating',
                'CVEs', 'Critical',
            ]
        ]

        for rs in sorted(
            data['risk_scores'],
            key=lambda x: x.overall_score,
            reverse=True
        ):
            app = next(
                (a for a in data['applications']
                 if a.id == rs.application_id),
                None
            )
            app_name = app.name if app else f'App #{rs.application_id}'

            risk_data.append([
                app_name,
                f'{rs.overall_score:.1f} / 10',
                rs.rating,
                str(rs.total_cves_found),
                str(rs.critical_cves_count),
            ])

        table = Table(
            risk_data,
            colWidths=[150, 80, 80, 60, 60]
        )
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0),
             colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5,
             colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.HexColor('#f8fafc')]),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))

        elements.append(table)

        return elements

    def _build_application_inventory(
        self,
        data: Dict
    ) -> list:
        """Build application inventory section."""
        elements = []

        elements.append(Paragraph(
            '3. Application Inventory',
            self.styles['SectionHeader']
        ))

        if not data['applications']:
            elements.append(Paragraph(
                'No applications in scope.',
                self.styles['BodyCustom']
            ))
            return elements

        app_data = [
            [
                'Application', 'Criticality',
                'Environment', 'Internet', 'Components',
            ]
        ]

        for app in data['applications']:
            comp_count = sum(
                1 for c in data['components']
                if c.application_id == app.id
            )
            app_data.append([
                app.name,
                app.criticality.value if app.criticality else 'N/A',
                app.environment.value if app.environment else 'N/A',
                'Yes' if app.internet_facing else 'No',
                str(comp_count),
            ])

        table = Table(
            app_data,
            colWidths=[140, 80, 80, 60, 70]
        )
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0),
             colors.HexColor('#1e40af')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5,
             colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.HexColor('#f8fafc')]),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ]))

        elements.append(table)

        return elements

    def _build_vulnerability_findings(
        self,
        data: Dict
    ) -> list:
        """Build CVE findings section."""
        elements = []

        elements.append(Paragraph(
            '4. Vulnerability Findings',
            self.styles['SectionHeader']
        ))

        if not data['cves']:
            elements.append(Paragraph(
                'No vulnerabilities discovered. '
                'Ensure CVE sync has been run for all '
                'components.',
                self.styles['BodyCustom']
            ))
            return elements

        # Show top 25 most critical CVEs
        sorted_cves = sorted(
            data['cves'],
            key=lambda c: c.cvss_score or 0,
            reverse=True
        )[:25]

        cve_data = [
            ['CVE ID', 'CVSS', 'Severity', 'Exploit', 'Patch']
        ]

        for cve in sorted_cves:
            cve_data.append([
                cve.cve_id,
                f'{cve.cvss_score:.1f}' if cve.cvss_score else 'N/A',
                cve.severity or 'Unknown',
                'Yes' if cve.exploit_available else 'No',
                'Yes' if cve.patch_available else 'No',
            ])

        table = Table(
            cve_data,
            colWidths=[130, 50, 70, 50, 50]
        )
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0),
             colors.HexColor('#dc2626')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5,
             colors.HexColor('#cbd5e1')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1),
             [colors.white, colors.HexColor('#fef2f2')]),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ]))

        elements.append(table)

        if len(data['cves']) > 25:
            elements.append(Spacer(1, 6))
            elements.append(Paragraph(
                f'Showing top 25 of {len(data["cves"])} '
                f'total CVEs.',
                self.styles['SmallText']
            ))

        return elements

    def _build_recommendations(self, data: Dict) -> list:
        """Build recommendations section."""
        elements = []

        elements.append(Paragraph(
            '5. Recommendations',
            self.styles['SectionHeader']
        ))

        recommendations = []

        sev = data['severity_counts']
        if sev['critical'] > 0:
            recommendations.append(
                f'<b>IMMEDIATE:</b> Address {sev["critical"]} '
                f'critical severity CVEs within 24-48 hours. '
                f'These represent the highest risk to the '
                f'organization.'
            )

        if sev['high'] > 0:
            recommendations.append(
                f'<b>URGENT:</b> Remediate {sev["high"]} '
                f'high severity CVEs within 7 days.'
            )

        # Check for internet-facing apps with CVEs
        internet_apps = [
            a for a in data['applications']
            if a.internet_facing
        ]
        if internet_apps:
            recommendations.append(
                f'<b>EXPOSURE:</b> {len(internet_apps)} '
                f'internet-facing application(s) require '
                f'priority patching as they are directly '
                f'accessible from the internet.'
            )

        # Check exploit availability
        exploit_cves = [
            c for c in data['cves']
            if c.exploit_available
        ]
        if exploit_cves:
            recommendations.append(
                f'<b>ACTIVE THREAT:</b> {len(exploit_cves)} '
                f'CVE(s) have known exploits available. '
                f'These should be patched immediately as '
                f'attackers can readily exploit them.'
            )

        # General recommendations
        recommendations.extend([
            '<b>PROCESS:</b> Implement automated SBOM '
            'scanning in CI/CD pipelines to detect '
            'vulnerabilities before deployment.',
            '<b>MONITORING:</b> Enable continuous CVE '
            'monitoring to receive alerts when new '
            'vulnerabilities affect registered components.',
            '<b>POLICY:</b> Establish a vulnerability '
            'remediation SLA: Critical within 48 hours, '
            'High within 7 days, Medium within 30 days.',
        ])

        for i, rec in enumerate(recommendations, 1):
            elements.append(Paragraph(
                f'{i}. {rec}',
                self.styles['BodyCustom']
            ))

        return elements

    def _build_risk_matrix(self, data: Dict) -> list:
        """Build visual risk matrix."""
        elements = []

        elements.append(Paragraph(
            '6. Risk Matrix',
            self.styles['SectionHeader']
        ))

        matrix_data = [
            ['Score Range', 'Rating', 'Action Required'],
            ['0.0 – 2.0', 'Low', 'Monitor'],
            ['2.1 – 4.0', 'Moderate', 'Plan remediation'],
            ['4.1 – 6.0', 'High', 'Remediate within 30 days'],
            ['6.1 – 8.0', 'Very High', 'Remediate within 7 days'],
            ['8.1 – 10.0', 'Critical', 'Immediate action required'],
        ]

        row_colors = [
            colors.HexColor('#1e40af'),
            colors.HexColor('#dcfce7'),
            colors.HexColor('#fef9c3'),
            colors.HexColor('#fed7aa'),
            colors.HexColor('#fecaca'),
            colors.HexColor('#fca5a5'),
        ]

        table = Table(matrix_data, colWidths=[100, 100, 230])
        style_commands = [
            ('BACKGROUND', (0, 0), (-1, 0), row_colors[0]),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5,
             colors.HexColor('#cbd5e1')),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]

        for i, color in enumerate(row_colors[1:], 1):
            style_commands.append(
                ('BACKGROUND', (0, i), (-1, i), color)
            )

        table.setStyle(TableStyle(style_commands))
        elements.append(table)

        return elements

    def _build_footer(self, data: Dict) -> list:
        """Build report footer."""
        elements = []

        elements.append(Spacer(1, 30))
        elements.append(HRFlowable(
            width="100%",
            color=colors.HexColor('#cbd5e1'),
        ))
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(
            f'Report generated on '
            f'{data["generated_at"].strftime("%Y-%m-%d %H:%M UTC")} '
            f'by Third Party Risk Assessment Tool.',
            self.styles['SmallText']
        ))
        elements.append(Paragraph(
            'This report is confidential and intended for '
            'authorized recipients only.',
            self.styles['SmallText']
        ))

        return elements


report_service = ReportService()
