"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
PDF Report Generator
Generates professional PDF audit reports with charts, findings, and recommendations.
"""



import os
import sys
from typing import Dict, List, Optional
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class PDFReportGenerator:
    """
    Professional PDF audit report generator
    
    Uses reportlab for PDF generation with:
    - Cover page with logo
    - Executive summary
    - Findings with severity ratings
    - Network topology
    - Credential findings
    - Recommendations
    - Appendices
    """

    def __init__(self):
        self.reportlab_available = False
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            self.reportlab_available = True
        except ImportError:
            logger.warning("reportlab not installed: pip install reportlab")

    def generate(self, worm_stats: Dict, scan_results: List[Dict],
                 infected_hosts: set, failed_targets: set,
                 vuln_findings: List[Dict] = None,
                 credential_findings: List[Dict] = None,
                 lateral_movements: List[Dict] = None,
                 recommendations: List[Dict] = None,
                 output_path: str = "reports/audit_report.pdf") -> str:
        """Generate a professional PDF audit report"""
        if not self.reportlab_available:
            logger.warning("reportlab not available, skipping PDF report")
            return ""

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                PageBreak, ListFlowable, ListItem, KeepTogether
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY

            os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)

            doc = SimpleDocTemplate(
                output_path,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72,
            )

            styles = getSampleStyleSheet()

            # Custom styles
            styles.add(ParagraphStyle(
                name='Title',
                parent=styles['Title'],
                fontSize=24,
                spaceAfter=6,
                textColor=colors.HexColor('#1a1a2e'),
            ))
            styles.add(ParagraphStyle(
                name='SectionHeader',
                parent=styles['Heading1'],
                fontSize=16,
                spaceBefore=20,
                spaceAfter=10,
                textColor=colors.HexColor('#16213e'),
            ))
            styles.add(ParagraphStyle(
                name='SubHeader',
                parent=styles['Heading2'],
                fontSize=13,
                spaceBefore=12,
                spaceAfter=6,
                textColor=colors.HexColor('#0f3460'),
            ))
            styles.add(ParagraphStyle(
                name='Body',
                parent=styles['Normal'],
                fontSize=10,
                spaceAfter=6,
                alignment=TA_JUSTIFY,
            ))

            story = []

            # === COVER PAGE ===
            story.append(Spacer(1, 3*inch))
            story.append(Paragraph("Wormy ML Network Worm", styles['Title']))
            story.append(Paragraph("Security Audit Report", ParagraphStyle(
                'Subtitle', parent=styles['Normal'], fontSize=18,
                textColor=colors.HexColor('#0f3460'), alignment=TA_CENTER,
            )))
            story.append(Spacer(1, 0.5*inch))
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ParagraphStyle(
                'Date', parent=styles['Normal'], fontSize=12, alignment=TA_CENTER,
            )))
            story.append(Paragraph("CONFIDENTIAL", ParagraphStyle(
                'Conf', parent=styles['Normal'], fontSize=14, textColor=colors.red,
                alignment=TA_CENTER, spaceBefore=inch,
            )))
            story.append(PageBreak())

            # === EXECUTIVE SUMMARY ===
            story.append(Paragraph("Executive Summary", styles['SectionHeader']))

            total_hosts = worm_stats.get('total_hosts_discovered', 0)
            total_infected = len(infected_hosts)
            total_failed = len(failed_targets)
            success_rate = (total_infected / max(total_infected + total_failed, 1)) * 100

            summary_data = [
                ['Metric', 'Value'],
                ['Total Hosts Discovered', str(total_hosts)],
                ['Hosts Compromised', str(total_infected)],
                ['Failed Attempts', str(total_failed)],
                ['Success Rate', f'{success_rate:.1f}%'],
                ['Vulnerabilities Found', str(len(vuln_findings or []))],
                ['Credentials Discovered', str(len(credential_findings or []))],
                ['Lateral Movements', str(len(lateral_movements or []))],
            ]

            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.3*inch))

            story.append(Paragraph("Overview", styles['SubHeader']))
            story.append(Paragraph(
                f"This report documents the findings of an authorized security assessment conducted "
                f"using the Wormy ML Network Worm platform. The assessment identified {total_infected} "
                f"compromised hosts out of {total_hosts} discovered, with a success rate of {success_rate:.1f}%. "
                f"A total of {len(vuln_findings or [])} vulnerabilities were identified, "
                f"{len(credential_findings or [])} credential sets were discovered, and "
                f"{len(lateral_movements or [])} lateral movement paths were exploited.",
                styles['Body']
            ))

            # === VULNERABILITY FINDINGS ===
            if vuln_findings:
                story.append(PageBreak())
                story.append(Paragraph("Vulnerability Findings", styles['SectionHeader']))

                for i, vuln in enumerate(vuln_findings[:20], 1):
                    severity = vuln.get('severity', 'UNKNOWN')
                    sev_color = {
                        'CRITICAL': colors.red,
                        'HIGH': colors.HexColor('#ff6600'),
                        'MEDIUM': colors.HexColor('#ffcc00'),
                        'LOW': colors.green,
                    }.get(severity, colors.grey)

                    story.append(Paragraph(
                        f"{i}. {vuln.get('name', 'Unknown')} "
                        f"<font color='red'>[{severity}]</font> "
                        f"(CVSS: {vuln.get('cvss', 'N/A')})",
                        styles['SubHeader']
                    ))
                    story.append(Paragraph(f"<b>CVE:</b> {vuln.get('cve', 'N/A')}", styles['Body']))
                    story.append(Paragraph(f"<b>Description:</b> {vuln.get('description', 'N/A')}", styles['Body']))
                    story.append(Paragraph(f"<b>Remediation:</b> {vuln.get('remediation', 'N/A')}", styles['Body']))
                    story.append(Spacer(1, 0.1*inch))

            # === CREDENTIAL FINDINGS ===
            if credential_findings:
                story.append(PageBreak())
                story.append(Paragraph("Credential Findings", styles['SectionHeader']))

                cred_data = [['#', 'Host', 'Username', 'Service', 'Source']]
                for i, cred in enumerate(credential_findings[:30], 1):
                    cred_data.append([
                        str(i),
                        cred.get('host', ''),
                        cred.get('username', ''),
                        cred.get('service', ''),
                        cred.get('source', ''),
                    ])

                cred_table = Table(cred_data, colWidths=[0.4*inch, 1.5*inch, 1.2*inch, 1.2*inch, 1.2*inch])
                cred_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#16213e')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f0f0f0')]),
                ]))
                story.append(cred_table)

            # === RECOMMENDATIONS ===
            if recommendations:
                story.append(PageBreak())
                story.append(Paragraph("Recommendations", styles['SectionHeader']))

                for i, rec in enumerate(recommendations, 1):
                    severity = rec.get('severity', 'INFO')
                    story.append(Paragraph(
                        f"{i}. [{severity}] {rec.get('category', 'General')}",
                        styles['SubHeader']
                    ))
                    story.append(Paragraph(f"<b>Finding:</b> {rec.get('finding', '')}", styles['Body']))
                    story.append(Paragraph(f"<b>Remediation:</b> {rec.get('remediation', '')}", styles['Body']))
                    story.append(Spacer(1, 0.1*inch))

            # Build PDF
            doc.build(story)
            logger.info(f"PDF report generated: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")
            return ""
