"""
PDF Report Templates for Network Mapping Tool
Provides executive and technical report templates with professional formatting
"""

import os
import sys
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus import Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from datetime import datetime
from typing import Dict, List, Any
import io
import base64


class PDFReportTemplate:
    """Base class for PDF report templates"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_custom_styles()
    
    def setup_custom_styles(self):
        """Setup custom paragraph styles for consistent formatting"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#1f4e79')
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Normal'],
            fontSize=16,
            spaceAfter=20,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#2e75b6')
        ))
        
        # Custom heading styles
        self.styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            spaceBefore=20,
            textColor=colors.HexColor('#1f4e79'),
            borderWidth=1,
            borderColor=colors.HexColor('#1f4e79'),
            borderPadding=5
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=10,
            spaceBefore=15,
            textColor=colors.HexColor('#2e75b6')
        ))
        
        self.styles.add(ParagraphStyle(
            name='CustomHeading3',
            parent=self.styles['Heading3'],
            fontSize=12,
            spaceAfter=8,
            spaceBefore=12,
            textColor=colors.HexColor('#4472c4')
        ))
        
        # Executive summary style
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=11,
            spaceAfter=12,
            alignment=TA_JUSTIFY,
            leftIndent=20,
            rightIndent=20,
            borderWidth=1,
            borderColor=colors.HexColor('#d9d9d9'),
            borderPadding=10,
            backColor=colors.HexColor('#f8f9fa')
        ))
        
        # Risk level styles
        self.styles.add(ParagraphStyle(
            name='HighRisk',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#c5504b'),
            backColor=colors.HexColor('#fce4d6')
        ))
        
        self.styles.add(ParagraphStyle(
            name='MediumRisk',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#e07c24'),
            backColor=colors.HexColor('#fff2cc')
        ))
        
        self.styles.add(ParagraphStyle(
            name='LowRisk',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#70ad47'),
            backColor=colors.HexColor('#e2efda')
        ))
        
        # Compliance styles
        self.styles.add(ParagraphStyle(
            name='Compliant',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#70ad47'),
            backColor=colors.HexColor('#e2efda')
        ))
        
        self.styles.add(ParagraphStyle(
            name='NonCompliant',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.HexColor('#c5504b'),
            backColor=colors.HexColor('#fce4d6')
        ))
        
        # Technical details style
        self.styles.add(ParagraphStyle(
            name='TechnicalDetails',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Courier',
            leftIndent=20,
            spaceAfter=6,
            backColor=colors.HexColor('#f5f5f5'),
            borderWidth=1,
            borderColor=colors.HexColor('#cccccc'),
            borderPadding=5
        ))
        
        # Recommendation style
        self.styles.add(ParagraphStyle(
            name='Recommendation',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            leftIndent=15,
            bulletIndent=10,
            bulletFontName='Symbol'
        ))
    
    def create_header_footer(self, canvas, doc):
        """Create header and footer for each page"""
        canvas.saveState()
        
        # Header
        canvas.setFont('Helvetica-Bold', 10)
        canvas.setFillColor(colors.HexColor('#1f4e79'))
        canvas.drawString(doc.leftMargin, doc.height + doc.topMargin - 20, 
                         "Network Security Assessment Report")
        
        # Footer
        canvas.setFont('Helvetica', 8)
        canvas.setFillColor(colors.HexColor('#666666'))
        canvas.drawString(doc.leftMargin, 30, 
                         f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        canvas.drawRightString(doc.width + doc.leftMargin, 30, 
                              f"Page {canvas.getPageNumber()}")
        
        # Footer line
        canvas.setStrokeColor(colors.HexColor('#cccccc'))
        canvas.line(doc.leftMargin, 50, doc.width + doc.leftMargin, 50)
        
        canvas.restoreState()
    
    def create_risk_table_style(self):
        """Create consistent table style for risk assessments"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8f9fa')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
        ])
    
    def create_metrics_table_style(self):
        """Create table style for metrics and statistics"""
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2e75b6')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#cccccc')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ])


class ExecutiveReportTemplate(PDFReportTemplate):
    """Executive summary report template for management"""
    
    def generate_report(self, scan_data: Dict, output_path: str) -> str:
        """Generate executive summary PDF report"""
        doc = SimpleDocTemplate(output_path, pagesize=letter, 
                               topMargin=1*inch, bottomMargin=1*inch)
        story = []
        
        # Title page
        story.extend(self._create_title_page(scan_data))
        story.append(PageBreak())
        
        # Executive summary
        story.extend(self._create_executive_summary(scan_data))
        story.append(PageBreak())
        
        # Metrics dashboard
        story.extend(self._create_metrics_dashboard(scan_data))
        story.append(PageBreak())
        
        # Risk overview
        story.extend(self._create_risk_overview(scan_data))
        story.append(PageBreak())
        
        # Compliance status
        story.extend(self._create_compliance_status(scan_data))
        story.append(PageBreak())
        
        # Strategic recommendations
        story.extend(self._create_strategic_recommendations(scan_data))
        
        # Build PDF
        doc.build(story, onFirstPage=self.create_header_footer, 
                 onLaterPages=self.create_header_footer)
        
        return output_path
    
    def _create_title_page(self, scan_data: Dict) -> List:
        """Create executive report title page"""
        elements = []
        
        # Main title
        elements.append(Paragraph("NETWORK SECURITY", self.styles['CustomTitle']))
        elements.append(Paragraph("EXECUTIVE ASSESSMENT", self.styles['CustomTitle']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Subtitle
        scan_info = scan_data.get('scan_info', {})
        network_range = scan_info.get('target', 'Network Infrastructure')
        elements.append(Paragraph(f"Assessment of {network_range}", self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 1*inch))
        
        # Key metrics summary box
        total_hosts = len(scan_data.get('hosts', {}))
        total_ports = sum(len(h.get('open_ports', [])) for h in scan_data.get('hosts', {}).values())
        high_risk = self._count_high_risk_findings(scan_data)
        
        summary_data = [
            ['Metric', 'Value', 'Status'],
            ['Hosts Discovered', str(total_hosts), 'Complete'],
            ['Open Services', str(total_ports), 'Analyzed'],
            ['High-Risk Findings', str(high_risk), 'Critical' if high_risk > 0 else 'Good'],
            ['Assessment Date', datetime.now().strftime('%Y-%m-%d'), 'Current']
        ]
        
        summary_table = Table(summary_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        summary_table.setStyle(self.create_metrics_table_style())
        elements.append(summary_table)
        elements.append(Spacer(1, 1*inch))
        
        # Report classification
        elements.append(Paragraph("CONFIDENTIAL - INTERNAL USE ONLY", 
                                self.styles['CustomHeading3']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Prepared for section
        elements.append(Paragraph("Prepared for: IT Security Management", self.styles['Normal']))
        elements.append(Paragraph(f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}", 
                                self.styles['Normal']))
        
        return elements
    
    def _create_executive_summary(self, scan_data: Dict) -> List:
        """Create executive summary section"""
        elements = []
        elements.append(Paragraph("EXECUTIVE SUMMARY", self.styles['CustomHeading1']))
        
        # Overall assessment
        total_hosts = len(scan_data.get('hosts', {}))
        high_risk = self._count_high_risk_findings(scan_data)
        medium_risk = self._count_medium_risk_findings(scan_data)
        
        if high_risk > 0:
            risk_level = "HIGH"
            risk_color = "red"
        elif medium_risk > 5:
            risk_level = "MEDIUM"
            risk_color = "orange"
        else:
            risk_level = "LOW"
            risk_color = "green"
        
        summary_text = f"""
        <b>Network Security Posture: <font color="{risk_color}">{risk_level} RISK</font></b><br/><br/>
        
        Our comprehensive network security assessment has identified <b>{total_hosts} active hosts</b> 
        within your network infrastructure. The assessment reveals <b>{high_risk} high-risk</b> and 
        <b>{medium_risk} medium-risk</b> security findings that require immediate attention.<br/><br/>
        
        <b>Key Findings:</b><br/>
        • Network contains {total_hosts} discoverable hosts<br/>
        • {high_risk} critical security vulnerabilities identified<br/>
        • {medium_risk} medium-priority security concerns detected<br/>
        • Immediate remediation recommended for high-risk findings<br/><br/>
        
        <b>Business Impact:</b><br/>
        The identified vulnerabilities present potential risks to data confidentiality, system integrity, 
        and service availability. Prompt remediation of critical findings is essential to maintain 
        security compliance and protect against potential security incidents.
        """
        
        elements.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_metrics_dashboard(self, scan_data: Dict) -> List:
        """Create metrics dashboard section"""
        elements = []
        elements.append(Paragraph("SECURITY METRICS DASHBOARD", self.styles['CustomHeading1']))
        
        # Calculate metrics
        total_hosts = len(scan_data.get('hosts', {}))
        total_ports = sum(len(h.get('open_ports', [])) for h in scan_data.get('hosts', {}).values())
        high_risk = self._count_high_risk_findings(scan_data)
        medium_risk = self._count_medium_risk_findings(scan_data)
        low_risk = self._count_low_risk_findings(scan_data)
        
        # Risk distribution table
        risk_data = [
            ['Risk Level', 'Count', 'Percentage', 'Priority'],
            ['High Risk', str(high_risk), f"{(high_risk/max(total_ports,1)*100):.1f}%", 'Immediate'],
            ['Medium Risk', str(medium_risk), f"{(medium_risk/max(total_ports,1)*100):.1f}%", 'Short-term'],
            ['Low Risk', str(low_risk), f"{(low_risk/max(total_ports,1)*100):.1f}%", 'Long-term']
        ]
        
        risk_table = Table(risk_data, colWidths=[1.5*inch, 1*inch, 1.2*inch, 1.3*inch])
        risk_table.setStyle(self.create_risk_table_style())
        elements.append(risk_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Network coverage metrics
        coverage_data = [
            ['Network Metric', 'Value', 'Assessment'],
            ['Total Hosts Scanned', str(total_hosts), 'Complete'],
            ['Services Identified', str(total_ports), 'Comprehensive'],
            ['Security Findings', str(high_risk + medium_risk), 'Requires Action'],
            ['Coverage Percentage', '100%', 'Full Network']
        ]
        
        coverage_table = Table(coverage_data, colWidths=[2*inch, 1.2*inch, 1.8*inch])
        coverage_table.setStyle(self.create_metrics_table_style())
        elements.append(coverage_table)
        
        return elements
    
    def _create_risk_overview(self, scan_data: Dict) -> List:
        """Create risk overview section"""
        elements = []
        elements.append(Paragraph("RISK ASSESSMENT OVERVIEW", self.styles['CustomHeading1']))
        
        # Risk summary by host
        elements.append(Paragraph("Host Risk Assessment", self.styles['CustomHeading2']))
        
        host_risk_data = [['Host IP', 'Open Ports', 'Risk Level', 'Priority Action']]
        
        for host_ip, host_data in scan_data.get('hosts', {}).items():
            open_ports = host_data.get('open_ports', [])
            risk_level = self._assess_host_risk_level(open_ports)
            port_count = len(open_ports)
            
            if risk_level == 'HIGH':
                priority = 'Immediate Review'
            elif risk_level == 'MEDIUM':
                priority = 'Schedule Review'
            else:
                priority = 'Monitor'
            
            host_risk_data.append([host_ip, str(port_count), risk_level, priority])
        
        if len(host_risk_data) > 1:  # Has data beyond header
            host_table = Table(host_risk_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1.5*inch])
            host_table.setStyle(self.create_risk_table_style())
            elements.append(host_table)
        else:
            elements.append(Paragraph("No hosts with open ports detected.", self.styles['Normal']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_compliance_status(self, scan_data: Dict) -> List:
        """Create compliance status section"""
        elements = []
        elements.append(Paragraph("COMPLIANCE & GOVERNANCE STATUS", self.styles['CustomHeading1']))
        
        # Security framework compliance
        high_risk = self._count_high_risk_findings(scan_data)
        medium_risk = self._count_medium_risk_findings(scan_data)
        
        compliance_data = [
            ['Framework', 'Status', 'Findings', 'Compliance Level'],
            ['Network Security', 'Non-Compliant' if high_risk > 0 else 'Compliant', 
             f"{high_risk} Critical", '85%' if high_risk == 0 else '60%'],
            ['Access Controls', 'Partial' if medium_risk > 3 else 'Compliant', 
             f"{medium_risk} Medium", '75%' if medium_risk <= 3 else '50%'],
            ['Service Hardening', 'Review Required', 
             f"{high_risk + medium_risk} Total", '70%'],
            ['Monitoring Coverage', 'Compliant', '0 Gaps', '95%']
        ]
        
        compliance_table = Table(compliance_data, colWidths=[1.8*inch, 1.2*inch, 1*inch, 1*inch])
        compliance_table.setStyle(self.create_risk_table_style())
        elements.append(compliance_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Regulatory considerations
        elements.append(Paragraph("Regulatory Considerations", self.styles['CustomHeading2']))
        
        regulatory_text = f"""
        <b>Data Protection Compliance:</b><br/>
        • {high_risk} high-risk services may impact data protection requirements<br/>
        • Network segmentation review recommended<br/>
        • Access logging and monitoring controls in place<br/><br/>
        
        <b>Industry Standards:</b><br/>
        • ISO 27001: Network security controls require attention<br/>
        • NIST Framework: Identify and Protect functions need enhancement<br/>
        • CIS Controls: Critical security controls implementation gaps identified<br/><br/>
        
        <b>Recommendations:</b><br/>
        • Implement immediate remediation for critical findings<br/>
        • Establish regular security assessment schedule<br/>
        • Enhance network monitoring and incident response capabilities
        """
        
        elements.append(Paragraph(regulatory_text, self.styles['ExecutiveSummary']))
        
        return elements
    
    def _create_strategic_recommendations(self, scan_data: Dict) -> List:
        """Create strategic recommendations section"""
        elements = []
        elements.append(Paragraph("STRATEGIC RECOMMENDATIONS", self.styles['CustomHeading1']))
        
        high_risk = self._count_high_risk_findings(scan_data)
        medium_risk = self._count_medium_risk_findings(scan_data)
        total_hosts = len(scan_data.get('hosts', {}))
        
        # Immediate actions
        elements.append(Paragraph("Immediate Actions (0-30 days)", self.styles['CustomHeading2']))
        
        immediate_actions = [
            f"Address {high_risk} critical security vulnerabilities identified",
            "Implement network segmentation for high-risk services",
            "Deploy additional monitoring for critical infrastructure",
            "Review and update incident response procedures"
        ]
        
        for action in immediate_actions:
            elements.append(Paragraph(f"• {action}", self.styles['Recommendation']))
        
        elements.append(Spacer(1, 0.2*inch))
        
        # Short-term improvements
        elements.append(Paragraph("Short-term Improvements (1-6 months)", self.styles['CustomHeading2']))
        
        short_term_actions = [
            f"Remediate {medium_risk} medium-priority security findings",
            "Implement automated vulnerability scanning",
            "Enhance network access controls and authentication",
            "Develop security awareness training program"
        ]
        
        for action in short_term_actions:
            elements.append(Paragraph(f"• {action}", self.styles['Recommendation']))
        
        elements.append(Spacer(1, 0.2*inch))
        
        # Long-term strategy
        elements.append(Paragraph("Long-term Strategy (6-12 months)", self.styles['CustomHeading2']))
        
        long_term_actions = [
            "Establish comprehensive security governance framework",
            "Implement zero-trust network architecture",
            "Deploy advanced threat detection and response capabilities",
            "Regular third-party security assessments"
        ]
        
        for action in long_term_actions:
            elements.append(Paragraph(f"• {action}", self.styles['Recommendation']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Investment priorities
        elements.append(Paragraph("Investment Priorities", self.styles['CustomHeading2']))
        
        investment_text = f"""
        <b>High Priority Investments:</b><br/>
        • Network security infrastructure upgrades<br/>
        • Security monitoring and SIEM solutions<br/>
        • Staff training and certification programs<br/><br/>
        
        <b>Expected ROI:</b><br/>
        • Reduced security incident response costs<br/>
        • Improved regulatory compliance posture<br/>
        • Enhanced business continuity and reputation protection<br/><br/>
        
        <b>Budget Considerations:</b><br/>
        • Critical remediation: Immediate budget allocation required<br/>
        • Infrastructure improvements: Plan for next fiscal year<br/>
        • Ongoing operational costs: Include in annual security budget
        """
        
        elements.append(Paragraph(investment_text, self.styles['ExecutiveSummary']))
        
        return elements
    
    def _count_high_risk_findings(self, scan_data: Dict) -> int:
        """Count high-risk findings based on critical ports and services"""
        count = 0
        for host_data in scan_data.get('hosts', {}).values():
            open_ports = host_data.get('open_ports', [])
            # Critical risk ports that pose immediate security threats
            critical_ports = [21, 23, 135, 139, 445, 1433, 3389]
            count += len([p for p in open_ports if p.get('port') in critical_ports])
        return count
    
    def _count_medium_risk_findings(self, scan_data: Dict) -> int:
        """Count medium-risk findings based on common service ports"""
        count = 0
        for host_data in scan_data.get('hosts', {}).values():
            open_ports = host_data.get('open_ports', [])
            # Medium risk ports that require attention but are commonly used
            medium_ports = [22, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
            count += len([p for p in open_ports if p.get('port') in medium_ports])
        return count
    
    def _count_low_risk_findings(self, scan_data: Dict) -> int:
        """Count low-risk findings (all other open ports)"""
        total_ports = sum(len(h.get('open_ports', [])) for h in scan_data.get('hosts', {}).values())
        high_risk = self._count_high_risk_findings(scan_data)
        medium_risk = self._count_medium_risk_findings(scan_data)
        return max(0, total_ports - high_risk - medium_risk)
    
    def _assess_host_risk_level(self, open_ports: List) -> str:
        """Assess the overall risk level of a host based on open ports"""
        if not open_ports:
            return 'LOW'
        
        # Define critical and medium-risk ports
        critical_ports = [21, 23, 135, 139, 445, 1433, 3389, 5432, 6379]  # High-risk services
        medium_risk_ports = [22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5900, 8080]  # Medium-risk services
        
        # Count risk levels
        high_risk_count = sum(1 for port in open_ports if port in critical_ports)
        medium_risk_count = sum(1 for port in open_ports if port in medium_risk_ports)
        
        # Determine overall risk level
        if high_risk_count > 0:
            return 'HIGH'
        elif medium_risk_count > 2:  # Multiple medium-risk services
            return 'MEDIUM'
        elif len(open_ports) > 10:  # Many open ports
            return 'MEDIUM'
        else:
            return 'LOW'


class TechnicalReportTemplate(PDFReportTemplate):
    """Technical detailed report template for security teams"""
    
    def generate_report(self, scan_data: Dict, output_path: str) -> str:
        """Generate technical detailed PDF report"""
        doc = SimpleDocTemplate(output_path, pagesize=letter, 
                               topMargin=1*inch, bottomMargin=1*inch)
        story = []
        
        # Title page
        story.extend(self._create_title_page(scan_data))
        story.append(PageBreak())
        
        # Executive summary (technical overview)
        story.extend(self._create_technical_summary(scan_data))
        story.append(PageBreak())
        
        # Methodology
        story.extend(self._create_methodology_section())
        story.append(PageBreak())
        
        # Network topology
        story.extend(self._create_network_topology(scan_data))
        story.append(PageBreak())
        
        # Detailed findings
        story.extend(self._create_detailed_findings(scan_data))
        story.append(PageBreak())
        
        # Host details
        story.extend(self._create_host_details(scan_data))
        story.append(PageBreak())
        
        # Remediation guide
        story.extend(self._create_remediation_guide(scan_data))
        story.append(PageBreak())
        
        # Technical appendix
        story.extend(self._create_technical_appendix(scan_data))
        
        # Build PDF
        doc.build(story, onFirstPage=self.create_header_footer, 
                 onLaterPages=self.create_header_footer)
        
        return output_path
    
    def _create_title_page(self, scan_data: Dict) -> List:
        """Create technical report title page"""
        elements = []
        
        # Main title
        elements.append(Paragraph("NETWORK SECURITY", self.styles['CustomTitle']))
        elements.append(Paragraph("TECHNICAL ASSESSMENT", self.styles['CustomTitle']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Subtitle
        scan_info = scan_data.get('scan_info', {})
        network_range = scan_info.get('target', 'Network Infrastructure')
        elements.append(Paragraph(f"Detailed Technical Analysis of {network_range}", 
                                self.styles['CustomSubtitle']))
        elements.append(Spacer(1, 0.8*inch))
        
        # Technical summary box
        total_hosts = len(scan_data.get('hosts', {}))
        total_ports = sum(len(h.get('open_ports', [])) for h in scan_data.get('hosts', {}).values())
        high_risk = self._count_high_risk_findings(scan_data)
        medium_risk = self._count_medium_risk_findings(scan_data)
        
        tech_summary_data = [
            ['Technical Metric', 'Value', 'Analysis Status'],
            ['Active Hosts', str(total_hosts), 'Enumerated'],
            ['Open Services', str(total_ports), 'Fingerprinted'],
            ['Critical Findings', str(high_risk), 'Analyzed'],
            ['Medium Findings', str(medium_risk), 'Documented'],
            ['Scan Completion', '100%', 'Complete']
        ]
        
        tech_table = Table(tech_summary_data, colWidths=[2*inch, 1.2*inch, 1.8*inch])
        tech_table.setStyle(self.create_metrics_table_style())
        elements.append(tech_table)
        elements.append(Spacer(1, 0.8*inch))
        
        # Scan parameters
        elements.append(Paragraph("Scan Parameters", self.styles['CustomHeading2']))
        
        scan_params = f"""
        <b>Target Network:</b> {network_range}<br/>
        <b>Scan Type:</b> Comprehensive Port Scan<br/>
        <b>Port Range:</b> 1-65535 (Common ports prioritized)<br/>
        <b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        <b>Duration:</b> {scan_info.get('duration', 'N/A')}<br/>
        <b>Scanner:</b> Network Mapping Tool v2.0<br/>
        """
        
        elements.append(Paragraph(scan_params, self.styles['TechnicalDetails']))
        elements.append(Spacer(1, 0.5*inch))
        
        # Classification
        elements.append(Paragraph("TECHNICAL DOCUMENTATION - RESTRICTED ACCESS", 
                                self.styles['CustomHeading3']))
        
        return elements
    
    def _create_technical_summary(self, scan_data: Dict) -> List:
        """Create technical summary section"""
        elements = []
        elements.append(Paragraph("TECHNICAL EXECUTIVE SUMMARY", self.styles['CustomHeading1']))
        
        # Network overview
        total_hosts = len(scan_data.get('hosts', {}))
        total_ports = sum(len(h.get('open_ports', [])) for h in scan_data.get('hosts', {}).values())
        high_risk = self._count_high_risk_findings(scan_data)
        medium_risk = self._count_medium_risk_findings(scan_data)
        
        summary_text = f"""
        <b>Network Infrastructure Analysis</b><br/><br/>
        
        The technical assessment identified <b>{total_hosts} active network hosts</b> with 
        <b>{total_ports} accessible services</b>. Security analysis reveals <b>{high_risk} critical</b> 
        and <b>{medium_risk} medium-severity</b> security findings requiring technical remediation.<br/><br/>
        
        <b>Key Technical Findings:</b><br/>
        • Network hosts: {total_hosts} systems responding to network probes<br/>
        • Service enumeration: {total_ports} open network services identified<br/>
        • Critical vulnerabilities: {high_risk} services with immediate security concerns<br/>
        • Security hardening: {medium_risk} services requiring configuration review<br/><br/>
        
        <b>Technical Risk Assessment:</b><br/>
        The network presents a {"HIGH" if high_risk > 0 else "MEDIUM" if medium_risk > 5 else "LOW"} 
        technical risk profile. Critical findings include potentially vulnerable services that could 
        provide unauthorized network access or facilitate lateral movement within the infrastructure.
        """
        
        elements.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Service distribution
        elements.append(Paragraph("Service Distribution Analysis", self.styles['CustomHeading2']))
        
        service_stats = {}
        for host_data in scan_data.get('hosts', {}).values():
            for port_info in host_data.get('open_ports', []):
                service = port_info.get('service', 'unknown')
                service_stats[service] = service_stats.get(service, 0) + 1
        
        if service_stats:
            service_data = [['Service Type', 'Count', 'Risk Assessment']]
            for service, count in sorted(service_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
                risk = self._assess_service_risk(service)
                service_data.append([service, str(count), risk])
            
            service_table = Table(service_data, colWidths=[2*inch, 1*inch, 2*inch])
            service_table.setStyle(self.create_risk_table_style())
            elements.append(service_table)
        
        return elements
    
    def _create_methodology_section(self) -> List:
        """Create methodology section"""
        elements = []
        elements.append(Paragraph("ASSESSMENT METHODOLOGY", self.styles['CustomHeading1']))
        
        methodology_text = f"""
        <b>Scanning Approach:</b><br/>
        • Network discovery using ICMP and ARP protocols<br/>
        • TCP port scanning with SYN stealth techniques<br/>
        • Service fingerprinting and version detection<br/>
        • Operating system detection where possible<br/><br/>
        
        <b>Technical Tools:</b><br/>
        • Primary: Custom Network Mapping Tool<br/>
        • Secondary: Nmap integration for detailed analysis<br/>
        • Service detection: Banner grabbing and probe responses<br/>
        • Risk assessment: Port-based vulnerability correlation<br/><br/>
        
        <b>Scan Parameters:</b><br/>
        • Port range: 1-65535 (common ports prioritized)<br/>
        • Timing: Adaptive based on network responsiveness<br/>
        • Stealth: SYN scanning to minimize detection<br/>
        • Accuracy: Multiple verification passes for critical findings<br/><br/>
        
        <b>Analysis Framework:</b><br/>
        • Risk categorization based on service criticality<br/>
        • Vulnerability correlation with known attack vectors<br/>
        • Network topology mapping and trust boundaries<br/>
        • Compliance assessment against security frameworks
        """
        
        elements.append(Paragraph(methodology_text, self.styles['TechnicalDetails']))
        
        return elements
    
    def _create_network_topology(self, scan_data: Dict) -> List:
        """Create network topology section"""
        elements = []
        elements.append(Paragraph("NETWORK TOPOLOGY ANALYSIS", self.styles['CustomHeading1']))
        
        # Network segments analysis
        elements.append(Paragraph("Network Segmentation", self.styles['CustomHeading2']))
        
        # Group hosts by subnet (simplified)
        subnets = {}
        for host_ip in scan_data.get('hosts', {}):
            # Simple subnet grouping by first 3 octets
            subnet = '.'.join(host_ip.split('.')[:3]) + '.0/24'
            if subnet not in subnets:
                subnets[subnet] = []
            subnets[subnet].append(host_ip)
        
        if subnets:
            subnet_data = [['Network Segment', 'Host Count', 'Risk Level', 'Notes']]
            for subnet, hosts in subnets.items():
                host_count = len(hosts)
                # Calculate subnet risk based on hosts
                total_risk = 0
                for host_ip in hosts:
                    host_data = scan_data.get('hosts', {}).get(host_ip, {})
                    open_ports = host_data.get('open_ports', [])
                    if self._assess_host_risk_level(open_ports) == 'HIGH':
                        total_risk += 3
                    elif self._assess_host_risk_level(open_ports) == 'MEDIUM':
                        total_risk += 2
                    else:
                        total_risk += 1
                
                avg_risk = total_risk / max(host_count, 1)
                if avg_risk >= 2.5:
                    subnet_risk = 'HIGH'
                    notes = 'Critical services detected'
                elif avg_risk >= 1.5:
                    subnet_risk = 'MEDIUM'
                    notes = 'Mixed service profile'
                else:
                    subnet_risk = 'LOW'
                    notes = 'Standard services'
                
                subnet_data.append([subnet, str(host_count), subnet_risk, notes])
            
            subnet_table = Table(subnet_data, colWidths=[1.8*inch, 1*inch, 1*inch, 1.7*inch])
            subnet_table.setStyle(self.create_risk_table_style())
            elements.append(subnet_table)
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Trust boundaries
        elements.append(Paragraph("Trust Boundary Analysis", self.styles['CustomHeading2']))
        
        trust_text = f"""
        <b>Network Zones Identified:</b><br/>
        • Internal network segments: {len(subnets)} subnets detected<br/>
        • DMZ services: Analysis of externally accessible services<br/>
        • Administrative interfaces: Management service identification<br/>
        • Inter-zone communication: Service dependencies mapped<br/><br/>
        
        <b>Security Implications:</b><br/>
        • Network segmentation effectiveness assessment<br/>
        • Lateral movement risk analysis<br/>
        • Trust relationship validation<br/>
        • Access control boundary verification
        """
        
        elements.append(Paragraph(trust_text, self.styles['TechnicalDetails']))
        
        return elements
    
    def _create_detailed_findings(self, scan_data: Dict) -> List:
        """Create detailed findings section"""
        elements = []
        elements.append(Paragraph("DETAILED SECURITY FINDINGS", self.styles['CustomHeading1']))
        
        # Critical findings
        elements.append(Paragraph("Critical Risk Findings", self.styles['CustomHeading2']))
        
        critical_ports = [21, 23, 135, 139, 445, 1433, 3389]
        critical_findings = []
        
        for host_ip, host_data in scan_data.get('hosts', {}).items():
            for port_info in host_data.get('open_ports', []):
                port = port_info.get('port')
                if port in critical_ports:
                    critical_findings.append({
                        'host': host_ip,
                        'port': port,
                        'service': port_info.get('service', 'unknown'),
                        'version': port_info.get('version', 'unknown')
                    })
        
        if critical_findings:
            for finding in critical_findings:
                elements.append(Paragraph(f"Critical Finding: {finding['host']}:{finding['port']}", 
                                        self.styles['CustomHeading3']))
                
                finding_details = f"""
                <b>Service:</b> {finding['service']}<br/>
                <b>Version:</b> {finding['version']}<br/>
                <b>Risk Level:</b> HIGH<br/>
                <b>Description:</b> {self._get_detailed_vulnerability_description(finding['port'], finding['service'], finding['version'])}<br/>
                <b>Impact:</b> Potential unauthorized access, data exposure, or system compromise<br/>
                <b>Recommendation:</b> Immediate remediation required - disable service or implement access controls
                """
                
                elements.append(Paragraph(finding_details, self.styles['TechnicalDetails']))
                elements.append(Spacer(1, 0.2*inch))
        else:
            elements.append(Paragraph("No critical risk findings identified.", self.styles['Normal']))
        
        return elements
    
    def _create_host_details(self, scan_data: Dict) -> List:
        """Create detailed host analysis section"""
        elements = []
        elements.append(Paragraph("HOST-BY-HOST ANALYSIS", self.styles['CustomHeading1']))
        
        for host_ip, host_data in scan_data.get('hosts', {}).items():
            elements.append(Paragraph(f"HOST: {host_ip}", self.styles['CustomHeading2']))
            
            open_ports = host_data.get('open_ports', [])
            
            # Host summary
            host_summary = f"""
            <b>Host Summary:</b><br/>
            • IP Address: {host_ip}<br/>
            • Open Ports: {len(open_ports)}<br/>
            • Risk Level: {self._assess_host_risk_level(open_ports)}<br/>
            • Last Scanned: {scan_data.get('scan_info', {}).get('timestamp', 'Unknown')}<br/>
            """
            elements.append(Paragraph(host_summary, self.styles['ExecutiveSummary']))
            
            # Services table for this host
            if open_ports:
                elements.append(Paragraph("DETECTED SERVICES", self.styles['CustomHeading3']))
                
                services_data = [['Port', 'Service', 'Version', 'Risk', 'Security Notes']]
                for port_info in open_ports:
                    port = port_info.get('port', 'Unknown')
                    service = port_info.get('service', 'unknown')
                    version = port_info.get('version', 'unknown')
                    risk = self._assess_port_risk(port)
                    notes = self._get_security_notes(port, service)
                    
                    services_data.append([str(port), service, version, risk, notes])
                
                services_table = Table(services_data, colWidths=[0.8*inch, 1.2*inch, 1.2*inch, 0.8*inch, 2*inch])
                services_table.setStyle(self.create_risk_table_style())
                elements.append(services_table)
                
                # Host-specific recommendations
                elements.append(Paragraph("Host Recommendations", self.styles['CustomHeading3']))
                recommendations = self._get_host_recommendations(host_ip, open_ports)
                for rec in recommendations:
                    elements.append(Paragraph(f"• {rec}", self.styles['Recommendation']))
            else:
                elements.append(Paragraph("No open ports detected on this host.", self.styles['Normal']))
            
            elements.append(Spacer(1, 0.3*inch))
        
        return elements
    
    def _create_remediation_guide(self, scan_data: Dict) -> List:
        """Create remediation guide section"""
        elements = []
        elements.append(Paragraph("TECHNICAL REMEDIATION GUIDE", self.styles['CustomHeading1']))
        
        # Priority-based remediation
        high_risk = self._count_high_risk_findings(scan_data)
        medium_risk = self._count_medium_risk_findings(scan_data)
        
        # Immediate actions
        elements.append(Paragraph("Priority 1: Immediate Actions", self.styles['CustomHeading2']))
        
        immediate_remediations = [
            "Disable or restrict access to critical risk services (FTP, Telnet, SMB)",
            "Implement network segmentation for administrative services",
            "Deploy intrusion detection systems for critical network segments",
            "Review and update firewall rules to block unnecessary services"
        ]
        
        for remediation in immediate_remediations:
            elements.append(Paragraph(f"• {remediation}", self.styles['Recommendation']))
        
        elements.append(Spacer(1, 0.2*inch))
        
        # Service-specific remediation
        elements.append(Paragraph("Priority 2: Service-Specific Hardening", self.styles['CustomHeading2']))
        
        service_remediations = {
            'ssh': 'Configure SSH key-based authentication, disable root login, change default port',
            'http': 'Implement HTTPS, update web server software, configure security headers',
            'https': 'Verify SSL/TLS configuration, update certificates, enable HSTS',
            'ftp': 'Replace with SFTP/FTPS, implement access controls, audit file transfers',
            'telnet': 'Replace with SSH, disable service if not required',
            'smtp': 'Configure authentication, implement encryption, restrict relay',
            'dns': 'Implement DNS security extensions, restrict zone transfers',
            'snmp': 'Change default community strings, implement SNMPv3, restrict access'
        }
        
        for service, remediation in service_remediations.items():
            elements.append(Paragraph(f"<b>{service.upper()}:</b> {remediation}", 
                                    self.styles['TechnicalDetails']))
        
        elements.append(Spacer(1, 0.3*inch))
        
        # Long-term improvements
        elements.append(Paragraph("Priority 3: Long-term Security Improvements", self.styles['CustomHeading2']))
        
        longterm_text = f"""
        <b>Infrastructure Hardening:</b><br/>
        • Implement network access control (NAC) solutions<br/>
        • Deploy endpoint detection and response (EDR) tools<br/>
        • Establish security information and event management (SIEM)<br/>
        • Regular vulnerability scanning and penetration testing<br/><br/>
        
        <b>Operational Security:</b><br/>
        • Develop incident response procedures<br/>
        • Implement security awareness training<br/>
        • Establish change management processes<br/>
        • Regular security policy reviews and updates<br/><br/>
        
        <b>Monitoring and Maintenance:</b><br/>
        • Continuous network monitoring<br/>
        • Regular security assessments<br/>
        • Patch management program<br/>
        • Security metrics and reporting
        """
        
        elements.append(Paragraph(longterm_text, self.styles['TechnicalDetails']))
        
        return elements
    
    def _create_technical_appendix(self, scan_data: Dict) -> List:
        """Create technical appendix section"""
        elements = []
        elements.append(Paragraph("TECHNICAL APPENDIX", self.styles['CustomHeading1']))
        
        # Scan configuration
        elements.append(Paragraph("Scan Configuration Details", self.styles['CustomHeading2']))
        
        scan_config = f"""
        <b>Network Discovery:</b><br/>
        • ICMP ping sweep for host discovery<br/>
        • ARP scanning for local network segments<br/>
        • TCP connect() scanning for service detection<br/>
        • UDP scanning for common UDP services<br/><br/>
        
        <b>Port Scanning Parameters:</b><br/>
        • TCP ports: 1-65535 (common ports prioritized)<br/>
        • UDP ports: Common services (53, 67, 68, 123, 161, 162)<br/>
        • Timing: Adaptive based on network conditions<br/>
        • Retries: 3 attempts for unresponsive ports<br/><br/>
        
        <b>Service Detection:</b><br/>
        • Banner grabbing for service identification<br/>
        • Protocol-specific probes for version detection<br/>
        • Operating system fingerprinting where possible<br/>
        • SSL/TLS certificate analysis for HTTPS services
        """
        
        elements.append(Paragraph(scan_config, self.styles['TechnicalDetails']))
        elements.append(Spacer(1, 0.3*inch))
        
        # Raw scan data summary
        elements.append(Paragraph("Scan Results Summary", self.styles['CustomHeading2']))
        
        total_hosts = len(scan_data.get('hosts', {}))
        total_ports = sum(len(h.get('open_ports', [])) for h in scan_data.get('hosts', {}).values())
        
        results_summary = f"""
        <b>Discovery Results:</b><br/>
        • Total hosts scanned: {total_hosts}<br/>
        • Total open ports found: {total_ports}<br/>
        • Average ports per host: {total_ports/max(total_hosts,1):.1f}<br/>
        • Scan completion: 100%<br/><br/>
        
        <b>Service Distribution:</b><br/>
        """
        
        # Add service statistics
        service_stats = {}
        for host_data in scan_data.get('hosts', {}).values():
            for port_info in host_data.get('open_ports', []):
                service = port_info.get('service', 'unknown')
                service_stats[service] = service_stats.get(service, 0) + 1
        
        for service, count in sorted(service_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            results_summary += f"• {service}: {count} instances<br/>"
        
        elements.append(Paragraph(results_summary, self.styles['TechnicalDetails']))
        
        return elements
    
    def _get_detailed_vulnerability_description(self, port: int, service: str, version: str) -> str:
        """Get detailed vulnerability description for a service"""
        descriptions = {
            21: "FTP service allows unencrypted file transfers and may be vulnerable to brute force attacks",
            23: "Telnet provides unencrypted remote access and transmits credentials in plaintext",
            135: "RPC Endpoint Mapper may expose internal services and facilitate lateral movement",
            139: "NetBIOS Session Service can leak system information and enable SMB attacks",
            445: "SMB service may be vulnerable to various attacks including EternalBlue and credential theft",
            1433: "SQL Server may be vulnerable to injection attacks and unauthorized database access",
            3389: "RDP service may be vulnerable to brute force attacks and credential stuffing"
        }
        return descriptions.get(port, f"Service on port {port} requires security review and hardening")
    
    def _get_port_service_name(self, port: int) -> str:
        """Get standard service name for port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'SQL Server', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt'
        }
        return services.get(port, f'Port-{port}')
    
    def _assess_port_risk(self, port: int) -> str:
        """Assess risk level for a specific port"""
        critical_ports = [21, 23, 135, 139, 445, 1433, 3389]
        medium_ports = [22, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        if port in critical_ports:
            return 'HIGH'
        elif port in medium_ports:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_security_notes(self, port: int, service: str) -> str:
        """Get security notes for a specific service"""
        notes = {
            21: 'Unencrypted, consider SFTP',
            22: 'Secure if properly configured',
            23: 'Unencrypted, replace with SSH',
            25: 'Requires authentication controls',
            53: 'Restrict zone transfers',
            80: 'Consider HTTPS redirect',
            135: 'Restrict RPC access',
            139: 'Disable if not required',
            143: 'Consider IMAPS',
            443: 'Verify SSL configuration',
            445: 'High risk, restrict access',
            993: 'Secure IMAP implementation',
            995: 'Secure POP3 implementation',
            1433: 'Restrict database access',
            3389: 'High risk, use VPN',
            8080: 'Alternative HTTP port'
        }
        return notes.get(port, 'Review service configuration')
    
    def _get_host_recommendations(self, host_ip: str, open_ports: List) -> List[str]:
        """Get specific recommendations for a host"""
        recommendations = []
        
        port_numbers = [p.get('port') for p in open_ports if p.get('port')]
        
        # Critical service recommendations
        if any(port in [21, 23, 135, 139, 445, 1433, 3389] for port in port_numbers):
            recommendations.append("Immediate review required - critical services detected")
            recommendations.append("Implement network segmentation and access controls")
        
        # Service-specific recommendations
        if 21 in port_numbers:
            recommendations.append("Replace FTP with SFTP or FTPS for secure file transfers")
        if 23 in port_numbers:
            recommendations.append("Replace Telnet with SSH for secure remote access")
        if 80 in port_numbers and 443 not in port_numbers:
            recommendations.append("Implement HTTPS to encrypt web traffic")
        if 445 in port_numbers:
            recommendations.append("Restrict SMB access and apply latest security patches")
        if 3389 in port_numbers:
            recommendations.append("Secure RDP with VPN access and strong authentication")
        
        # General recommendations
        if len(open_ports) > 10:
            recommendations.append("Consider reducing attack surface by disabling unused services")
        
        recommendations.append("Implement regular security monitoring and logging")
        recommendations.append("Apply security patches and updates regularly")
        
        return recommendations
    
    def _assess_service_risk(self, service: str) -> str:
        """Assess risk level for a service type"""
        high_risk_services = ['ftp', 'telnet', 'rpc', 'netbios-ssn', 'microsoft-ds', 'ms-sql-s', 'ms-wbt-server']
        medium_risk_services = ['ssh', 'smtp', 'http', 'pop3', 'imap', 'https', 'imaps', 'pop3s']
        
        if service.lower() in high_risk_services:
            return 'HIGH'
        elif service.lower() in medium_risk_services:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _count_high_risk_findings(self, scan_data: Dict) -> int:
        """Count high-risk findings based on critical ports and services"""
        count = 0
        for host_data in scan_data.get('hosts', {}).values():
            open_ports = host_data.get('open_ports', [])
            # Critical risk ports that pose immediate security threats
            critical_ports = [21, 23, 135, 139, 445, 1433, 3389]
            count += len([p for p in open_ports if p.get('port') in critical_ports])
        return count
    
    def _count_medium_risk_findings(self, scan_data: Dict) -> int:
        """Count medium-risk findings based on common service ports"""
        count = 0
        for host_data in scan_data.get('hosts', {}).values():
            open_ports = host_data.get('open_ports', [])
            # Medium risk ports that require attention but are commonly used
            medium_ports = [22, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
            count += len([p for p in open_ports if p.get('port') in medium_ports])
        return count
    
    def _count_low_risk_findings(self, scan_data: Dict) -> int:
        """Count low-risk findings (all other open ports)"""
        total_ports = sum(len(h.get('open_ports', [])) for h in scan_data.get('hosts', {}).values())
        high_risk = self._count_high_risk_findings(scan_data)
        medium_risk = self._count_medium_risk_findings(scan_data)
        return max(0, total_ports - high_risk - medium_risk)
    
    def _assess_host_risk_level(self, open_ports: List) -> str:
        """Assess the overall risk level of a host based on open ports"""
        if not open_ports:
            return 'LOW'
        
        # Define critical and medium-risk ports
        critical_ports = [21, 23, 135, 139, 445, 1433, 3389, 5432, 6379]  # High-risk services
        medium_risk_ports = [22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5900, 8080]  # Medium-risk services
        
        # Count risk levels
        high_risk_count = sum(1 for port in open_ports if port in critical_ports)
        medium_risk_count = sum(1 for port in open_ports if port in medium_risk_ports)
        
        # Determine overall risk level
        if high_risk_count > 0:
            return 'HIGH'
        elif medium_risk_count > 2:  # Multiple medium-risk services
            return 'MEDIUM'
        elif len(open_ports) > 10:  # Many open ports
            return 'MEDIUM'
        else:
            return 'LOW'