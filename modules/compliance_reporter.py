#!/usr/bin/env python3
"""
Compliance Reporter Module
Generates compliance reports for various security frameworks (NIST, OWASP, ISO 27001)
and provides security metrics dashboard functionality.

Author: Gustavo Valente
Version: 2.0 (DevSecOps Enhanced)
"""

import json
import os
import datetime
import hashlib
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import csv


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    OWASP_TOP10_2021 = "owasp_top10_2021"
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    CIS_CONTROLS = "cis_controls"
    GDPR = "gdpr"
    SOC2 = "soc2"


class ComplianceStatus(Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNDER_REVIEW = "under_review"


@dataclass
class ComplianceControl:
    """Individual compliance control"""
    control_id: str
    framework: str
    title: str
    description: str
    status: ComplianceStatus
    evidence: List[str]
    gaps: List[str]
    remediation: List[str]
    risk_level: str
    last_assessed: datetime.datetime
    assessor: str
    notes: str = ""


@dataclass
class SecurityMetric:
    """Security metric data point"""
    metric_name: str
    value: float
    unit: str
    timestamp: datetime.datetime
    category: str
    threshold: Optional[float] = None
    status: str = "normal"


class ComplianceReporter:
    """
    Comprehensive compliance reporting and security metrics system
    """
    
    def __init__(self, reports_dir: str = "compliance_reports"):
        """
        Initialize compliance reporter
        
        Args:
            reports_dir: Directory to store compliance reports
        """
        self.reports_dir = reports_dir
        self.db_path = os.path.join(reports_dir, "compliance.db")
        
        # Create directories
        os.makedirs(reports_dir, exist_ok=True)
        os.makedirs(os.path.join(reports_dir, "frameworks"), exist_ok=True)
        os.makedirs(os.path.join(reports_dir, "metrics"), exist_ok=True)
        os.makedirs(os.path.join(reports_dir, "dashboards"), exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # Load compliance frameworks
        self.frameworks = self._load_frameworks()
    
    def _init_database(self):
        """Initialize SQLite database for compliance tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Compliance controls table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_controls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                control_id TEXT NOT NULL,
                framework TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                evidence TEXT,
                gaps TEXT,
                remediation TEXT,
                risk_level TEXT,
                last_assessed TIMESTAMP,
                assessor TEXT,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(control_id, framework)
            )
        ''')
        
        # Security metrics table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_name TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT,
                timestamp TIMESTAMP NOT NULL,
                category TEXT,
                threshold REAL,
                status TEXT DEFAULT 'normal',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Compliance assessments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                framework TEXT NOT NULL,
                assessment_date TIMESTAMP NOT NULL,
                overall_score REAL,
                compliant_controls INTEGER,
                total_controls INTEGER,
                assessor TEXT,
                report_path TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_frameworks(self) -> Dict[str, Dict]:
        """Load compliance framework definitions"""
        frameworks = {
            ComplianceFramework.OWASP_TOP10_2021.value: {
                "name": "OWASP Top 10 2021",
                "version": "2021",
                "controls": {
                    "A01": {
                        "title": "Broken Access Control",
                        "description": "Access control enforces policy such that users cannot act outside of their intended permissions",
                        "requirements": [
                            "Implement proper access controls",
                            "Use principle of least privilege",
                            "Validate access on server-side",
                            "Deny by default"
                        ]
                    },
                    "A02": {
                        "title": "Cryptographic Failures",
                        "description": "Protect data in transit and at rest with strong cryptography",
                        "requirements": [
                            "Encrypt sensitive data",
                            "Use strong encryption algorithms",
                            "Implement proper key management",
                            "Avoid deprecated cryptographic functions"
                        ]
                    },
                    "A03": {
                        "title": "Injection",
                        "description": "Prevent injection flaws such as SQL, NoSQL, OS, and LDAP injection",
                        "requirements": [
                            "Use parameterized queries",
                            "Validate and sanitize input",
                            "Use safe APIs",
                            "Implement input validation"
                        ]
                    },
                    "A04": {
                        "title": "Insecure Design",
                        "description": "Secure design is a culture and methodology that constantly evaluates threats",
                        "requirements": [
                            "Implement threat modeling",
                            "Use secure design patterns",
                            "Establish security requirements",
                            "Implement defense in depth"
                        ]
                    },
                    "A05": {
                        "title": "Security Misconfiguration",
                        "description": "Secure configuration of all system components",
                        "requirements": [
                            "Implement secure configuration baselines",
                            "Remove unnecessary features",
                            "Keep systems updated",
                            "Implement proper error handling"
                        ]
                    },
                    "A06": {
                        "title": "Vulnerable and Outdated Components",
                        "description": "Manage component vulnerabilities and keep dependencies updated",
                        "requirements": [
                            "Maintain component inventory",
                            "Monitor for vulnerabilities",
                            "Apply security updates",
                            "Remove unused components"
                        ]
                    },
                    "A07": {
                        "title": "Identification and Authentication Failures",
                        "description": "Implement strong authentication and session management",
                        "requirements": [
                            "Implement multi-factor authentication",
                            "Use strong password policies",
                            "Secure session management",
                            "Implement account lockout"
                        ]
                    },
                    "A08": {
                        "title": "Software and Data Integrity Failures",
                        "description": "Ensure software updates and critical data are integrity protected",
                        "requirements": [
                            "Use digital signatures",
                            "Implement integrity checks",
                            "Secure CI/CD pipeline",
                            "Validate software updates"
                        ]
                    },
                    "A09": {
                        "title": "Security Logging and Monitoring Failures",
                        "description": "Implement comprehensive logging and monitoring",
                        "requirements": [
                            "Log security events",
                            "Implement real-time monitoring",
                            "Establish incident response",
                            "Protect log integrity"
                        ]
                    },
                    "A10": {
                        "title": "Server-Side Request Forgery (SSRF)",
                        "description": "Prevent SSRF attacks through proper validation",
                        "requirements": [
                            "Validate URLs and inputs",
                            "Implement network segmentation",
                            "Use allowlists for URLs",
                            "Disable unnecessary protocols"
                        ]
                    }
                }
            },
            ComplianceFramework.NIST_CSF.value: {
                "name": "NIST Cybersecurity Framework",
                "version": "1.1",
                "functions": {
                    "IDENTIFY": "Develop organizational understanding to manage cybersecurity risk",
                    "PROTECT": "Develop and implement appropriate safeguards",
                    "DETECT": "Develop and implement appropriate activities to identify cybersecurity events",
                    "RESPOND": "Develop and implement appropriate activities regarding detected cybersecurity events",
                    "RECOVER": "Develop and implement appropriate activities to maintain resilience plans"
                }
            }
        }
        
        return frameworks
    
    def assess_control(self, control: ComplianceControl) -> bool:
        """
        Assess and record a compliance control
        
        Args:
            control: ComplianceControl object to assess
            
        Returns:
            bool: Success status
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert or update control assessment
            cursor.execute('''
                INSERT OR REPLACE INTO compliance_controls 
                (control_id, framework, title, description, status, evidence, gaps, 
                 remediation, risk_level, last_assessed, assessor, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                control.control_id,
                control.framework,
                control.title,
                control.description,
                control.status.value,
                json.dumps(control.evidence),
                json.dumps(control.gaps),
                json.dumps(control.remediation),
                control.risk_level,
                control.last_assessed,
                control.assessor,
                control.notes
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error assessing control: {e}")
            return False
    
    def record_metric(self, metric: SecurityMetric) -> bool:
        """
        Record a security metric
        
        Args:
            metric: SecurityMetric object to record
            
        Returns:
            bool: Success status
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Determine status based on threshold
            status = "normal"
            if metric.threshold:
                if metric.value > metric.threshold:
                    status = "warning"
                if metric.value > metric.threshold * 1.5:
                    status = "critical"
            
            cursor.execute('''
                INSERT INTO security_metrics 
                (metric_name, value, unit, timestamp, category, threshold, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                metric.metric_name,
                metric.value,
                metric.unit,
                metric.timestamp,
                metric.category,
                metric.threshold,
                status
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error recording metric: {e}")
            return False
    
    def generate_compliance_report(self, framework: ComplianceFramework, 
                                 assessor: str = "System") -> Dict[str, Any]:
        """
        Generate comprehensive compliance report for a framework
        
        Args:
            framework: Compliance framework to report on
            assessor: Name of the assessor
            
        Returns:
            Dict containing the compliance report
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get all controls for the framework
            cursor.execute('''
                SELECT * FROM compliance_controls 
                WHERE framework = ? 
                ORDER BY control_id
            ''', (framework.value,))
            
            controls = cursor.fetchall()
            
            # Calculate compliance statistics
            total_controls = len(controls)
            compliant_controls = len([c for c in controls if c[5] == ComplianceStatus.COMPLIANT.value])
            partial_controls = len([c for c in controls if c[5] == ComplianceStatus.PARTIAL.value])
            non_compliant_controls = len([c for c in controls if c[5] == ComplianceStatus.NON_COMPLIANT.value])
            
            compliance_score = (compliant_controls + (partial_controls * 0.5)) / total_controls * 100 if total_controls > 0 else 0
            
            # Generate report
            report = {
                "framework": framework.value,
                "framework_name": self.frameworks.get(framework.value, {}).get("name", framework.value),
                "assessment_date": datetime.datetime.now().isoformat(),
                "assessor": assessor,
                "summary": {
                    "total_controls": total_controls,
                    "compliant_controls": compliant_controls,
                    "partial_controls": partial_controls,
                    "non_compliant_controls": non_compliant_controls,
                    "compliance_score": round(compliance_score, 2),
                    "compliance_level": self._get_compliance_level(compliance_score)
                },
                "controls": [],
                "recommendations": [],
                "risk_assessment": self._assess_risks(controls)
            }
            
            # Add control details
            for control in controls:
                control_data = {
                    "control_id": control[1],
                    "title": control[3],
                    "status": control[5],
                    "evidence": json.loads(control[6]) if control[6] else [],
                    "gaps": json.loads(control[7]) if control[7] else [],
                    "remediation": json.loads(control[8]) if control[8] else [],
                    "risk_level": control[9],
                    "last_assessed": control[10]
                }
                report["controls"].append(control_data)
            
            # Generate recommendations
            report["recommendations"] = self._generate_recommendations(controls, framework)
            
            # Save report
            report_filename = f"{framework.value}_compliance_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            report_path = os.path.join(self.reports_dir, "frameworks", report_filename)
            
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Record assessment in database
            cursor.execute('''
                INSERT INTO compliance_assessments 
                (framework, assessment_date, overall_score, compliant_controls, total_controls, assessor, report_path)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                framework.value,
                datetime.datetime.now(),
                compliance_score,
                compliant_controls,
                total_controls,
                assessor,
                report_path
            ))
            
            conn.commit()
            conn.close()
            
            return report
            
        except Exception as e:
            print(f"Error generating compliance report: {e}")
            return {}
    
    def _get_compliance_level(self, score: float) -> str:
        """Determine compliance level based on score"""
        if score >= 90:
            return "Excellent"
        elif score >= 80:
            return "Good"
        elif score >= 70:
            return "Acceptable"
        elif score >= 60:
            return "Needs Improvement"
        else:
            return "Poor"
    
    def _assess_risks(self, controls: List) -> Dict[str, Any]:
        """Assess overall risk based on control status"""
        high_risk_controls = len([c for c in controls if c[9] == "high" and c[5] != ComplianceStatus.COMPLIANT.value])
        medium_risk_controls = len([c for c in controls if c[9] == "medium" and c[5] != ComplianceStatus.COMPLIANT.value])
        low_risk_controls = len([c for c in controls if c[9] == "low" and c[5] != ComplianceStatus.COMPLIANT.value])
        
        overall_risk = "low"
        if high_risk_controls > 0:
            overall_risk = "high"
        elif medium_risk_controls > 2:
            overall_risk = "medium"
        
        return {
            "overall_risk": overall_risk,
            "high_risk_gaps": high_risk_controls,
            "medium_risk_gaps": medium_risk_controls,
            "low_risk_gaps": low_risk_controls,
            "risk_score": (high_risk_controls * 3 + medium_risk_controls * 2 + low_risk_controls * 1)
        }
    
    def _generate_recommendations(self, controls: List, framework: ComplianceFramework) -> List[str]:
        """Generate recommendations based on control gaps"""
        recommendations = []
        
        non_compliant = [c for c in controls if c[5] == ComplianceStatus.NON_COMPLIANT.value]
        partial = [c for c in controls if c[5] == ComplianceStatus.PARTIAL.value]
        
        if non_compliant:
            recommendations.append(f"Prioritize addressing {len(non_compliant)} non-compliant controls")
        
        if partial:
            recommendations.append(f"Complete implementation for {len(partial)} partially compliant controls")
        
        # Framework-specific recommendations
        if framework == ComplianceFramework.OWASP_TOP10_2021:
            high_priority = ["A01", "A02", "A03"]  # Most critical OWASP controls
            for control in non_compliant:
                if control[1] in high_priority:
                    recommendations.append(f"Critical: Address {control[1]} - {control[3]} immediately")
        
        return recommendations
    
    def generate_security_dashboard(self) -> Dict[str, Any]:
        """
        Generate security metrics dashboard
        
        Returns:
            Dict containing dashboard data
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get recent metrics
            cursor.execute('''
                SELECT metric_name, value, unit, category, status, timestamp
                FROM security_metrics 
                WHERE timestamp >= datetime('now', '-30 days')
                ORDER BY timestamp DESC
            ''')
            
            metrics = cursor.fetchall()
            
            # Get compliance summary
            cursor.execute('''
                SELECT framework, overall_score, assessment_date
                FROM compliance_assessments 
                ORDER BY assessment_date DESC
                LIMIT 10
            ''')
            
            assessments = cursor.fetchall()
            
            dashboard = {
                "generated_at": datetime.datetime.now().isoformat(),
                "summary": {
                    "total_metrics": len(metrics),
                    "critical_alerts": len([m for m in metrics if m[4] == "critical"]),
                    "warning_alerts": len([m for m in metrics if m[4] == "warning"]),
                    "frameworks_assessed": len(set([a[0] for a in assessments]))
                },
                "metrics": {
                    "by_category": self._group_metrics_by_category(metrics),
                    "trends": self._calculate_metric_trends(metrics),
                    "alerts": [m for m in metrics if m[4] in ["warning", "critical"]]
                },
                "compliance": {
                    "recent_assessments": [
                        {
                            "framework": a[0],
                            "score": a[1],
                            "date": a[2]
                        } for a in assessments
                    ],
                    "average_score": sum([a[1] for a in assessments]) / len(assessments) if assessments else 0
                },
                "recommendations": self._generate_dashboard_recommendations(metrics, assessments)
            }
            
            # Save dashboard
            dashboard_filename = f"security_dashboard_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            dashboard_path = os.path.join(self.reports_dir, "dashboards", dashboard_filename)
            
            with open(dashboard_path, 'w') as f:
                json.dump(dashboard, f, indent=2, default=str)
            
            conn.close()
            return dashboard
            
        except Exception as e:
            print(f"Error generating security dashboard: {e}")
            return {}
    
    def _group_metrics_by_category(self, metrics: List) -> Dict[str, List]:
        """Group metrics by category"""
        categories = {}
        for metric in metrics:
            category = metric[3] or "general"
            if category not in categories:
                categories[category] = []
            categories[category].append({
                "name": metric[0],
                "value": metric[1],
                "unit": metric[2],
                "status": metric[4],
                "timestamp": metric[5]
            })
        return categories
    
    def _calculate_metric_trends(self, metrics: List) -> Dict[str, str]:
        """Calculate trends for key metrics"""
        # Simplified trend calculation
        trends = {}
        metric_names = set([m[0] for m in metrics])
        
        for name in metric_names:
            metric_values = [m for m in metrics if m[0] == name]
            if len(metric_values) >= 2:
                recent = metric_values[0][1]
                older = metric_values[-1][1]
                if recent > older:
                    trends[name] = "increasing"
                elif recent < older:
                    trends[name] = "decreasing"
                else:
                    trends[name] = "stable"
            else:
                trends[name] = "insufficient_data"
        
        return trends
    
    def _generate_dashboard_recommendations(self, metrics: List, assessments: List) -> List[str]:
        """Generate dashboard recommendations"""
        recommendations = []
        
        # Check for critical alerts
        critical_metrics = [m for m in metrics if m[4] == "critical"]
        if critical_metrics:
            recommendations.append(f"Address {len(critical_metrics)} critical security alerts immediately")
        
        # Check compliance scores
        if assessments:
            avg_score = sum([a[1] for a in assessments]) / len(assessments)
            if avg_score < 70:
                recommendations.append("Overall compliance score is below acceptable threshold")
        
        # Check for missing assessments
        if not assessments:
            recommendations.append("No recent compliance assessments found - schedule security review")
        
        return recommendations
    
    def export_compliance_csv(self, framework: ComplianceFramework, output_path: str) -> bool:
        """
        Export compliance data to CSV format
        
        Args:
            framework: Compliance framework to export
            output_path: Path for CSV file
            
        Returns:
            bool: Success status
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT control_id, title, status, risk_level, last_assessed, assessor
                FROM compliance_controls 
                WHERE framework = ?
                ORDER BY control_id
            ''', (framework.value,))
            
            controls = cursor.fetchall()
            
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Control ID', 'Title', 'Status', 'Risk Level', 'Last Assessed', 'Assessor'])
                writer.writerows(controls)
            
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error exporting CSV: {e}")
            return False
    
    def get_compliance_summary(self) -> Dict[str, Any]:
        """Get overall compliance summary across all frameworks"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT framework, COUNT(*) as total, 
                       SUM(CASE WHEN status = 'compliant' THEN 1 ELSE 0 END) as compliant
                FROM compliance_controls 
                GROUP BY framework
            ''')
            
            results = cursor.fetchall()
            
            summary = {
                "frameworks": {},
                "overall": {
                    "total_controls": 0,
                    "compliant_controls": 0,
                    "compliance_percentage": 0
                }
            }
            
            total_all = 0
            compliant_all = 0
            
            for result in results:
                framework, total, compliant = result
                compliance_pct = (compliant / total * 100) if total > 0 else 0
                
                summary["frameworks"][framework] = {
                    "total_controls": total,
                    "compliant_controls": compliant,
                    "compliance_percentage": round(compliance_pct, 2)
                }
                
                total_all += total
                compliant_all += compliant
            
            if total_all > 0:
                summary["overall"]["total_controls"] = total_all
                summary["overall"]["compliant_controls"] = compliant_all
                summary["overall"]["compliance_percentage"] = round((compliant_all / total_all * 100), 2)
            
            conn.close()
            return summary
            
        except Exception as e:
            print(f"Error getting compliance summary: {e}")
            return {}


# Example usage and testing
if __name__ == "__main__":
    # Initialize compliance reporter
    reporter = ComplianceReporter()
    
    # Example: Assess OWASP Top 10 controls
    owasp_controls = [
        ComplianceControl(
            control_id="A01",
            framework=ComplianceFramework.OWASP_TOP10_2021.value,
            title="Broken Access Control",
            description="Access control enforces policy",
            status=ComplianceStatus.COMPLIANT,
            evidence=["Input validation implemented", "Rate limiting active"],
            gaps=[],
            remediation=[],
            risk_level="high",
            last_assessed=datetime.datetime.now(),
            assessor="Security Team"
        ),
        ComplianceControl(
            control_id="A03",
            framework=ComplianceFramework.OWASP_TOP10_2021.value,
            title="Injection",
            description="Prevent injection flaws",
            status=ComplianceStatus.COMPLIANT,
            evidence=["Input sanitization", "Parameterized queries"],
            gaps=[],
            remediation=[],
            risk_level="high",
            last_assessed=datetime.datetime.now(),
            assessor="Security Team"
        )
    ]
    
    # Assess controls
    for control in owasp_controls:
        reporter.assess_control(control)
    
    # Record security metrics
    metrics = [
        SecurityMetric(
            metric_name="vulnerability_count",
            value=2,
            unit="count",
            timestamp=datetime.datetime.now(),
            category="vulnerabilities",
            threshold=5
        ),
        SecurityMetric(
            metric_name="scan_coverage",
            value=95.5,
            unit="percentage",
            timestamp=datetime.datetime.now(),
            category="coverage",
            threshold=90
        )
    ]
    
    for metric in metrics:
        reporter.record_metric(metric)
    
    # Generate reports
    owasp_report = reporter.generate_compliance_report(ComplianceFramework.OWASP_TOP10_2021)
    dashboard = reporter.generate_security_dashboard()
    summary = reporter.get_compliance_summary()
    
    print("Compliance Reporter initialized and tested successfully!")
    print(f"OWASP compliance score: {owasp_report.get('summary', {}).get('compliance_score', 0)}%")
    print(f"Total frameworks assessed: {summary.get('overall', {}).get('total_controls', 0)} controls")