#!/usr/bin/env python3
"""
Security Audit Logger Module
Implements comprehensive security logging and compliance tracking for network scanning activities.

Author: Gustavo Valente
Version: 2.0
"""

import logging
import json
import hashlib
import time
from datetime import datetime
from pathlib import Path
import os

class SecurityLogger:
    """
    Security audit logger implementing DevSecOps best practices
    - Tamper-evident logging with checksums
    - Compliance tracking (NIST, OWASP)
    - Security event correlation
    - Audit trail maintenance
    """
    
    def __init__(self, log_dir="security_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Create separate log files for different security events
        self.audit_log = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"
        self.compliance_log = self.log_dir / f"compliance_{datetime.now().strftime('%Y%m%d')}.log"
        self.security_events_log = self.log_dir / f"security_events_{datetime.now().strftime('%Y%m%d')}.log"
        
        # Setup loggers
        self._setup_loggers()
        
        # Security metrics
        self.scan_count = 0
        self.suspicious_activities = []
        self.compliance_violations = []
        
    def _setup_loggers(self):
        """Setup secure logging with proper formatting and rotation"""
        
        # Audit logger
        self.audit_logger = logging.getLogger('security_audit')
        self.audit_logger.setLevel(logging.INFO)
        audit_handler = logging.FileHandler(self.audit_log)
        audit_formatter = logging.Formatter(
            '%(asctime)s | AUDIT | %(levelname)s | %(message)s | CHECKSUM:%(checksum)s',
            datefmt='%Y-%m-%d %H:%M:%S UTC'
        )
        audit_handler.setFormatter(audit_formatter)
        self.audit_logger.addHandler(audit_handler)
        
        # Compliance logger
        self.compliance_logger = logging.getLogger('compliance')
        self.compliance_logger.setLevel(logging.INFO)
        compliance_handler = logging.FileHandler(self.compliance_log)
        compliance_formatter = logging.Formatter(
            '%(asctime)s | COMPLIANCE | %(framework)s | %(control)s | %(status)s | %(details)s'
        )
        compliance_handler.setFormatter(compliance_formatter)
        self.compliance_logger.addHandler(compliance_handler)
        
        # Security events logger
        self.security_logger = logging.getLogger('security_events')
        self.security_logger.setLevel(logging.WARNING)
        security_handler = logging.FileHandler(self.security_events_log)
        security_formatter = logging.Formatter(
            '%(asctime)s | SECURITY | %(severity)s | %(event_type)s | %(details)s'
        )
        security_handler.setFormatter(security_formatter)
        self.security_logger.addHandler(security_handler)
    
    def _generate_checksum(self, data):
        """Generate tamper-evident checksum for log entries"""
        return hashlib.sha256(str(data).encode()).hexdigest()[:16]
    
    def log_scan_start(self, target, user_context, scan_params):
        """Log the start of a network scan with full context"""
        scan_data = {
            'event': 'SCAN_START',
            'target': target,
            'user': user_context.get('username', 'unknown'),
            'source_ip': user_context.get('source_ip', 'unknown'),
            'scan_type': scan_params.get('scan_type', 'standard'),
            'threads': scan_params.get('threads', 50),
            'timestamp': datetime.utcnow().isoformat(),
            'session_id': scan_params.get('session_id', 'unknown')
        }
        
        checksum = self._generate_checksum(scan_data)
        self.audit_logger.info(json.dumps(scan_data), extra={'checksum': checksum})
        self.scan_count += 1
        
        # Check for compliance violations
        self._check_scan_compliance(target, scan_params)
    
    def log_scan_complete(self, target, results, duration):
        """Log scan completion with results summary"""
        completion_data = {
            'event': 'SCAN_COMPLETE',
            'target': target,
            'hosts_found': len(results.get('hosts', [])),
            'ports_found': results.get('total_ports', 0),
            'vulnerabilities_found': results.get('total_vulnerabilities', 0),
            'duration_seconds': duration,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        checksum = self._generate_checksum(completion_data)
        self.audit_logger.info(json.dumps(completion_data), extra={'checksum': checksum})
    
    def log_security_event(self, event_type, severity, details):
        """Log security-relevant events"""
        event_data = {
            'event_type': event_type,
            'severity': severity,
            'details': details,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.security_logger.warning(
            json.dumps(event_data),
            extra={
                'severity': severity,
                'event_type': event_type,
                'details': json.dumps(details)
            }
        )
        
        if severity in ['HIGH', 'CRITICAL']:
            self.suspicious_activities.append(event_data)
    
    def _check_scan_compliance(self, target, scan_params):
        """Check scan parameters against compliance frameworks"""
        
        # NIST Cybersecurity Framework compliance
        if scan_params.get('threads', 50) > 100:
            self._log_compliance_violation(
                'NIST_CSF', 
                'PR.DS-1', 
                'VIOLATION',
                f'Excessive thread count ({scan_params.get("threads")}) may impact target availability'
            )
        
        # OWASP Testing Guide compliance
        if not scan_params.get('rate_limiting', False):
            self._log_compliance_violation(
                'OWASP_TESTING',
                'WSTG-INFO-01',
                'WARNING',
                'No rate limiting configured - may trigger security controls'
            )
        
        # Check for internal IP scanning without authorization
        if self._is_internal_ip(target) and not scan_params.get('authorized', False):
            self._log_compliance_violation(
                'INTERNAL_POLICY',
                'AUTH-001',
                'VIOLATION',
                f'Internal IP scanning ({target}) without explicit authorization'
            )
    
    def _log_compliance_violation(self, framework, control, status, details):
        """Log compliance framework violations"""
        self.compliance_logger.info(
            '',
            extra={
                'framework': framework,
                'control': control,
                'status': status,
                'details': details
            }
        )
        
        if status == 'VIOLATION':
            self.compliance_violations.append({
                'framework': framework,
                'control': control,
                'details': details,
                'timestamp': datetime.utcnow().isoformat()
            })
    
    def _is_internal_ip(self, ip_str):
        """Check if IP is in private/internal ranges"""
        import ipaddress
        try:
            ip = ipaddress.ip_address(ip_str.split('/')[0])
            return ip.is_private
        except:
            return False
    
    def generate_security_report(self):
        """Generate comprehensive security and compliance report"""
        report = {
            'report_generated': datetime.utcnow().isoformat(),
            'scan_statistics': {
                'total_scans': self.scan_count,
                'suspicious_activities': len(self.suspicious_activities),
                'compliance_violations': len(self.compliance_violations)
            },
            'security_events': self.suspicious_activities[-10:],  # Last 10 events
            'compliance_status': {
                'violations': self.compliance_violations,
                'frameworks_checked': ['NIST_CSF', 'OWASP_TESTING', 'INTERNAL_POLICY']
            },
            'recommendations': self._generate_security_recommendations()
        }
        
        # Save report
        report_file = self.log_dir / f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def _generate_security_recommendations(self):
        """Generate security recommendations based on observed patterns"""
        recommendations = []
        
        if len(self.compliance_violations) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'COMPLIANCE',
                'recommendation': 'Address compliance violations before production use',
                'details': f'{len(self.compliance_violations)} violations detected'
            })
        
        if len(self.suspicious_activities) > 5:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'SECURITY',
                'recommendation': 'Review security events for potential threats',
                'details': f'{len(self.suspicious_activities)} security events logged'
            })
        
        recommendations.append({
            'priority': 'LOW',
            'category': 'MONITORING',
            'recommendation': 'Implement continuous security monitoring',
            'details': 'Regular review of audit logs recommended'
        })
        
        return recommendations
    
    def cleanup_old_logs(self, days_to_keep=30):
        """Clean up old log files while maintaining compliance retention"""
        cutoff_date = datetime.now().timestamp() - (days_to_keep * 24 * 3600)
        
        for log_file in self.log_dir.glob("*.log"):
            if log_file.stat().st_mtime < cutoff_date:
                # Archive before deletion for compliance
                archive_name = f"archived_{log_file.name}"
                log_file.rename(self.log_dir / archive_name)