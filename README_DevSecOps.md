# DevSecOps Enhanced Network Mapper

## Overview

This network mapping tool has been enhanced with comprehensive DevSecOps practices, integrating security throughout the development lifecycle. The implementation follows OWASP guidelines, NIST cybersecurity framework, and ISO 27001 standards.

## Security Features Implemented

### 1. Security Audit Logging (`modules/security_logger.py`)
- **Tamper-evident logging** with cryptographic checksums
- **Compliance tracking** for NIST, OWASP, and ISO 27001
- **Security event monitoring** with real-time alerts
- **Log integrity verification** and rotation
- **Automated security reporting**

### 2. Input Validation (`modules/input_validator.py`)
- **OWASP-compliant validation** for all user inputs
- **Injection attack prevention** (SQL, Command, XSS)
- **Network target sanitization** and validation
- **File path traversal protection**
- **Dangerous pattern detection**

### 3. Secrets Management (`modules/secrets_manager.py`)
- **Encrypted credential storage** using Fernet encryption
- **Environment variable fallback** for configuration
- **System keyring integration** for secure storage
- **API key rotation** and expiration tracking
- **Configuration validation** and sanitization

### 4. Rate Limiting (`modules/rate_limiter.py`)
- **Token bucket algorithm** for request throttling
- **Per-target and global rate limiting**
- **Abuse detection** and automatic blocking
- **Adaptive rate limiting** based on system load
- **Concurrent scan tracking**

### 5. Compliance Reporting (`modules/compliance_reporter.py`)
- **Multi-framework support** (NIST, OWASP, ISO 27001)
- **Automated compliance assessments**
- **Security metrics dashboard**
- **Control implementation tracking**
- **Risk assessment reporting**

### 6. Secure Configuration (`modules/secure_config.py`)
- **Secure-by-default settings** with fail-safe mechanisms
- **Security level presets** (MINIMAL, STANDARD, HIGH, MAXIMUM)
- **Configuration validation** and hardening
- **Emergency shutdown capabilities**
- **Security policy enforcement**

### 7. Configuration Management System (New in v2.2)
- **Centralized configuration** via `config/default_flags.json`
- **Configuration validation** and security checks
- **Automatic backup system** for configuration changes
- **Tamper detection** for configuration files
- **Secure default values** with security-conscious presets
- **Configuration audit trail** and change tracking

## Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Mapper Core                     │
├─────────────────────────────────────────────────────────────┤
│  Security Layer (DevSecOps Integration)                    │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │   Input     │ │   Rate      │ │  Security   │          │
│  │ Validation  │ │  Limiting   │ │  Logging    │          │
│  └─────────────┘ └─────────────┘ └─────────────┘          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │  Secrets    │ │ Compliance  │ │   Secure    │          │
│  │ Management  │ │ Reporting   │ │   Config    │          │
│  └─────────────┘ └─────────────┘ └─────────────┘          │
├─────────────────────────────────────────────────────────────┤
│  Core Modules (Vulnerability Scanner, Device Detector...)  │
└─────────────────────────────────────────────────────────────┘
```

## Security Testing

### Unit Tests (`tests/test_security.py`)
- Comprehensive security-focused test suite
- Input validation testing
- Security logging verification
- Secrets management testing
- Rate limiting validation
- Integration testing

### SAST Configuration (`sast_config.yml`)
- **Bandit** for Python security analysis
- **Safety** for dependency vulnerability scanning
- **Semgrep** for custom security rules
- **Automated security metrics** collection
- **OWASP Top 10 compliance** mapping

## Usage Examples

### Basic Secure Scan
```bash
python network_mapper_refactored.py 192.168.1.0/24
```

### Configuration Management (New in v2.2)
```bash
# View current security configuration
python network_mapper_refactored.py --show-config

# Reset to secure factory defaults
python network_mapper_refactored.py --reset-config

# Scan with custom security-conscious defaults
python network_mapper_refactored.py 192.168.1.0/24  # Uses config/default_flags.json
```

### High Security Mode
```python
from modules.secure_config import SecurityLevel

mapper = NetworkMapper(
    "192.168.1.0/24",
    security_level=SecurityLevel.HIGH
)
```

### Compliance Reporting
```python
from modules.compliance_reporter import ComplianceReporter, ComplianceFramework

reporter = ComplianceReporter()
report = reporter.generate_compliance_report(ComplianceFramework.NIST)
```

## Security Configuration Levels

### MINIMAL
- Basic input validation
- Standard logging
- Default rate limits

### STANDARD (Default)
- Enhanced input validation
- Security event logging
- Moderate rate limiting
- Basic compliance tracking

### HIGH
- Strict input validation
- Comprehensive security logging
- Aggressive rate limiting
- Full compliance reporting

### MAXIMUM
- Paranoid input validation
- Real-time security monitoring
- Minimal rate limits
- Continuous compliance assessment

## Compliance Frameworks Supported

### NIST Cybersecurity Framework
- **Identify**: Asset discovery and risk assessment
- **Protect**: Access controls and security measures
- **Detect**: Security monitoring and logging
- **Respond**: Incident response capabilities
- **Recover**: System recovery and continuity

### OWASP Top 10 2021
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable Components
- A07: Authentication Failures
- A08: Software Integrity Failures
- A09: Security Logging Failures
- A10: Server-Side Request Forgery

### ISO 27001
- Information security management
- Risk assessment and treatment
- Security controls implementation
- Continuous monitoring and improvement

## Security Metrics

The system tracks various security metrics:
- **Authentication attempts** and failures
- **Input validation** blocks and bypasses
- **Rate limiting** triggers and blocks
- **Security events** by severity and type
- **Compliance scores** across frameworks
- **Vulnerability detection** rates

## Emergency Procedures

### Emergency Shutdown
```python
from modules.secure_config import SecureConfigManager

config = SecureConfigManager()
config.trigger_emergency_shutdown("Security incident detected")
```

### Security Incident Response
1. **Immediate containment** via emergency shutdown
2. **Log preservation** and forensic collection
3. **Incident documentation** and reporting
4. **System recovery** and hardening
5. **Post-incident review** and improvement

## Best Practices

1. **Regular security updates** of dependencies
2. **Periodic security assessments** using SAST tools
3. **Log monitoring** and analysis
4. **Compliance reporting** review
5. **Security configuration** validation
6. **Incident response** testing
7. **Security awareness** training

## Dependencies Security

All dependencies are regularly scanned for vulnerabilities:
- `cryptography` for encryption operations
- `keyring` for secure credential storage
- `python-dotenv` for environment management
- `sqlite3` for secure data storage

## Contributing Security

When contributing to this project:
1. Run security tests: `python -m pytest tests/test_security.py`
2. Execute SAST scan: `bandit -r modules/`
3. Check dependencies: `safety check`
4. Validate compliance: Review `sast_config.yml`
5. Update security documentation

## Security Contact

For security issues or vulnerabilities, please follow responsible disclosure practices and contact the security team through appropriate channels.

---

**Note**: This implementation demonstrates enterprise-grade DevSecOps practices suitable for production environments requiring high security standards and regulatory compliance.