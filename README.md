# Network Mapper - Advanced Network Discovery & Vulnerability Assessment Tool

A comprehensive Python-based network mapping and discovery tool designed for penetration testing and network analysis. This tool provides host discovery, port scanning, service detection, vulnerability assessment, device type identification, MAC address discovery, and detailed reporting capabilities with Excel-friendly CSV export.

**Note**: This is my first Python project and my first venture into offensive security tools development. It represents a learning journey into both Python programming (which I am currently new with) and cybersecurity concepts, developed with the assistance of AI to help guide both the Python implementation and best practices, as well as README format to make it as clear and detailed as possible. Any suggestion is welcome.

## ⚠️ Legal and Ethical Considerations

**IMPORTANT**: This tool is designed for educational purposes and authorized penetration testing only.

### Legal Usage Guidelines:
- ✅ Use only on networks you own or have explicit written permission to test
- ✅ Educational environments and personal labs
- ✅ Authorized penetration testing engagements
- ✅ Security research with proper authorization

### Prohibited Usage:
- ❌ Scanning networks without permission
- ❌ Unauthorized network reconnaissance
- ❌ Any malicious activities

**Always ensure you have proper authorization before scanning any network.**

## 🔄 Recent Enhancements

### Version 2.2 Features (Latest - Configuration Management)
- ✅ **⚙️ Configurable Default Flags**: Easily customize default behavior without code changes
  - `config/default_flags.json` - Centralized configuration for all command-line defaults
  - `--show-config` - View current configuration settings
  - `--reset-config` - Reset to factory defaults with automatic backup
  - Dynamic help text showing current default values
  - Configuration validation and error handling
- ✅ **🎯 User-Friendly Configuration**: Simple JSON-based configuration system
- ✅ **📚 Comprehensive Documentation**: Complete configuration guide with examples
- ✅ **🔄 Backup & Recovery**: Automatic configuration backup during reset operations
- ✅ **🛡️ Secure Defaults**: Security-conscious default configurations

### Version 2.1 Features (DevSecOps Enhanced)
- ✅ **🔒 DevSecOps Integration**: Enterprise-grade security practices throughout the development lifecycle
  - `security_logger.py` - Tamper-evident security logging with compliance tracking
  - `input_validator.py` - OWASP-compliant input validation and sanitization
  - `secrets_manager.py` - Encrypted secrets management with keyring integration
  - `rate_limiter.py` - Advanced rate limiting with abuse detection
  - `compliance_reporter.py` - Multi-framework compliance reporting (NIST, OWASP, ISO 27001)
  - `secure_config.py` - Secure-by-default configuration with fail-safe mechanisms
- ✅ **🛡️ Security-First Design**: Defense in depth with multiple security layers
- ✅ **📊 Compliance Ready**: NIST, OWASP Top 10, and ISO 27001 alignment
- ✅ **🔍 Security Testing**: Comprehensive SAST configuration and security-focused unit tests
- ✅ **📈 Security Metrics**: Real-time security monitoring and compliance dashboards
- ✅ **🚨 Incident Response**: Emergency shutdown capabilities and forensic-ready audit trails

### Version 2.0 Features (Refactored Architecture)
- ✅ **🏗️ Modular Architecture**: Complete refactoring into clean, maintainable modules
  - `vulnerability_scanner.py` - Vulnerability assessment engine
  - `device_detector.py` - Device type detection logic
  - `network_utils.py` - Network operations (ping, port scan, service detection)
  - `report_generator.py` - Export and reporting functionality
  - `network_mapper_refactored.py` - Main orchestrator class
- ✅ **📦 Package Structure**: Proper Python package with `__init__.py`
- ✅ **🧪 Enhanced Testing**: Modular components allow for better unit testing
- ✅ **🔧 Maintainability**: Single Responsibility Principle applied throughout
- ✅ **🤝 Easy to Read**: Better to look and understand each part and what they do individually
- ✅ **♻️ Reusability**: Modules can be imported and used in other projects

### Version 1.2 Features
- ✅ **🛡️ Vulnerability Assessment Engine**: Comprehensive vulnerability database for 20+ services
  - CVE reference mapping for critical vulnerabilities
  - Risk level classification (High/Medium/Low)
  - Attack vector identification and security recommendations
- ✅ **📊 Excel-Friendly CSV Export**: Optimized spreadsheet format
  - Separate columns for each service/vulnerability
  - Shortened descriptions for better readability
  - UTF-8 encoding support for special characters
- ✅ **📖 Excel Integration Guide**: Step-by-step import instructions
  - Data tab import methods
  - Column formatting recommendations
  - Troubleshooting common Excel issues

### Version 1.1 Features
- ✅ **Device Type Detection**: Automatic classification with confidence scoring
- ✅ **MAC Address Discovery**: ARP table lookup for physical addresses
- ✅ **Smart IP Filtering**: Skip common infrastructure addresses
- ✅ **Custom Exclusions**: Flexible IP range exclusion system
- ✅ **Enhanced Exports**: JSON and CSV now include device type and MAC data
- ✅ **Improved Performance**: Reduced scan times through intelligent filtering
- ✅ **Better Reporting**: Cleaner output with device information

## 📁 Project Structure

```
net_mapping/
├── config/                          # Configuration management
│   ├── default_flags.json          # Default flag configuration
│   └── backups/                     # Configuration backups
├── docs/                            # Documentation
│   └── configuration_guide.md      # Configuration system guide
├── modules/                         # Modular components package
│   ├── __init__.py                 # Package initialization
│   ├── vulnerability_scanner.py    # Vulnerability assessment logic
│   ├── device_detector.py         # Device type detection
│   ├── network_utils.py           # Network operations
│   ├── report_generator.py        # Export and reporting
│   ├── security_logger.py         # Security audit logging (DevSecOps)
│   ├── input_validator.py         # Input validation & sanitization (DevSecOps)
│   ├── secrets_manager.py         # Encrypted secrets management (DevSecOps)
│   ├── rate_limiter.py            # Rate limiting & abuse detection (DevSecOps)
│   ├── compliance_reporter.py     # Compliance reporting (DevSecOps)
│   └── secure_config.py           # Secure configuration management (DevSecOps)
├── tests/                          # Test suite
│   └── test_security.py           # Security-focused unit tests
├── network_mapper.py              # Original monolithic version
├── network_mapper_refactored.py   # New modular version (recommended)
├── requirements.txt               # Python dependencies
├── sast_config.yml               # SAST tools configuration
├── README.md                     # This file
├── README_DevSecOps.md           # Detailed DevSecOps documentation
└── .gitignore                    # Git ignore patterns
```

## 🐍 Understanding Python Cache (`__pycache__`)
Adding this because while researching and getting help by the AI Agent, it told me that it makes the python run faster and smoother but i had no clue what this thing was.. So who better to explain than the Python documentation itself?

When you run Python code, you might notice a `__pycache__` folder appearing in your project directory. Here's what it is:

### What is `__pycache__`?
- **Purpose**: Python automatically creates this folder to store compiled bytecode files
- **Files**: Contains `.pyc` files (Python compiled) for faster module loading
- **Automatic**: Created automatically when you import modules or run Python scripts
- **Performance**: Speeds up subsequent imports by avoiding recompilation

### Example Structure:
```
modules/
├── __pycache__/                    # Auto-generated cache folder
│   ├── __init__.cpython-39.pyc    # Compiled version of __init__.py
│   ├── vulnerability_scanner.cpython-39.pyc
│   └── device_detector.cpython-39.pyc
├── __init__.py                     # Your source files
├── vulnerability_scanner.py
└── device_detector.py
```

### Should You Worry About It?
- **✅ Safe to ignore**: These files are automatically managed by Python
- **✅ Safe to delete**: Python will recreate them as needed
- **✅ Git ignored**: Already included in `.gitignore` so they won't be committed
- **❌ Don't edit**: These are binary files, not meant for human editing

### When Does It Appear?
```bash
# This will create __pycache__ folders:
python network_mapper_refactored.py 192.168.1.0/24

# Because the script imports modules:
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.device_detector import DeviceDetector
# etc.
```

---

**Disclaimer**: This tool is provided for educational and authorized testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.

## 🚀 Features

- **Host Discovery**: Fast ping sweep to identify live hosts on a network
- **Smart IP Filtering**: Automatically excludes common infrastructure IPs (gateways, broadcast addresses)
- **Custom IP Exclusion**: Exclude specific IP ranges or addresses from scanning
- **Port Scanning**: Multi-threaded port scanning with customizable port lists
- **Service Detection**: Automatic service fingerprinting and banner grabbing
- **🔥 Vulnerability Assessment**: Comprehensive vulnerability database with 20+ services
  - Attack vector identification
  - Critical vulnerability detection (CVE mapping)
  - Security risk assessment
- **Device Type Detection**: Intelligent device classification (Windows, Linux, routers, mobile devices, IoT)
- **MAC Address Discovery**: Retrieves MAC addresses via ARP table lookup
- **Hostname Resolution**: DNS reverse lookup for discovered hosts
- **Multiple Output Formats**: Export results in JSON or Excel-friendly CSV format
  - **Enhanced CSV**: Separate columns for each service/vulnerability
  - **Excel Integration**: Optimized formatting for spreadsheet analysis
- **Nmap Integration**: Optional nmap integration for advanced scanning
- **Multi-threading**: Configurable thread count for optimal performance
- **Cross-platform**: Works on both Windows and Linux systems

### 🔒 DevSecOps Security Features

- **🛡️ Security Audit Logging**: Tamper-evident logging with cryptographic checksums and compliance tracking
- **🔍 Input Validation**: OWASP-compliant validation preventing injection attacks and malicious inputs
- **🔐 Secrets Management**: Encrypted storage of API keys and credentials with keyring integration
- **⚡ Rate Limiting**: Advanced rate limiting with abuse detection and adaptive throttling
- **📊 Compliance Reporting**: Automated compliance assessments for NIST, OWASP Top 10, and ISO 27001
- **⚙️ Secure Configuration**: Secure-by-default settings with multiple security levels and fail-safe mechanisms
- **🚨 Emergency Response**: Emergency shutdown capabilities and incident response features
- **📈 Security Metrics**: Real-time security monitoring and compliance dashboards
- **🧪 Security Testing**: Comprehensive SAST configuration and security-focused unit tests

## 📋 Requirements

### Core Dependencies
The tool now includes comprehensive dependencies for both command-line and GUI usage:

#### Main Requirements (`requirements.txt`)
- **Core functionality**: tqdm, colorama for progress and output
- **GUI framework**: tkinter (included in Python), requests for updates
- **Network analysis**: scapy, python-nmap, networkx, matplotlib
- **Security**: cryptography, keyring, python-dotenv
- **Development**: bandit, safety, semgrep, pytest
- **Reports**: reportlab, weasyprint, Pillow

#### GUI Enhancements (`requirements-gui.txt`)
- **Data processing**: pandas, numpy for advanced analysis
- **Export formats**: openpyxl for Excel, tabulate for formatting
- **Visual enhancements**: Additional Pillow features

### System Dependencies
- **Nmap**: For advanced OS detection and service versioning
  - Linux: `sudo apt-get install nmap`
  - Windows: Download from [nmap.org](https://nmap.org/download.html)
- **Python 3.8+**: Required for GUI features and modern security libraries

### Platform-Specific Notes
- **Windows**: All dependencies included, tkinter available by default
- **Linux**: May need `python3-tk` package for GUI: `sudo apt-get install python3-tk`
- **macOS**: Use Python from python.org for full tkinter support

## 🛠️ Installation

### Prerequisites
- **Python 3.7+** (tested with Python 3.8-3.11)
- **Network access** to target networks
- **Administrator/root privileges** (recommended for advanced features)

### DevSecOps Dependencies (Optional)
For enhanced security features, install additional packages:
```bash
pip install keyring cryptography psutil
```

### Quick Installation

#### Command Line Version (Basic)
```bash
# Clone the repository
git clone <repository-url>
cd net_mapping

# Install core dependencies
pip install -r requirements.txt

# Verify installation
python network_mapper_refactored.py --help
```

#### GUI Version (Full Features)
```bash
# Clone the repository
git clone <repository-url>
cd net_mapping

# Install all dependencies (core + GUI)
pip install -r requirements.txt
pip install -r requirements-gui.txt

# Launch GUI
python network_mapper_gui_refactored.py
```

#### Requirements Files
- **`requirements.txt`**: Core dependencies + GUI essentials (network analysis, security, visualization)
- **`requirements-gui.txt`**: Additional GUI-specific enhancements (data processing, advanced exports)

**Note**: The main `requirements.txt` now includes GUI dependencies. Use `requirements-gui.txt` for additional enhancements.

### Configuration Setup
The tool includes a configurable default flags system for easy customization:

```bash
# View current configuration
python network_mapper_refactored.py --show-config

# Reset to factory defaults (creates backup)
python network_mapper_refactored.py --reset-config
```

**Configuration File**: `config/default_flags.json`
- Customize default values for all command-line options
- Automatic validation and error handling
- Backup system for safe configuration changes

📖 **See `docs/configuration_guide.md` for detailed configuration instructions**

### Additional Setup (Optional)

1. Make the script executable (Linux/Mac):
```bash
chmod +x network_mapper.py
```

2. Install DevSecOps tools (optional but recommended):
```bash
pip install bandit safety semgrep
```

3. Run security tests (optional):
```bash
python -m pytest tests/test_security.py -v
bandit -r modules/ -f json -o security_report.json
safety check
```

4. Verify Python installation:
```bash
python3 --version
```

## 📖 Usage

### 🖥️ GUI Usage (Recommended for Interactive Use)

The Network Mapper includes both original and refactored GUI versions with comprehensive features:

#### GUI Installation
```bash
# Install GUI-specific dependencies
pip install -r requirements.txt
pip install -r requirements-gui.txt

# Launch the refactored GUI (recommended)
python network_mapper_gui_refactored.py

# Launch the original GUI (legacy)
python network_mapper_gui.py
```

#### GUI Features
- **🎯 Interactive Scanning**: Point-and-click network scanning with real-time progress
- **📊 Live Results**: Real-time display of discovered hosts, services, and vulnerabilities
- **🔍 Traffic Monitoring**: Advanced network traffic analysis with packet capture
- **📈 Network Topology**: Visual network mapping and device relationship analysis
- **📋 Export Options**: Multiple export formats (CSV, JSON, HTML, PDF reports)
- **⚙️ Configuration Management**: Easy-to-use settings and security level configuration
- **🛡️ Security Dashboard**: Real-time security monitoring and compliance tracking

#### GUI Usage Instructions
1. **Launch the GUI**: Run `python network_mapper_gui_refactored.py`
2. **Configure Scan**: Enter target network (e.g., `192.168.1.0/24`) and adjust settings
3. **Start Scanning**: Click "Start Scan" to begin network discovery
4. **Monitor Progress**: Watch real-time progress and results in the interface
5. **Analyze Results**: Review discovered hosts, services, and vulnerabilities
6. **Traffic Analysis**: Use the Traffic tab for network monitoring and packet analysis
7. **Export Data**: Generate reports in various formats (CSV, JSON, PDF)

#### GUI Requirements
- **Python 3.8+** with tkinter support (included in most Python installations)
- **Additional packages**: See `requirements-gui.txt` for complete list
- **System Requirements**:
  - Windows: tkinter included by default
  - Linux: Install `python3-tk` package if needed
  - macOS: tkinter included with Python from python.org

### 💻 Command Line Usage (Recommended - Modular Version)

```bash
# Scan a network with vulnerability assessment (new modular version)
python3 network_mapper_refactored.py 192.168.1.0/24

# Ping sweep only
python3 network_mapper_refactored.py 192.168.1.0/24 --ping-only

# Custom thread count and timeout
python3 network_mapper_refactored.py 192.168.1.0/24 -t 100 --timeout 5

# Generate vulnerability report
python3 network_mapper_refactored.py 192.168.1.0/24 --vuln-report

# Enable security logging and compliance reporting
python3 network_mapper_refactored.py 192.168.1.0/24 --security-level high --compliance-report

# Emergency mode with minimal footprint
python3 network_mapper_refactored.py 192.168.1.0/24 --security-level emergency
```

### Advanced Usage with Vulnerability Focus

```bash
# Exclude specific IP ranges with vulnerability assessment
python3 network_mapper_refactored.py 192.168.1.0/24 --exclude 192.168.1.1 --exclude 192.168.1.200-192.168.1.254

# Disable smart filtering (scan all IPs including gateways)
python3 network_mapper_refactored.py 192.168.1.0/24 --no-smart-filter

# Export results with device detection, MAC addresses, and vulnerabilities
python3 network_mapper_refactored.py 192.168.1.0/24 -o my_scan -f json

# Export to CSV with vulnerability data
python3 network_mapper_refactored.py 192.168.1.0/24 -o my_scan -f csv

# Use nmap for advanced scanning with vulnerability assessment
python3 network_mapper_refactored.py 192.168.1.0/24 --nmap

# Comprehensive vulnerability scan with all options
python3 network_mapper_refactored.py 10.0.0.0/24 -t 75 --timeout 2 -o corporate_vuln_scan -f json --nmap --exclude 10.0.0.1-10.0.0.10

# Stealth scan with rate limiting
python3 network_mapper_refactored.py 10.0.0.0/16 --ports 22,80,443,3389 -t 50 --timeout 5 --rate-limit 10 --security-level medium
```

### Security Testing

```bash
# Run comprehensive security tests
python -m pytest tests/test_security.py -v

# Generate SAST security report
bandit -r modules/ -f json -o security_report.json

# Check for vulnerable dependencies
safety check --json --output safety_report.json

# Run Semgrep security analysis
semgrep --config=auto modules/
```

### Legacy Usage (Original Monolithic Version)

```bash
# Original version (still available but not recommended for new projects)
python3 network_mapper.py 192.168.1.0/24
```

### Command Line Arguments

| Argument | Description | Default | DevSecOps Enhanced |
|----------|-------------|---------|-------------------|
| `network` | Target network in CIDR notation (required) | - | ✅ Input validation |
| `-t, --threads` | Number of concurrent threads | 50* | ✅ Rate limited |
| `--timeout` | Timeout in seconds for each operation | 3* | ✅ Secure defaults |
| `-o, --output` | Output filename (without extension) | Auto-generated | ✅ Path validation |
| `-f, --format` | Output format (json/csv) | json* | ✅ Format validation |
| `--ping-only` | Only perform host discovery | False | ✅ Secure scanning |
| `--nmap` | Use nmap for advanced scanning | False* | ✅ Command injection protection |
| `--exclude` | Exclude IP ranges (can be used multiple times) | None | ✅ IP validation |
| `--no-smart-filter` | Disable smart filtering of infrastructure IPs | False | ✅ Security filtering |
| `--vuln-report` | Generate vulnerability report | False* | ✅ Secure reporting |
| `--security-level` | Security level (low/medium/high/emergency) | medium | 🆕 DevSecOps feature |
| `--compliance-report` | Generate compliance assessment report | False | 🆕 DevSecOps feature |
| `--rate-limit` | Maximum requests per second | 50 | 🆕 DevSecOps feature |
| `--audit-log` | Enable security audit logging | True | 🆕 DevSecOps feature |
| `--emergency-mode` | Enable emergency shutdown capabilities | False | 🆕 DevSecOps feature |
| `--show-config` | Display current configuration settings | N/A | 🆕 Configuration management |
| `--reset-config` | Reset to factory defaults with backup | N/A | 🆕 Configuration management |

**Note**: Default values marked with * can be customized in `config/default_flags.json`

### Configuration Management Commands

```bash
# View current default settings
python network_mapper_refactored.py --show-config

# Reset configuration to factory defaults (creates backup)
python network_mapper_refactored.py --reset-config

# These commands work without requiring a network argument
```

## 📊 Output Examples

### Console Output
```
╔══════════════════════════════════════════════════════════════╗
║                    NETWORK MAPPER v2.2                      ║
║              Advanced Network Discovery Tool                 ║
║                  For Educational Purposes                    ║
╚══════════════════════════════════════════════════════════════╝

[+] Starting ping sweep on 192.168.1.0/24
[+] Using 50 threads with 3s timeout
[!] Skipping likely gateway: 192.168.1.1
[!] Skipping likely gateway: 192.168.1.254
[+] Filtered out 2 IPs (gateways, excluded ranges, etc.)
[+] Scanning 252 filtered IP addresses
[+] Host 192.168.1.100 is alive
[+] Discovered 1 live hosts

[+] Starting comprehensive network scan...

[+] Scanning 192.168.1.100
[+] Getting MAC address...
[+] Scanning ports on 192.168.1.100
    Port 22: SSH
    Port 80: HTTP
    Device Type: Linux Server (85%)
    MAC Address: aa:bb:cc:dd:ee:ff

============================================================
NETWORK SCAN SUMMARY
============================================================
Target Network: 192.168.1.0/24
Total Hosts Discovered: 1
Scan Completed: 2024-01-15 10:30:45

DISCOVERED HOSTS:
------------------------------------------------------------
Host: 192.168.1.100 (webserver.local)
  MAC Address: aa:bb:cc:dd:ee:ff
  Device Type: Linux Server (85%)
  Open Ports: 22, 80
    22: SSH
    80: HTTP

[+] Results exported to scan_results.json (1 hosts with open ports)
```

### Enhanced JSON Output with Vulnerability Data
```json
{
  "scan_info": {
    "target_network": "192.168.1.0/24",
    "scan_time": "2024-01-15T10:30:45.123456",
    "total_hosts": 1,
    "hosts_with_open_ports": 1,
    "vulnerability_scan": true
  },
  "results": {
    "192.168.1.100": {
      "hostname": "webserver.local",
      "mac_address": "aa:bb:cc:dd:ee:ff",
      "device_type": "Linux Server (85%)",
      "open_ports": [21, 22, 80, 443],
      "services": {
        "21": "FTP - vsftpd 2.3.4",
        "22": "SSH - OpenSSH 7.4",
        "80": "HTTP - Apache 2.4.29",
        "443": "HTTPS - Apache 2.4.29"
      },
      "vulnerabilities": {
        "21": {
          "service": "FTP",
          "issues": ["Anonymous login enabled", "Outdated version"],
          "risk_level": "High",
          "cve_references": ["CVE-2011-2523"]
        },
        "22": {
          "service": "SSH",
          "issues": ["Weak encryption algorithms"],
          "risk_level": "Medium"
        }
      },
      "scan_time": "2024-01-15T10:30:45.123456"
    }
  }
}
```

### Enhanced CSV Output (Excel-Friendly Format)
```csv
IP,Hostname,MAC_Address,Device_Type,Scan_Time,Port_21_FTP,Port_22_SSH,Port_80_HTTP,Port_443_HTTPS,Other_Ports
192.168.1.100,webserver.local,aa:bb:cc:dd:ee:ff,Linux Server (85%),2024-01-15T10:30:45,FTP: Anonymous login (HIGH RISK),SSH: Weak encryption (MEDIUM),HTTP: Apache 2.4.29,HTTPS: Apache 2.4.29,
```

## 🛡️ Vulnerability Assessment Features

### Comprehensive Vulnerability Database
The tool includes vulnerability assessments for 20+ common services:

#### Network Services
- **FTP (21)**: Anonymous access, version vulnerabilities, weak configurations
- **SSH (22)**: Weak algorithms, outdated versions, configuration issues
- **Telnet (23)**: Unencrypted protocols, default credentials
- **SMTP (25)**: Open relays, version vulnerabilities
- **DNS (53)**: Zone transfers, cache poisoning vulnerabilities

#### Web Services  
- **HTTP/HTTPS (80/443)**: Server vulnerabilities, SSL/TLS issues, directory traversal
- **Alternative HTTP (8080/8443)**: Proxy vulnerabilities, admin interfaces

#### Database Services
- **MySQL (3306)**: Default credentials, version vulnerabilities, privilege escalation
- **PostgreSQL (5432)**: Authentication bypass, injection vulnerabilities

#### Remote Access
- **RDP (3389)**: BlueKeep, weak authentication, encryption issues
- **VNC (5900)**: Weak passwords, unencrypted connections

#### And many more services with detailed vulnerability mappings...

### Vulnerability Risk Levels
- **🔴 HIGH**: Critical vulnerabilities requiring immediate attention
- **🟡 MEDIUM**: Important security issues that should be addressed
- **🟢 LOW**: Minor security concerns or informational findings

### Excel Integration Guide
For best results when opening CSV files in Excel:

1. **Use Data Tab Import**: Don't double-click the CSV file
2. **Set UTF-8 Encoding**: Ensures special characters display correctly  
3. **Configure Delimiters**: Use comma as delimiter
4. **Auto-fit Columns**: For better readability
5. **Apply Filters**: To sort by risk levels or services

📖 **See `Excel_Import_Guide.md` for detailed instructions**

## 🎯 Device Type Detection

The tool automatically identifies device types based on:

### Detection Categories
- **Windows Systems** (desktops, servers)
- **Linux/Unix Systems** (servers, workstations)
- **Network Devices** (routers, switches, access points)
- **Mobile Devices** (Android, iOS)
- **IoT Devices** (smart TVs, cameras, printers)
- **Unknown Devices** (when classification is uncertain)

### Detection Methods
- **Port Analysis**: Common service ports (RDP=Windows, SSH=Linux, etc.)
- **Service Banners**: HTTP headers, SSH versions, service strings
- **Hostname Patterns**: Device naming conventions
- **Confidence Scoring**: Percentage-based reliability indicator

### Example Device Classifications
```
Windows System (95%) - Multiple Windows ports detected
Linux Server (85%) - SSH + web services
Router (70%) - Web interface + SNMP
Android Device (60%) - Mobile-specific services
Unknown Device (30%) - Limited information available
```

## 🔧 Smart Filtering Features

### Automatic Smart Filtering (Default)
- **Gateway IPs**: `.1` and `.254` addresses
- **Network/Broadcast**: `.0` and `.255` addresses (context-dependent)
- **Performance**: Reduces scan time by 1-4 IPs per /24 network

### Custom Exclusion Examples
```bash
# Exclude single IPs
--exclude 192.168.1.1 --exclude 192.168.1.254

# Exclude IP ranges
--exclude 192.168.1.1-192.168.1.10 --exclude 192.168.1.200-192.168.1.254

# Exclude subnets
--exclude 192.168.1.0/28

# Multiple exclusions
--exclude 192.168.1.1 --exclude 192.168.1.50-192.168.1.100 --exclude 192.168.1.200/29
```

### Filtering Benefits
- **Faster Scans**: Skip unlikely targets
- **Focused Results**: Concentrate on actual devices
- **Reduced Network Load**: Fewer unnecessary packets
- **Customizable**: Adapt to specific network layouts

## 🔧 Customization

### Custom Port Lists
Modify the `port_scan` method to scan custom ports:

```python
# In the port_scan method, replace the default ports list:
ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]

# With your custom ports:
ports = [80, 443, 8080, 8443, 9000, 9090]  # Web services only
```

### Performance Tuning

```bash
# For small networks (< 50 hosts) with smart filtering
python3 network_mapper.py 192.168.1.0/24 -t 25 --timeout 2

# For large networks (> 500 hosts) with exclusions
python3 network_mapper.py 10.0.0.0/16 -t 100 --timeout 1 --exclude 10.0.0.1-10.0.0.50

# For slow networks
python3 network_mapper.py 192.168.1.0/24 -t 10 --timeout 10

# Maximum performance (disable smart filtering)
python3 network_mapper.py 192.168.1.0/24 -t 200 --timeout 1 --no-smart-filter
```


## 🔧 Troubleshooting

### Common Issues

1. **Permission Errors**
   - **Issue**: "Permission denied" when scanning
   - **Solution**: Run with administrator/root privileges for raw socket operations
   - **DevSecOps**: Check security audit logs for permission-related events

2. **High Memory Usage**
   - **Issue**: Script consumes too much memory on large networks
   - **Solution**: Reduce thread count (`--threads 25`) or scan smaller subnets
   - **DevSecOps**: Use `--security-level emergency` for minimal resource usage

3. **Slow Scanning**
   - **Issue**: Scanning takes too long
   - **Solution**: Increase threads, reduce timeout, or use targeted port lists
   - **DevSecOps**: Enable rate limiting (`--rate-limit`) to balance speed and stealth

4. **Nmap Not Found**
   - **Issue**: "nmap command not found"
   - **Solution**: Install nmap or run without `--nmap` flag
   - **DevSecOps**: Input validator will warn about missing dependencies

5. **Network Connectivity**
   - **Issue**: No hosts discovered
   - **Solution**: Check network connectivity, firewall rules, and target network
   - **DevSecOps**: Review security logs for network-related errors

6. **Security Validation Errors**
   - **Issue**: Input validation failures
   - **Solution**: Ensure IP ranges, ports, and file paths follow expected formats
   - **DevSecOps**: Check audit logs for detailed validation error messages

### Known Issues

- Some antivirus software may flag the script as potentially unwanted due to network scanning capabilities
- Windows Defender may require exclusion for the script directory
- Rate limiting may affect scan speed but improves stealth and compliance
- Emergency mode disables some features for maximum security

### Future Enhancements

- **Enhanced DevSecOps Features**:
  - Integration with SIEM systems
  - Advanced threat intelligence feeds
  - Automated incident response workflows
  - Machine learning-based anomaly detection
- **Performance Improvements**:
  - Asynchronous scanning engine
  - Distributed scanning capabilities
  - Cloud-native deployment options
- **Additional Compliance Frameworks**:
  - SOC 2 Type II compliance
  - GDPR privacy assessments
  - Industry-specific standards (HIPAA, PCI-DSS)

## 📝 License

This project is for educational purposes. Use responsibly and in accordance with applicable laws and regulations.
   
   # Check if exclusions are too broad
   python3 network_mapper.py 192.168.1.0/24 --exclude 192.168.1.1
   ```

6. **Nmap Not Found**
   ```bash
   # Install nmap
   sudo apt-get install nmap  # Linux
   # Or download from nmap.org for Windows
   ```