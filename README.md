# Network Mapper - Advanced Network Discovery & Vulnerability Assessment Tool

A comprehensive Python-based network mapping and discovery tool designed for penetration testing and network analysis. This tool provides host discovery, port scanning, service detection, vulnerability assessment, device type identification, MAC address discovery, and detailed reporting capabilities with Excel-friendly CSV export.

**Note**: This is my first Python project and my first venture into offensive security tools development. It represents a learning journey into both Python programming (which I am currently new with) and cybersecurity concepts, developed with the assistance of AI to help guide both the Python implementation and best practices, as well as README format to make it as clear and detailed as possible. Any suggestion is welcome.

## 🔄 Recent Enhancements

### Version 1.2 Features (Latest)
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

### Known Issues
- **False Positives**: Some services may be misidentified due to limited port scanning
- **MAC Address Limitations**: Some devices may not have MAC addresses recorded in ARP tables
- **Device Type Confidence**: Limited accuracy for unknown device types 
- **Device Type: Device type may be wrong due to small amount of ports open or found

### Future Enhancements (Maybe)
- 🔮 **Advanced Vulnerability Scanning**: Integration with CVE databases
- 🔮 **GUI Interface**: User-friendly graphical interface
- 🔮 **Network Topology Visualization**: Interactive network maps
- 🔮 **Database Storage**: Scan history and trend analysis
- 🔮 **Web-based Dashboard**: Real-time reporting interface
- 🔮 **SIEM Integration**: Export to security information systems
- 🔮 **Automated Reporting**: PDF/HTML report generation
- 🔮 **Network Change Detection**: Baseline comparison features

## 📝 License

This project is for educational purposes. Use responsibly and in accordance with applicable laws and regulations.

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

## 📋 Requirements

### Python Dependencies
```bash
# No external dependencies required - uses only Python standard library
python3 -m pip install --upgrade pip
```

### Optional Dependencies
- **Nmap**: For advanced OS detection and service versioning
  - Linux: `sudo apt-get install nmap`
  - Windows: Download from [nmap.org](https://nmap.org/download.html)
- **Colorama**: For enhanced colored output (automatically handled)

## 🛠️ Installation

1. Clone or download the script:
```bash
git clone <repository-url>
cd net_mapping
```

2. Make the script executable (Linux/Mac):
```bash
chmod +x network_mapper.py
```

3. Verify Python installation:
```bash
python3 --version
```

## 📖 Usage

### Basic Usage

```bash
# Scan a network with vulnerability assessment
python3 network_mapper.py 192.168.1.0/24

# Ping sweep only
python3 network_mapper.py 192.168.1.0/24 --ping-only

# Custom thread count and timeout
python3 network_mapper.py 192.168.1.0/24 -t 100 --timeout 5
```

### Advanced Usage with Vulnerability Focus

```bash
# Exclude specific IP ranges with vulnerability assessment
python3 network_mapper.py 192.168.1.0/24 --exclude 192.168.1.1 --exclude 192.168.1.200-192.168.1.254

# Disable smart filtering (scan all IPs including gateways)
python3 network_mapper.py 192.168.1.0/24 --no-smart-filter

# Export results with device detection, MAC addresses, and vulnerabilities
python3 network_mapper.py 192.168.1.0/24 -o my_scan -f json

# Export to CSV with vulnerability data
python3 network_mapper.py 192.168.1.0/24 -o my_scan -f csv

# Use nmap for advanced scanning with vulnerability assessment
python3 network_mapper.py 192.168.1.0/24 --nmap

# Comprehensive vulnerability scan with all options
python3 network_mapper.py 10.0.0.0/24 -t 75 --timeout 2 -o corporate_vuln_scan -f json --nmap --exclude 10.0.0.1-10.0.0.10
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `network` | Target network in CIDR notation (required) | - |
| `-t, --threads` | Number of concurrent threads | 50 |
| `--timeout` | Timeout in seconds for each operation | 3 |
| `-o, --output` | Output filename (without extension) | Auto-generated |
| `-f, --format` | Output format (json/csv) | json |
| `--ping-only` | Only perform host discovery | False |
| `--nmap` | Use nmap for advanced scanning | False |
| `--exclude` | Exclude IP ranges (can be used multiple times) | None |
| `--no-smart-filter` | Disable smart filtering of infrastructure IPs | False |

## 📊 Output Examples

### Console Output
```
╔══════════════════════════════════════════════════════════════╗
║                    NETWORK MAPPER v1.0                       ║
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

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   ```bash
   # Linux: Run with sudo for raw socket access
   sudo python3 network_mapper.py 192.168.1.0/24
   ```

2. **MAC Address Shows "Unknown"**
   - MAC addresses only available for local network segments
   - Try scanning your actual network range instead of localhost
   - Ensure ARP table has entries (ping devices first)

3. **Device Detection Low Confidence**
   - Limited open ports reduce detection accuracy
   - Try scanning with nmap for better service detection
   - Some devices intentionally hide their identity

4. **Timeout Issues**
   ```bash
   # Increase timeout for slow networks
   python3 network_mapper.py 192.168.1.0/24 --timeout 10
   ```

5. **No Hosts Discovered After Filtering**
   ```bash
   # Disable smart filtering to scan all IPs
   python3 network_mapper.py 192.168.1.0/24 --no-smart-filter
   
   # Check if exclusions are too broad
   python3 network_mapper.py 192.168.1.0/24 --exclude 192.168.1.1
   ```

6. **Nmap Not Found**
   ```bash
   # Install nmap
   sudo apt-get install nmap  # Linux
   # Or download from nmap.org for Windows
   ```