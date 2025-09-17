#!/usr/bin/env python3
"""
Network Mapper - Advanced Network Discovery and Mapping Tool
Author: Gustavo Valente
Description: Comprehensive network mapping tool for penetration testing and network analysis
"""

import os
import subprocess
import socket
import threading
import ipaddress
import json
import csv
import argparse
import sys
import time
import signal
import atexit
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

# Optional colorama for colored output
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Auto-reset colors after each print
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    # Fallback color class for when colorama is not available
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

# Optional tqdm for progress bars
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    # Fallback progress class when tqdm is not available
    class tqdm:
        def __init__(self, iterable=None, total=None, desc=None, unit=None, **kwargs):
            self.iterable = iterable
            self.total = total or (len(iterable) if iterable else 0)
            self.desc = desc
            self.current = 0
            self.start_time = time.time()
            if desc:
                print(f"[+] {desc}: Starting...")
        
        def __iter__(self):
            if self.iterable:
                for item in self.iterable:
                    yield item
                    self.update(1)
            return self
        
        def __enter__(self):
            return self
        
        def __exit__(self, *args):
            if self.desc:
                elapsed = time.time() - self.start_time
                print(f"[+] {self.desc}: Completed in {elapsed:.2f}s")
        
        def update(self, n=1):
            self.current += n
            if self.total > 0:
                progress = (self.current / self.total) * 100
                if self.current % max(1, self.total // 10) == 0 or self.current == self.total:
                    elapsed = time.time() - self.start_time
                    if self.current > 0 and elapsed > 0:
                        rate = self.current / elapsed
                        eta = (self.total - self.current) / rate if rate > 0 else 0
                        print(f"[+] {self.desc}: {progress:.1f}% ({self.current}/{self.total}) - ETA: {eta:.1f}s")
        
        def set_description(self, desc):
            self.desc = desc

class NetworkMapper:
    def __init__(self, target_network, threads=50, timeout=3, exclude_ranges=None, smart_filter=True):
        self.target_network = target_network
        self.threads = threads
        self.timeout = timeout
        self.exclude_ranges = exclude_ranges or []
        self.smart_filter = smart_filter
        self.scan_results = {}
        self.total_hosts_found = 0
        self.total_ports_found = 0
        self.scan_start_time = None
        
        # Incremental export settings
        self.output_file = None
        self.output_format = None
        self.incremental_mode = False
        self.csv_writer = None
        self.csv_file_handle = None
        self.json_file_handle = None
        self.first_json_entry = True
        
        # Vulnerability database
        self.vulnerability_db = self._load_vulnerability_database()
        
        # Register cleanup handlers
        atexit.register(self.cleanup_on_exit)
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def _load_vulnerability_database(self):
        """Load vulnerability information for common services"""
        return {
            21: {
                "service": "FTP",
                "vulnerabilities": [
                    "Anonymous login may be enabled",
                    "Brute force attacks possible",
                    "Unencrypted data transmission",
                    "Directory traversal vulnerabilities"
                ],
                "attack_vectors": ["Brute force", "Anonymous access", "Man-in-the-middle"]
            },
            22: {
                "service": "SSH",
                "vulnerabilities": [
                    "Weak authentication methods",
                    "Brute force attacks possible",
                    "Outdated SSH versions may have CVEs"
                ],
                "attack_vectors": ["Brute force", "Key-based attacks", "Protocol downgrade"]
            },
            23: {
                "service": "Telnet",
                "vulnerabilities": [
                    "Unencrypted communication",
                    "Credentials sent in plaintext",
                    "No authentication encryption"
                ],
                "attack_vectors": ["Credential sniffing", "Man-in-the-middle", "Session hijacking"]
            },
            25: {
                "service": "SMTP",
                "vulnerabilities": [
                    "Open relay configuration",
                    "Email spoofing possible",
                    "User enumeration via VRFY/EXPN"
                ],
                "attack_vectors": ["Email spoofing", "Spam relay", "User enumeration"]
            },
            53: {
                "service": "DNS",
                "vulnerabilities": [
                    "DNS cache poisoning",
                    "Zone transfer attacks",
                    "DNS amplification attacks"
                ],
                "attack_vectors": ["Cache poisoning", "Zone transfer", "DDoS amplification"]
            },
            80: {
                "service": "HTTP",
                "vulnerabilities": [
                    "Unencrypted web traffic",
                    "Web application vulnerabilities",
                    "Information disclosure"
                ],
                "attack_vectors": ["Web app attacks", "Traffic interception", "XSS/SQLi"]
            },
            110: {
                "service": "POP3",
                "vulnerabilities": [
                    "Unencrypted email retrieval",
                    "Credentials sent in plaintext",
                    "Email content exposure"
                ],
                "attack_vectors": ["Credential sniffing", "Email interception", "Brute force"]
            },
            135: {
                "service": "RPC",
                "vulnerabilities": [
                    "RPC endpoint enumeration",
                    "Buffer overflow vulnerabilities",
                    "Privilege escalation possible"
                ],
                "attack_vectors": ["RPC enumeration", "Buffer overflow", "Privilege escalation"]
            },
            139: {
                "service": "NetBIOS",
                "vulnerabilities": [
                    "SMB relay attacks",
                    "Null session enumeration",
                    "Share enumeration"
                ],
                "attack_vectors": ["SMB relay", "Null sessions", "Share enumeration"]
            },
            143: {
                "service": "IMAP",
                "vulnerabilities": [
                    "Unencrypted email access",
                    "Credentials in plaintext",
                    "Email content exposure"
                ],
                "attack_vectors": ["Credential sniffing", "Email interception", "Brute force"]
            },
            443: {
                "service": "HTTPS",
                "vulnerabilities": [
                    "SSL/TLS configuration issues",
                    "Weak cipher suites",
                    "Certificate validation bypass"
                ],
                "attack_vectors": ["SSL/TLS attacks", "Certificate spoofing", "Weak encryption"]
            },
            445: {
                "service": "SMB",
                "vulnerabilities": [
                    "SMB relay attacks",
                    "EternalBlue (MS17-010)",
                    "Share enumeration and access"
                ],
                "attack_vectors": ["SMB relay", "EternalBlue exploit", "Share enumeration"]
            },
            993: {
                "service": "IMAPS",
                "vulnerabilities": [
                    "SSL/TLS configuration issues",
                    "Weak cipher suites",
                    "Certificate validation bypass"
                ],
                "attack_vectors": ["SSL/TLS attacks", "Certificate spoofing", "Brute force"]
            },
            995: {
                "service": "POP3S",
                "vulnerabilities": [
                    "SSL/TLS configuration issues",
                    "Weak cipher suites",
                    "Certificate validation bypass"
                ],
                "attack_vectors": ["SSL/TLS attacks", "Certificate spoofing", "Brute force"]
            },
            1433: {
                "service": "MSSQL",
                "vulnerabilities": [
                    "SQL injection vulnerabilities",
                    "Weak authentication",
                    "Database enumeration"
                ],
                "attack_vectors": ["SQL injection", "Brute force", "Database enumeration"]
            },
            1723: {
                "service": "PPTP",
                "vulnerabilities": [
                    "Weak encryption (MPPE)",
                    "Authentication bypass",
                    "VPN tunnel attacks"
                ],
                "attack_vectors": ["Encryption attacks", "Authentication bypass", "Tunnel hijacking"]
            },
            3306: {
                "service": "MySQL",
                "vulnerabilities": [
                    "SQL injection vulnerabilities",
                    "Weak root passwords",
                    "Database enumeration"
                ],
                "attack_vectors": ["SQL injection", "Brute force", "Database enumeration"]
            },
            3389: {
                "service": "RDP",
                "vulnerabilities": [
                    "BlueKeep (CVE-2019-0708)",
                    "Brute force attacks",
                    "Man-in-the-middle attacks"
                ],
                "attack_vectors": ["BlueKeep exploit", "Brute force", "Session hijacking"]
            },
            5432: {
                "service": "PostgreSQL",
                "vulnerabilities": [
                    "SQL injection vulnerabilities",
                    "Weak authentication",
                    "Database enumeration"
                ],
                "attack_vectors": ["SQL injection", "Brute force", "Database enumeration"]
            },
            5900: {
                "service": "VNC",
                "vulnerabilities": [
                    "Weak or no authentication",
                    "Unencrypted screen sharing",
                    "Remote access vulnerabilities"
                ],
                "attack_vectors": ["Unauthorized access", "Screen capture", "Remote control"]
            },
            6379: {
                "service": "Redis",
                "vulnerabilities": [
                    "No authentication by default",
                    "Command injection",
                    "Data exposure"
                ],
                "attack_vectors": ["Unauthorized access", "Command injection", "Data exfiltration"]
            },
            8080: {
                "service": "HTTP-Alt",
                "vulnerabilities": [
                    "Web application vulnerabilities",
                    "Administrative interfaces exposed",
                    "Unencrypted traffic"
                ],
                "attack_vectors": ["Web app attacks", "Admin panel access", "Traffic interception"]
            }
        }
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handle interruption signals gracefully"""
        print(f"\n{Fore.YELLOW}[!] Received interruption signal. Finalizing output file...")
        self.finalize_output_file()
        print(f"{Fore.GREEN}[+] Scan results saved successfully. Exiting...")
        sys.exit(0)
    
    def cleanup_on_exit(self):
        """Cleanup function called on normal exit"""
        if self.incremental_mode and (self.json_file_handle or self.csv_file_handle):
            self.finalize_output_file()
    
    def setup_incremental_export(self, format_type='json', filename=None):
        """Setup incremental export to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}"
        
        self.output_format = format_type
        self.output_file = f"{filename}.{format_type}"
        self.incremental_mode = True
        print(f"{Fore.GREEN}[+] Incremental export enabled: {self.output_file}")
        
        if format_type == 'json':
            self.json_file_handle = open(self.output_file, 'w')
            self.first_json_entry = True
            
            # Write JSON header
            self.json_file_handle.write('{\n')
            self.json_file_handle.write('  "scan_info": {\n')
            self.json_file_handle.write(f'    "target_network": "{self.target_network}",\n')
            self.json_file_handle.write(f'    "scan_start_time": "{datetime.now().isoformat()}",\n')
            self.json_file_handle.write('    "scan_status": "in_progress"\n')
            self.json_file_handle.write('  },\n')
            self.json_file_handle.write('  "results": {\n')
            self.json_file_handle.flush()
            
        elif format_type == 'csv':
            self.csv_file_handle = open(self.output_file, 'w', newline='')
            self.csv_writer = csv.writer(self.csv_file_handle)
            # Write enhanced CSV header with separate columns
            headers = [
                'IP', 'Hostname', 'MAC_Address', 'Device_Type', 'Scan_Time',
                'Port_21_FTP', 'Port_22_SSH', 'Port_23_Telnet', 'Port_25_SMTP', 'Port_53_DNS',
                'Port_80_HTTP', 'Port_110_POP3', 'Port_135_RPC', 'Port_139_NetBIOS', 'Port_143_IMAP',
                'Port_443_HTTPS', 'Port_445_SMB', 'Port_993_IMAPS', 'Port_995_POP3S', 'Port_1433_MSSQL',
                'Port_1723_PPTP', 'Port_3306_MySQL', 'Port_3389_RDP', 'Port_5432_PostgreSQL', 
                'Port_5900_VNC', 'Port_6379_Redis', 'Port_8080_HTTP_Alt', 'Other_Ports'
            ]
            self.csv_writer.writerow(headers)
            self.csv_file_handle.flush()
        
        print(f"{Fore.GREEN}[+] Incremental export enabled: {self.output_file}")
    
    def write_host_result(self, host, result):
        """Write individual host result to file immediately"""
        if not self.incremental_mode or not result.get('open_ports'):
            return
        
        if self.output_format == 'json':
            if not self.first_json_entry:
                self.json_file_handle.write(',\n')
            else:
                self.first_json_entry = False
            
            # Write host result
            self.json_file_handle.write(f'    "{host}": ')
            json.dump(result, self.json_file_handle, indent=6)
            self.json_file_handle.flush()
            
        elif self.output_format == 'csv' and self.csv_writer:
            # Prepare data for separate columns
            mac_address = result.get('mac_address', 'Unknown')
            device_type = result.get('device_type', 'Unknown Device')
            scan_time = result.get('scan_time', datetime.now().isoformat())
            
            # Define port mapping for CSV columns
            port_columns = {
                21: 'Port_21_FTP', 22: 'Port_22_SSH', 23: 'Port_23_Telnet', 25: 'Port_25_SMTP', 53: 'Port_53_DNS',
                80: 'Port_80_HTTP', 110: 'Port_110_POP3', 135: 'Port_135_RPC', 139: 'Port_139_NetBIOS', 143: 'Port_143_IMAP',
                443: 'Port_443_HTTPS', 445: 'Port_445_SMB', 993: 'Port_993_IMAPS', 995: 'Port_995_POP3S', 1433: 'Port_1433_MSSQL',
                1723: 'Port_1723_PPTP', 3306: 'Port_3306_MySQL', 3389: 'Port_3389_RDP', 5432: 'Port_5432_PostgreSQL',
                5900: 'Port_5900_VNC', 6379: 'Port_6379_Redis', 8080: 'Port_8080_HTTP_Alt'
            }
            
            # Initialize row data with basic info
            row_data = {
                'IP': host,
                'Hostname': result['hostname'],
                'MAC_Address': mac_address,
                'Device_Type': device_type,
                'Scan_Time': scan_time
            }
            
            # Initialize all port columns as empty
            for port_col in port_columns.values():
                row_data[port_col] = ''
            row_data['Other_Ports'] = ''
            
            # Fill in service information for each open port (Excel-friendly format)
            other_ports = []
            for port in result['open_ports']:
                port_int = int(port)
                full_service_info = result['services'].get(str(port), f"Unknown service on port {port}")
                
                # Create Excel-friendly shortened version
                if " - Attack Vectors:" in full_service_info:
                    service_name = full_service_info.split(" - Attack Vectors:")[0]
                    # Extract critical vulnerabilities if present
                    if "Critical Vulnerabilities:" in full_service_info:
                        vuln_part = full_service_info.split("Critical Vulnerabilities:")[1].strip()
                        if vuln_part != "None detected":
                            service_info = f"{service_name} | CRITICAL: {vuln_part}"
                        else:
                            service_info = f"{service_name} | No critical vulns"
                    else:
                        service_info = service_name
                else:
                    service_info = full_service_info
                
                if port_int in port_columns:
                    row_data[port_columns[port_int]] = service_info
                else:
                    other_ports.append(f"{port}:{service_info}")
            
            # Add other ports to the Other_Ports column
            if other_ports:
                row_data['Other_Ports'] = '; '.join(other_ports)
            
            # Write row in the correct column order
            headers = [
                'IP', 'Hostname', 'MAC_Address', 'Device_Type', 'Scan_Time',
                'Port_21_FTP', 'Port_22_SSH', 'Port_23_Telnet', 'Port_25_SMTP', 'Port_53_DNS',
                'Port_80_HTTP', 'Port_110_POP3', 'Port_135_RPC', 'Port_139_NetBIOS', 'Port_143_IMAP',
                'Port_443_HTTPS', 'Port_445_SMB', 'Port_993_IMAPS', 'Port_995_POP3S', 'Port_1433_MSSQL',
                'Port_1723_PPTP', 'Port_3306_MySQL', 'Port_3389_RDP', 'Port_5432_PostgreSQL', 
                'Port_5900_VNC', 'Port_6379_Redis', 'Port_8080_HTTP_Alt', 'Other_Ports'
            ]
            
            row_values = [row_data[header] for header in headers]
            self.csv_writer.writerow(row_values)
            # Flush the underlying file
            self.csv_file_handle.flush()
    
    def finalize_output_file(self):
        """Finalize the output file with proper closing"""
        if not self.incremental_mode:
            return
        
        if self.output_format == 'json' and self.json_file_handle:
            # Close JSON structure
            self.json_file_handle.write('\n  },\n')
            self.json_file_handle.write('  "scan_summary": {\n')
            self.json_file_handle.write(f'    "total_hosts_discovered": {self.total_hosts_found},\n')
            self.json_file_handle.write(f'    "total_ports_found": {self.total_ports_found},\n')
            self.json_file_handle.write(f'    "hosts_with_open_ports": {len([r for r in self.scan_results.values() if r.get("open_ports")])},\n')
            if self.scan_start_time:
                elapsed = time.time() - self.scan_start_time
                self.json_file_handle.write(f'    "scan_duration_seconds": {elapsed:.2f},\n')
            self.json_file_handle.write(f'    "scan_completed_time": "{datetime.now().isoformat()}"\n')
            self.json_file_handle.write('  }\n')
            self.json_file_handle.write('}\n')
            self.json_file_handle.close()
            self.json_file_handle = None
            
        elif self.output_format == 'csv' and self.csv_writer:
            # Close CSV file
            self.csv_file_handle.close()
            self.csv_writer = None
            self.csv_file_handle = None
        
        if self.output_file:
            hosts_with_ports = len([r for r in self.scan_results.values() if r.get('open_ports')])
            print(f"{Fore.GREEN}[+] Final results saved to {self.output_file} ({hosts_with_ports} hosts with open ports)")
            self.incremental_mode = False
    
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║{Style.BRIGHT}                    NETWORK MAPPER v2.2                       {Style.RESET_ALL}{Fore.CYAN}║
║{Style.BRIGHT}              Advanced Network Discovery Tool                 {Style.RESET_ALL}{Fore.CYAN}║
║{Style.BRIGHT}                  For Educational Purposes Only               {Style.RESET_ALL}{Fore.CYAN}║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
        
    def filter_ip_addresses(self, network):
        """Filter IP addresses based on exclusion rules and smart filtering"""
        all_ips = list(network.hosts())
        filtered_ips = []
        
        # Common IPs to exclude in smart filtering mode
        smart_exclusions = {
            '.0',    # Network address (usually)
            '.1',    # Common gateway
            '.255',  # Broadcast address (usually)
            '.254',  # Common gateway alternative
        }
        
        for ip in all_ips:
            ip_str = str(ip)
            
            # Check exclude ranges
            should_exclude = False
            for exclude_range in self.exclude_ranges:
                try:
                    exclude_net = ipaddress.ip_network(exclude_range, strict=False)
                    if ip in exclude_net:
                        should_exclude = True
                        break
                except ValueError:
                    # Try as single IP
                    try:
                        if ip == ipaddress.ip_address(exclude_range):
                            should_exclude = True
                            break
                    except ValueError:
                        continue
            
            # Smart filtering
            if self.smart_filter and not should_exclude:
                # Skip common infrastructure IPs
                if any(ip_str.endswith(suffix) for suffix in smart_exclusions):
                    if ip_str.endswith('.1') or ip_str.endswith('.254'):
                        print(f"{Fore.YELLOW}[!] Skipping likely gateway: {ip}")
                        continue
                    elif ip_str.endswith('.0') or ip_str.endswith('.255'):
                        print(f"{Fore.YELLOW}[!] Skipping network/broadcast: {ip}")
                        continue
            
            if not should_exclude:
                filtered_ips.append(ip)
        
        excluded_count = len(all_ips) - len(filtered_ips)
        if excluded_count > 0:
            print(f"{Fore.CYAN}[+] Filtered out {excluded_count} IPs (gateways, excluded ranges, etc.)")
        
        return filtered_ips

    def ping_sweep(self):
        """Perform ping sweep to discover live hosts"""
        print(f"{Fore.YELLOW}[+] Starting ping sweep on {self.target_network}")
        print(f"{Fore.YELLOW}[+] Using {self.threads} threads with {self.timeout}s timeout")
        
        try:
            network = ipaddress.ip_network(self.target_network, strict=False)
        except ValueError as e:
            print(f"{Fore.RED}[-] Invalid network format: {e}")
            return []
        
        # Filter IP addresses before scanning
        target_ips = self.filter_ip_addresses(network)
        
        if not target_ips:
            print(f"{Fore.RED}[-] No IPs to scan after filtering")
            return []
        
        print(f"{Fore.CYAN}[+] Scanning {len(target_ips)} filtered IP addresses")
        live_hosts = []
        
        def ping_host(ip):
            try:
                # Use ping command (works on both Windows and Linux)
                if sys.platform.startswith('win'):
                    result = subprocess.run(['ping', '-n', '1', '-w', str(self.timeout * 1000), str(ip)], 
                                          capture_output=True, text=True, timeout=self.timeout + 1)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', str(self.timeout), str(ip)], 
                                          capture_output=True, text=True, timeout=self.timeout + 1)
                
                if result.returncode == 0:
                    return str(ip)
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                pass
            return None
        
        # Progress bar for ping sweep
        with tqdm(total=len(target_ips), desc="Host Discovery", unit="hosts", 
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] Live: {postfix}") as pbar:
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(ping_host, ip): ip for ip in target_ips}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        live_hosts.append(result)
                        print(f"{Fore.GREEN}[+] Host {result} is alive")
                        pbar.set_postfix_str(f"{len(live_hosts)}")
                    pbar.update(1)
        
        self.discovered_hosts = sorted(live_hosts, key=lambda x: ipaddress.ip_address(x))
        self.total_hosts_found = len(self.discovered_hosts)
        print(f"{Fore.GREEN}[+] Discovered {len(self.discovered_hosts)} live hosts")
        return self.discovered_hosts
    
    def port_scan(self, host, ports=None):
        """Scan common ports on a host"""
        if ports is None:
            # Common ports to scan
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    return port
            except Exception:
                pass
            return None
        
        print(f"{Fore.BLUE}[+] Scanning ports on {host}")
        
        # Progress bar for port scanning
        with tqdm(total=len(ports), desc=f"Port Scan ({host})", unit="ports", 
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] Open: {postfix}",
                  leave=False) as pbar:
            
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(scan_port, port): port for port in ports}
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)
                        pbar.set_postfix_str(f"{len(open_ports)}")
                    pbar.update(1)
        
        self.total_ports_found += len(open_ports)
        return sorted(open_ports)
    
    def service_detection(self, host, port):
        """Attempt to detect service running on port with vulnerability information"""
        service_info = ""
        vulnerability_info = ""
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((host, port))
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                if 'Server:' in response:
                    server = response.split('Server:')[1].split('\r\n')[0].strip()
                    sock.close()
                    service_info = f"HTTP - {server}"
                else:
                    service_info = "HTTP"
            else:
                # Send basic probe for other services
                sock.send(b"\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                # Basic service fingerprinting
                if 'SSH' in response:
                    service_info = f"SSH - {response.strip()}"
                elif 'FTP' in response:
                    service_info = f"FTP - {response.strip()}"
                elif 'SMTP' in response:
                    service_info = f"SMTP - {response.strip()}"
                elif port == 3389:
                    service_info = "RDP - Remote Desktop Protocol"
                elif port == 3306:
                    service_info = "MySQL Database"
                elif port == 5432:
                    service_info = "PostgreSQL Database"
        except:
            pass
        
        # Get vulnerability information from database
        if port in self.vulnerability_db:
            vuln_data = self.vulnerability_db[port]
            if not service_info:
                service_info = vuln_data["service"]
            
            # Format vulnerability information
            primary_attacks = vuln_data["attack_vectors"][:2]  # Show top 2 attack vectors
            vulnerability_info = f" -> Possible attacks: {', '.join(primary_attacks)}"
            
            # Add critical vulnerabilities for high-risk services
            if port in [445, 3389, 135]:  # SMB, RDP, RPC
                critical_vulns = [v for v in vuln_data["vulnerabilities"] if any(keyword in v.lower() 
                                for keyword in ['eternalblue', 'bluekeep', 'buffer overflow'])]
                if critical_vulns:
                    vulnerability_info += f" | Critical: {critical_vulns[0]}"
        
        # Fallback to common port mappings if no service detected
        if not service_info:
            common_services = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
                443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
                1433: "MSSQL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
                5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt"
            }
            service_info = common_services.get(port, f"Unknown service on port {port}")
        
        return service_info + vulnerability_info
    
    def get_mac_address(self, ip):
        """Attempt to get MAC address from ARP table"""
        try:
            if sys.platform.startswith('win'):
                # Windows ARP command
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line and 'dynamic' in line.lower():
                            parts = line.split()
                            for part in parts:
                                if '-' in part and len(part) == 17:  # MAC format xx-xx-xx-xx-xx-xx
                                    return part.replace('-', ':').upper()
            else:
                # Linux/Unix ARP command
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                mac = parts[2]
                                if ':' in mac and len(mac) == 17:  # MAC format xx:xx:xx:xx:xx:xx
                                    return mac.upper()
        except Exception:
            pass
        return "Unknown"
    
    def detect_device_type(self, ip, open_ports, services, hostname):
        """Detect device type based on open ports, services, and hostname"""
        device_indicators = {
            'router': {
                'ports': [80, 443, 23, 22, 161],
                'services': ['http', 'https', 'telnet', 'ssh', 'snmp'],
                'hostnames': ['router', 'gateway', 'gw', 'rt', 'cisco', 'netgear', 'linksys', 'asus']
            },
            'printer': {
                'ports': [631, 9100, 515, 80, 443],
                'services': ['ipp', 'jetdirect', 'lpd', 'http'],
                'hostnames': ['printer', 'print', 'hp', 'canon', 'epson', 'brother', 'lexmark']
            },
            'mobile': {
                'ports': [62078, 5353, 1024, 49152],
                'services': ['airplay', 'mdns', 'bonjour'],
                'hostnames': ['iphone', 'android', 'mobile', 'phone', 'tablet', 'ipad']
            },
            'smart_tv': {
                'ports': [8008, 8009, 7001, 80, 443, 1900],
                'services': ['chromecast', 'upnp', 'dlna', 'http'],
                'hostnames': ['tv', 'samsung', 'lg', 'sony', 'chromecast', 'roku', 'appletv']
            },
            'iot_device': {
                'ports': [80, 443, 1883, 8883, 5683],
                'services': ['http', 'https', 'mqtt', 'coap'],
                'hostnames': ['iot', 'sensor', 'camera', 'doorbell', 'thermostat', 'alexa', 'nest']
            },
            'nas_storage': {
                'ports': [80, 443, 22, 21, 139, 445, 548, 2049],
                'services': ['http', 'https', 'ssh', 'ftp', 'smb', 'afp', 'nfs'],
                'hostnames': ['nas', 'storage', 'synology', 'qnap', 'drobo', 'freenas']
            },
            'gaming_console': {
                'ports': [80, 443, 9293, 1935],
                'services': ['http', 'https', 'xbox', 'playstation'],
                'hostnames': ['xbox', 'playstation', 'ps4', 'ps5', 'nintendo', 'switch']
            }
        }
        
        scores = {}
        hostname_lower = hostname.lower() if hostname != 'Unknown' else ''
        
        for device_type, indicators in device_indicators.items():
            score = 0
            
            # Check hostname indicators
            for keyword in indicators['hostnames']:
                if keyword in hostname_lower:
                    score += 3
            
            # Check port indicators
            matching_ports = set(open_ports) & set(indicators['ports'])
            score += len(matching_ports) * 2
            
            # Check service indicators
            for service in services.values():
                service_lower = service.lower()
                for indicator in indicators['services']:
                    if indicator in service_lower:
                        score += 2
            
            if score > 0:
                scores[device_type] = score
        
        if scores:
            # Return the device type with highest score
            best_match = max(scores, key=scores.get)
            confidence = min(scores[best_match] * 10, 95)  # Cap at 95%
            return f"{best_match.replace('_', ' ').title()} ({confidence}%)"
        
        # Fallback based on common patterns
        if 22 in open_ports and 80 in open_ports:
            return "Server/Computer (60%)"
        elif 3389 in open_ports:
            return "Windows Computer (70%)"
        elif 22 in open_ports:
            return "Linux/Unix System (65%)"
        elif 135 in open_ports or 139 in open_ports or 445 in open_ports:
            return "Windows System (60%)"
        else:
            return "Unknown Device"

    def get_hostname(self, ip):
        """Attempt to resolve hostname"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def comprehensive_scan(self):
        """Perform comprehensive network scan"""
        print(f"\n{Fore.MAGENTA}[+] Starting comprehensive network scan...")
        self.scan_start_time = time.time()
        
        # Overall progress bar for comprehensive scan
        with tqdm(total=len(self.discovered_hosts), desc="Comprehensive Scan", unit="hosts",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] Ports: {postfix}") as main_pbar:
            
            for host in self.discovered_hosts:
                print(f"\n{Fore.CYAN}[+] Scanning {host}")
                
                # Get hostname
                hostname = self.get_hostname(host)
                
                # Get MAC address
                print(f"{Fore.YELLOW}[+] Getting MAC address...")
                mac_address = self.get_mac_address(host)
                
                # Port scan
                open_ports = self.port_scan(host)
                
                # Service detection
                services = {}
                if open_ports:
                    with tqdm(open_ports, desc=f"Service Detection ({host})", unit="services", leave=False) as service_pbar:
                        for port in open_ports:
                            service = self.service_detection(host, port)
                            services[port] = service
                            print(f"    {Fore.WHITE}Port {port}: {Fore.YELLOW}{service}")
                            service_pbar.update(1)
                
                # Device type detection
                device_type = self.detect_device_type(host, open_ports, services, hostname)
                print(f"    {Fore.MAGENTA}Device Type: {Fore.CYAN}{device_type}")
                print(f"    {Fore.MAGENTA}MAC Address: {Fore.GREEN}{mac_address}")
                
                # Store results
                self.scan_results[host] = {
                    'hostname': hostname,
                    'mac_address': mac_address,
                    'device_type': device_type,
                    'open_ports': open_ports,
                    'services': services,
                    'scan_time': datetime.now().isoformat()
                }
                
                # Write result immediately if incremental mode is enabled
                self.write_host_result(host, self.scan_results[host])
                
                # Update main progress bar
                main_pbar.set_postfix_str(f"{self.total_ports_found}")
                main_pbar.update(1)
        
        # Print final statistics
        elapsed_time = time.time() - self.scan_start_time
        print(f"\n{Fore.GREEN}[+] Scan completed in {elapsed_time:.2f} seconds")
        print(f"{Fore.GREEN}[+] Total hosts scanned: {len(self.discovered_hosts)}")
        print(f"{Fore.GREEN}[+] Total open ports found: {self.total_ports_found}")
        if elapsed_time > 0:
            hosts_per_sec = len(self.discovered_hosts) / elapsed_time
            print(f"{Fore.GREEN}[+] Average scan rate: {hosts_per_sec:.2f} hosts/second")
    
    def nmap_scan(self, host):
        """Use nmap for advanced scanning if available"""
        try:
            # Check if nmap is available
            subprocess.run(['nmap', '--version'], capture_output=True, check=True)
            
            print(f"[+] Running nmap scan on {host}")
            result = subprocess.run(['nmap', '-sV', '-O', '--top-ports', '1000', host], 
                                  capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return result.stdout
            else:
                return None
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return None
    
    def export_results(self, format_type='json', filename=None):
        """Export scan results to file (only hosts with open ports)"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}"
        
        # Filter out hosts with no open ports
        filtered_results = {ip: data for ip, data in self.scan_results.items() if data['open_ports']}
        
        if format_type.lower() == 'json':
            filename += '.json'
            with open(filename, 'w') as f:
                json.dump({
                    'scan_info': {
                        'target_network': self.target_network,
                        'scan_time': datetime.now().isoformat(),
                        'total_hosts': len(self.discovered_hosts),
                        'hosts_with_open_ports': len(filtered_results)
                    },
                    'results': filtered_results
                }, f, indent=2)
            print(f"{Fore.GREEN}[+] Results exported to {filename} ({len(filtered_results)} hosts with open ports)")
            
        elif format_type.lower() == 'csv':
            filename += '.csv'
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Hostname', 'MAC Address', 'Device Type', 'Open Ports', 'Services'])
                
                for ip, data in filtered_results.items():
                    ports = ','.join(map(str, data['open_ports']))
                    services = '; '.join([f"{port}:{service}" for port, service in data['services'].items()])
                    mac_address = data.get('mac_address', 'Unknown')
                    device_type = data.get('device_type', 'Unknown Device')
                    writer.writerow([ip, data['hostname'], mac_address, device_type, ports, services])
            print(f"{Fore.GREEN}[+] Results exported to {filename} ({len(filtered_results)} hosts with open ports)")
    
    def print_summary(self):
        """Print scan summary with statistics"""
        if not self.scan_results:
            print(f"{Fore.RED}[-] No scan results to display")
            return
        
        # Calculate scan statistics
        total_hosts = len(self.scan_results)
        total_open_ports = sum(len(result['open_ports']) for result in self.scan_results.values())
        unique_services = set()
        device_types = {}
        
        for result in self.scan_results.values():
            for service in result['services'].values():
                if service != 'unknown':
                    unique_services.add(service)
            
            device_type = result['device_type']
            device_types[device_type] = device_types.get(device_type, 0) + 1
        
        # Print summary header
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}                    SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Print statistics with live counters
        print(f"{Fore.GREEN}[+] Total Hosts Discovered: {Fore.YELLOW}{self.total_hosts_found}")
        print(f"{Fore.GREEN}[+] Total Hosts Scanned: {Fore.YELLOW}{total_hosts}")
        print(f"{Fore.GREEN}[+] Total Open Ports Found: {Fore.YELLOW}{self.total_ports_found}")
        print(f"{Fore.GREEN}[+] Unique Services Identified: {Fore.YELLOW}{len(unique_services)}")
        
        # Print scan timing statistics
        if hasattr(self, 'scan_start_time') and self.scan_start_time:
            elapsed_time = time.time() - self.scan_start_time
            print(f"{Fore.GREEN}[+] Total Scan Time: {Fore.YELLOW}{elapsed_time:.2f} seconds")
            if elapsed_time > 0:
                hosts_per_sec = total_hosts / elapsed_time
                ports_per_sec = self.total_ports_found / elapsed_time
                print(f"{Fore.GREEN}[+] Average Scan Rate: {Fore.YELLOW}{hosts_per_sec:.2f} hosts/sec, {ports_per_sec:.2f} ports/sec")
        
        # Print device type distribution
        if device_types:
            print(f"\n{Fore.CYAN}[+] Device Type Distribution:")
            for device_type, count in sorted(device_types.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_hosts) * 100
                print(f"    {Fore.WHITE}{device_type}: {Fore.YELLOW}{count} ({percentage:.1f}%)")
        
        # Print top services
        if unique_services:
            print(f"\n{Fore.CYAN}[+] Services Discovered: {Fore.YELLOW}{', '.join(sorted(unique_services))}")
        
        print(f"{Fore.CYAN}{'='*60}")
        
        # Print detailed results
        for host, result in self.scan_results.items():
            print(f"\n{Fore.CYAN}[+] Host: {Fore.WHITE}{host}")
            print(f"    {Fore.MAGENTA}Hostname: {Fore.GREEN}{result['hostname']}")
            print(f"    {Fore.MAGENTA}MAC Address: {Fore.GREEN}{result['mac_address']}")
            print(f"    {Fore.MAGENTA}Device Type: {Fore.CYAN}{result['device_type']}")
            
            if result['open_ports']:
                print(f"    {Fore.MAGENTA}Open Ports ({len(result['open_ports'])}): {Fore.YELLOW}{', '.join(map(str, result['open_ports']))}")
                for port, service in result['services'].items():
                    print(f"        {Fore.WHITE}Port {port}: {Fore.YELLOW}{service}")
            else:
                print(f"    {Fore.RED}No open ports found")

def main():
    parser = argparse.ArgumentParser(description='Advanced Network Mapping Tool')
    parser.add_argument('network', help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('-t', '--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=3, help='Timeout in seconds (default: 3)')
    parser.add_argument('-o', '--output', help='Output filename (without extension)')
    parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json', help='Output format')
    parser.add_argument('--ping-only', action='store_true', help='Only perform ping sweep')
    parser.add_argument('--nmap', action='store_true', help='Use nmap for advanced scanning')
    parser.add_argument('--exclude', action='append', help='Exclude IP ranges (can be used multiple times)')
    parser.add_argument('--no-smart-filter', action='store_true', help='Disable smart filtering of common infrastructure IPs')
    
    args = parser.parse_args()
    
    # Create network mapper instance
    mapper = NetworkMapper(
        args.network, 
        args.threads, 
        args.timeout,
        exclude_ranges=args.exclude,
        smart_filter=not args.no_smart_filter
    )
    
    # Setup incremental export if output is specified
    if args.output:
        mapper.setup_incremental_export(args.format, args.output)
    
    mapper.print_banner()
    
    try:
        # Discover hosts
        hosts = mapper.ping_sweep()
        
        if not hosts:
            print("[-] No live hosts discovered")
            return
        
        if not args.ping_only:
            # Comprehensive scan
            mapper.comprehensive_scan()
            
            # Nmap scan if requested and available
            if args.nmap:
                print("\n[+] Running advanced nmap scans...")
                for host in hosts[:5]:  # Limit to first 5 hosts for demo
                    nmap_result = mapper.nmap_scan(host)
                    if nmap_result:
                        print(f"\nNmap results for {host}:")
                        print(nmap_result)
        
        # Print summary
        mapper.print_summary()
        
        # Export results (only if not using incremental mode)
        if (args.output or not args.ping_only) and not mapper.incremental_mode:
            mapper.export_results(args.format, args.output)
            
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        mapper.finalize_output_file()
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        mapper.finalize_output_file()

if __name__ == "__main__":
    main()