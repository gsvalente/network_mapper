"""
Network Utilities Module

This module handles core network operations including host discovery,
port scanning, service detection, and MAC address resolution.
"""

import socket
import subprocess
import sys
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from colorama import Fore
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    class tqdm:
        def __init__(self, iterable=None, total=None, desc=None, unit=None, **kwargs):
            self.iterable = iterable
            self.total = total
            self.desc = desc
            self.n = 0
            
        def __iter__(self):
            if self.iterable:
                for item in self.iterable:
                    yield item
                    self.update(1)
            
        def __enter__(self):
            return self
            
        def __exit__(self, *args):
            pass
            
        def update(self, n=1):
            self.n += n
            
        def set_postfix_str(self, s):
            pass
            
        def set_description(self, desc):
            self.desc = desc


class NetworkUtils:
    """
    Core network utilities for scanning and discovery
    """
    
    def __init__(self, threads=50, timeout=3):
        self.threads = threads
        self.timeout = timeout
        self.total_hosts_found = 0
        self.total_ports_found = 0
    
    def filter_ip_addresses(self, network, exclude_ranges=None, smart_filter=True):
        """
        Filter IP addresses to exclude common infrastructure IPs
        
        Args:
            network: IP network object
            exclude_ranges: List of IP ranges to exclude
            smart_filter: Whether to apply smart filtering
            
        Returns:
            list: Filtered list of IP addresses
        """
        all_ips = list(network.hosts())
        
        if not smart_filter and not exclude_ranges:
            return all_ips
        
        filtered_ips = []
        
        # Smart filtering patterns
        smart_exclusions = {
            'network_address': lambda ip: ip == network.network_address,
            'broadcast_address': lambda ip: ip == network.broadcast_address,
            'router_ips': lambda ip: str(ip).endswith(('.1', '.254')),
            'dhcp_range_start': lambda ip: str(ip).endswith('.100'),
            'common_infrastructure': lambda ip: any(str(ip).endswith(suffix) 
                                                   for suffix in ['.0', '.255'])
        }
        
        for ip in all_ips:
            exclude_ip = False
            
            # Apply smart filtering
            if smart_filter:
                for filter_name, filter_func in smart_exclusions.items():
                    if filter_func(ip):
                        exclude_ip = True
                        break
            
            # Apply custom exclusions
            if exclude_ranges and not exclude_ip:
                for exclude_range in exclude_ranges:
                    try:
                        exclude_network = ipaddress.ip_network(exclude_range, strict=False)
                        if ip in exclude_network:
                            exclude_ip = True
                            break
                    except ValueError:
                        continue
            
            if not exclude_ip:
                filtered_ips.append(ip)
        
        return filtered_ips
    
    def ping_sweep(self, target_network, exclude_ranges=None, smart_filter=True):
        """
        Perform ping sweep to discover live hosts
        
        Args:
            target_network (str): Target network in CIDR notation
            exclude_ranges (list): List of IP ranges to exclude
            smart_filter (bool): Whether to apply smart filtering
            
        Returns:
            list: List of live host IP addresses
        """
        print(f"{Fore.YELLOW}[+] Starting ping sweep on {target_network}")
        print(f"{Fore.YELLOW}[+] Using {self.threads} threads with {self.timeout}s timeout")
        
        try:
            network = ipaddress.ip_network(target_network, strict=False)
        except ValueError as e:
            print(f"{Fore.RED}[-] Invalid network format: {e}")
            return []
        
        # Filter IP addresses before scanning
        target_ips = self.filter_ip_addresses(network, exclude_ranges, smart_filter)
        
        if not target_ips:
            print(f"{Fore.RED}[-] No IPs to scan after filtering")
            return []
        
        print(f"{Fore.CYAN}[+] Scanning {len(target_ips)} filtered IP addresses")
        live_hosts = []
        
        def ping_host(ip):
            """Ping a single host"""
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
            except Exception:
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
        
        discovered_hosts = sorted(live_hosts, key=lambda x: ipaddress.ip_address(x))
        self.total_hosts_found = len(discovered_hosts)
        print(f"{Fore.GREEN}[+] Discovered {len(discovered_hosts)} live hosts")
        return discovered_hosts
    
    def port_scan(self, host, ports=None):
        """
        Scan ports on a specific host
        
        Args:
            host (str): Target host IP address
            ports (list): List of ports to scan (default: common ports)
            
        Returns:
            list: List of open ports
        """
        if ports is None:
            # Common ports to scan
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 
                    1723, 3306, 3389, 5432, 5900, 8080, 8443, 9100, 631, 1433, 6379]
        
        open_ports = []
        
        def scan_port(port):
            """Scan a single port"""
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
    
    def service_detection(self, host, port, vulnerability_db=None):
        """
        Detect service running on a specific port
        
        Args:
            host (str): Target host IP address
            port (int): Target port number
            vulnerability_db (dict): Vulnerability database for additional info
            
        Returns:
            str: Service information with vulnerability details
        """
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
        if vulnerability_db and port in vulnerability_db:
            vuln_data = vulnerability_db[port]
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
            service_info = self._get_common_service(port)
        
        return service_info + vulnerability_info
    
    def _get_common_service(self, port):
        """
        Get common service name for a port
        
        Args:
            port (int): Port number
            
        Returns:
            str: Service name
        """
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1723: "PPTP", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 9100: "JetDirect", 631: "IPP", 1521: "Oracle",
            27017: "MongoDB", 5984: "CouchDB", 9200: "Elasticsearch"
        }
        return common_services.get(port, f"Unknown service on port {port}")
    
    def get_mac_address(self, ip):
        """
        Attempt to get MAC address from ARP table
        
        Args:
            ip (str): Target IP address
            
        Returns:
            str: MAC address or "Unknown"
        """
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
    
    def get_hostname(self, ip):
        """
        Attempt to resolve hostname for an IP address
        
        Args:
            ip (str): Target IP address
            
        Returns:
            str: Hostname or "Unknown"
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def nmap_scan(self, host):
        """
        Use nmap for advanced scanning if available
        
        Args:
            host (str): Target host IP address
            
        Returns:
            str: Nmap output or None if not available
        """
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
    
    def comprehensive_port_scan(self, host, port_range=None):
        """
        Perform comprehensive port scan with extended port range
        
        Args:
            host (str): Target host IP address
            port_range (tuple): Port range as (start, end) tuple
            
        Returns:
            list: List of open ports
        """
        if port_range is None:
            # Scan top 1000 ports
            ports = self._get_top_ports(1000)
        else:
            start_port, end_port = port_range
            ports = list(range(start_port, end_port + 1))
        
        return self.port_scan(host, ports)
    
    def _get_top_ports(self, count=1000):
        """
        Get list of top ports to scan
        
        Args:
            count (int): Number of top ports to return
            
        Returns:
            list: List of port numbers
        """
        # Top 100 most common ports
        top_ports = [
            80, 23, 443, 21, 22, 25, 53, 110, 111, 995, 993, 143, 993, 995, 587, 465,
            135, 139, 445, 1433, 3306, 5432, 1521, 3389, 5900, 6379, 27017, 5984,
            8080, 8443, 8000, 8888, 9200, 9300, 11211, 6667, 6697, 1723, 1701,
            500, 4500, 1194, 1723, 47, 500, 4500, 1701, 1194, 1723, 47, 500,
            631, 9100, 515, 2000, 8009, 7001, 9999, 8001, 8008, 8080, 8443,
            3000, 3001, 5000, 5001, 8000, 8001, 9000, 9001, 10000, 10001,
            20, 69, 161, 162, 389, 636, 3268, 3269, 88, 464, 749, 750, 751,
            1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034,
            1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045
        ]
        
        # Extend with additional common ports if needed
        if count > len(top_ports):
            additional_ports = list(range(1, 1025)) + list(range(8000, 8100))
            all_ports = list(set(top_ports + additional_ports))
            return sorted(all_ports)[:count]
        
        return top_ports[:count]
    
    def get_counters(self):
        """
        Get current counter values
        
        Returns:
            tuple: (total_hosts_found, total_ports_found)
        """
        return self.total_hosts_found, self.total_ports_found
    
    def reset_counters(self):
        """Reset counter values"""
        self.total_hosts_found = 0
        self.total_ports_found = 0
    
    def set_timeout(self, timeout):
        """Set timeout for network operations"""
        self.timeout = timeout
    
    def set_threads(self, threads):
        """Set number of threads for concurrent operations"""
        self.threads = threads