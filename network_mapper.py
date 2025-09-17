#!/usr/bin/env python3
"""
Network Mapper - Advanced Network Discovery and Mapping Tool
Author: Gustavo Valente
Description: Comprehensive network mapping tool for penetration testing and network analysis
"""

import subprocess
import socket
import threading
import ipaddress
import json
import csv
import argparse
import sys
import time
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

class NetworkMapper:
    def __init__(self, target_network, threads=50, timeout=3, exclude_ranges=None, smart_filter=True):
        self.target_network = target_network
        self.threads = threads
        self.timeout = timeout
        self.discovered_hosts = []
        self.scan_results = {}
        self.exclude_ranges = exclude_ranges or []
        self.smart_filter = smart_filter
        
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║{Style.BRIGHT}                    NETWORK MAPPER v1.0                       {Style.RESET_ALL}{Fore.CYAN}║
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
                    print(f"{Fore.GREEN}[+] Host {ip} is alive")
                    return str(ip)
            except subprocess.TimeoutExpired:
                pass
            except Exception as e:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in target_ips}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    live_hosts.append(result)
        
        self.discovered_hosts = sorted(live_hosts, key=lambda x: ipaddress.ip_address(x))
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
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports)
    
    def service_detection(self, host, port):
        """Attempt to detect service running on port"""
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
                    return f"HTTP - {server}"
            
            # Send basic probe for other services
            sock.send(b"\r\n")
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # Basic service fingerprinting
            if 'SSH' in response:
                return f"SSH - {response.strip()}"
            elif 'FTP' in response:
                return f"FTP - {response.strip()}"
            elif 'SMTP' in response:
                return f"SMTP - {response.strip()}"
            elif port == 3389:
                return "RDP - Remote Desktop Protocol"
            elif port == 3306:
                return "MySQL Database"
            elif port == 5432:
                return "PostgreSQL Database"
            else:
                return f"Unknown service on port {port}"
                
        except Exception:
            # Fallback to common port mappings
            common_services = {
                21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
                80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
                443: "HTTPS", 993: "IMAPS", 995: "POP3S", 1723: "PPTP", 
                3389: "RDP", 5900: "VNC"
            }
            return common_services.get(port, f"Unknown service on port {port}")
    
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
            for port in open_ports:
                service = self.service_detection(host, port)
                services[port] = service
                print(f"    {Fore.WHITE}Port {port}: {Fore.YELLOW}{service}")
            
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
        """Print scan summary"""
        print("\n" + "="*60)
        print("NETWORK SCAN SUMMARY")
        print("="*60)
        print(f"Target Network: {self.target_network}")
        print(f"Total Hosts Discovered: {len(self.discovered_hosts)}")
        print(f"Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.scan_results:
            print("\nDISCOVERED HOSTS:")
            print("-" * 60)
            for ip, data in self.scan_results.items():
                print(f"Host: {ip} ({data['hostname']})")
                
                # Display MAC address and device type if available
                mac_address = data.get('mac_address', 'Unknown')
                device_type = data.get('device_type', 'Unknown Device')
                print(f"  MAC Address: {mac_address}")
                print(f"  Device Type: {device_type}")
                
                if data['open_ports']:
                    print(f"  Open Ports: {', '.join(map(str, data['open_ports']))}")
                    for port, service in data['services'].items():
                        print(f"    {port}: {service}")
                else:
                    print("  No open ports detected")
                print()

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
        
        # Export results
        if args.output or not args.ping_only:
            mapper.export_results(args.format, args.output)
            
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
    except Exception as e:
        print(f"[-] Error during scan: {e}")

if __name__ == "__main__":
    main()