#!/usr/bin/env python3
"""
Advanced Network Mapping and Vulnerability Assessment Tool - Refactored Version

This is the refactored version of the network mapper that uses a modular architecture
for better maintainability, testing, and code organization.

Author: Gustavo Valente
Version: 2.0 (Refactored)
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

# Import our custom modules
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.device_detector import DeviceDetector
from modules.network_utils import NetworkUtils
from modules.report_generator import ReportGenerator

# Optional dependencies with fallbacks
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Auto-reset colors after each print
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

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


class NetworkMapper:
    """
    Main NetworkMapper class - refactored to use modular components
    
    This class orchestrates the various modules to perform comprehensive
    network mapping and vulnerability assessment.
    """
    
    def __init__(self, target_network, threads=50, timeout=3, exclude_ranges=None, smart_filter=True):
        """
        Initialize NetworkMapper with modular components
        
        Args:
            target_network (str): Target network in CIDR notation
            threads (int): Number of threads for concurrent operations
            timeout (int): Timeout for network operations
            exclude_ranges (list): IP ranges to exclude from scanning
            smart_filter (bool): Enable smart filtering of infrastructure IPs
        """
        self.target_network = target_network
        self.threads = threads
        self.timeout = timeout
        self.exclude_ranges = exclude_ranges or []
        self.smart_filter = smart_filter
        
        # Initialize modular components
        self.vulnerability_scanner = VulnerabilityScanner()
        self.device_detector = DeviceDetector()
        self.network_utils = NetworkUtils(threads=threads, timeout=timeout)
        self.report_generator = ReportGenerator()
        
        # Scan state
        self.discovered_hosts = []
        self.scan_results = {}
        self.scan_start_time = None
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        atexit.register(self.cleanup_on_exit)
    
    def signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        print(f"\n{Fore.YELLOW}[!] Received signal {signum}, cleaning up...")
        self.cleanup_on_exit()
        sys.exit(0)
    
    def cleanup_on_exit(self):
        """Cleanup operations on exit"""
        if hasattr(self.report_generator, 'incremental_mode') and self.report_generator.incremental_mode:
            self.report_generator.finalize_output_file()
    
    def setup_incremental_export(self, format_type='json', filename=None):
        """Setup incremental export mode"""
        self.report_generator.setup_incremental_export(format_type, filename)
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                    Advanced Network Mapping Tool v2.0                       ║
║                        Vulnerability Assessment Edition                      ║
╚══════════════════════════════════════════════════════════════════════════════╝{Fore.RESET}

{Fore.GREEN}[+] Target Network: {Fore.YELLOW}{self.target_network}
{Fore.GREEN}[+] Threads: {Fore.YELLOW}{self.threads}
{Fore.GREEN}[+] Timeout: {Fore.YELLOW}{self.timeout}s
{Fore.GREEN}[+] Smart Filtering: {Fore.YELLOW}{'Enabled' if self.smart_filter else 'Disabled'}
{Fore.GREEN}[+] Exclude Ranges: {Fore.YELLOW}{', '.join(self.exclude_ranges) if self.exclude_ranges else 'None'}
"""
        print(banner)
    
    def ping_sweep(self):
        """Perform ping sweep to discover live hosts"""
        self.discovered_hosts = self.network_utils.ping_sweep(
            self.target_network, 
            self.exclude_ranges, 
            self.smart_filter
        )
        return self.discovered_hosts
    
    def comprehensive_scan(self):
        """Perform comprehensive network scan with vulnerability assessment"""
        print(f"\n{Fore.MAGENTA}[+] Starting comprehensive network scan with vulnerability assessment...")
        self.scan_start_time = time.time()
        self.report_generator.set_scan_timing(self.scan_start_time)
        
        # Overall progress bar for comprehensive scan
        with tqdm(total=len(self.discovered_hosts), desc="Comprehensive Scan", unit="hosts",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] Ports: {postfix}") as main_pbar:
            
            for host in self.discovered_hosts:
                print(f"\n{Fore.CYAN}[+] Scanning {host}")
                
                # Get hostname
                hostname = self.network_utils.get_hostname(host)
                
                # Get MAC address
                print(f"{Fore.YELLOW}[+] Getting MAC address...")
                mac_address = self.network_utils.get_mac_address(host)
                
                # Port scan
                open_ports = self.network_utils.port_scan(host)
                
                # Service detection with vulnerability database
                services = {}
                if open_ports:
                    vuln_db = self.vulnerability_scanner.get_vulnerability_database()
                    with tqdm(open_ports, desc=f"Service Detection ({host})", unit="services", leave=False) as service_pbar:
                        for port in open_ports:
                            service = self.network_utils.service_detection(host, port, vuln_db)
                            services[port] = service
                            print(f"    {Fore.WHITE}Port {port}: {Fore.YELLOW}{service}")
                            service_pbar.update(1)
                
                # Device type detection
                device_type = self.device_detector.detect_device_type(host, open_ports, services, hostname)
                print(f"    {Fore.MAGENTA}Device Type: {Fore.CYAN}{device_type}")
                print(f"    {Fore.MAGENTA}MAC Address: {Fore.GREEN}{mac_address}")
                
                # Vulnerability assessment
                vulnerability_assessment = self.vulnerability_scanner.assess_vulnerabilities(host, open_ports, services)
                if vulnerability_assessment['vulnerabilities']:
                    risk_level = vulnerability_assessment['risk_level']
                    risk_color = self._get_risk_color(risk_level)
                    print(f"    {Fore.MAGENTA}Risk Level: {risk_color}{risk_level}")
                    print(f"    {Fore.MAGENTA}Vulnerabilities: {Fore.YELLOW}{vulnerability_assessment['summary']}")
                
                # Store results
                self.scan_results[host] = {
                    'hostname': hostname,
                    'mac_address': mac_address,
                    'device_type': device_type,
                    'open_ports': open_ports,
                    'services': services,
                    'scan_time': datetime.now().isoformat(),
                    'vulnerabilities': vulnerability_assessment
                }
                
                # Write result immediately if incremental mode is enabled
                self.report_generator.write_host_result(host, self.scan_results[host], vulnerability_assessment)
                
                # Update main progress bar
                total_hosts, total_ports = self.network_utils.get_counters()
                main_pbar.set_postfix_str(f"{total_ports}")
                main_pbar.update(1)
        
        # Print final statistics
        elapsed_time = time.time() - self.scan_start_time
        total_hosts, total_ports = self.network_utils.get_counters()
        print(f"\n{Fore.GREEN}[+] Scan completed in {elapsed_time:.2f} seconds")
        print(f"{Fore.GREEN}[+] Total hosts scanned: {len(self.discovered_hosts)}")
        print(f"{Fore.GREEN}[+] Total open ports found: {total_ports}")
        if elapsed_time > 0:
            hosts_per_sec = len(self.discovered_hosts) / elapsed_time
            print(f"{Fore.GREEN}[+] Average scan rate: {hosts_per_sec:.2f} hosts/second")
    
    def _get_risk_color(self, risk_level):
        """Get color for risk level display"""
        risk_colors = {
            'Critical': Fore.RED,
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.GREEN,
            'Info': Fore.CYAN
        }
        return risk_colors.get(risk_level, Fore.WHITE)
    
    def nmap_scan(self, host):
        """Use nmap for advanced scanning if available"""
        return self.network_utils.nmap_scan(host)
    
    def export_results(self, format_type='json', filename=None):
        """Export scan results to file"""
        # Extract vulnerability assessments for export
        vulnerability_assessments = {}
        for ip, data in self.scan_results.items():
            if 'vulnerabilities' in data:
                vulnerability_assessments[ip] = data['vulnerabilities']
        
        # Set counter values for statistics
        total_hosts, total_ports = self.network_utils.get_counters()
        self.report_generator.set_counters(total_hosts, total_ports)
        
        self.report_generator.export_results(
            self.scan_results, 
            self.target_network, 
            format_type, 
            filename, 
            vulnerability_assessments
        )
    
    def generate_vulnerability_report(self, filename=None):
        """Generate focused vulnerability assessment report"""
        vulnerability_assessments = {}
        for ip, data in self.scan_results.items():
            if 'vulnerabilities' in data:
                vulnerability_assessments[ip] = data['vulnerabilities']
        
        return self.report_generator.generate_vulnerability_report(
            self.scan_results, 
            vulnerability_assessments, 
            filename
        )
    
    def print_summary(self):
        """Print scan summary with statistics"""
        # Set counter values for statistics
        total_hosts, total_ports = self.network_utils.get_counters()
        self.report_generator.set_counters(total_hosts, total_ports)
        
        self.report_generator.print_summary(self.scan_results, self.discovered_hosts)
    
    def finalize_output_file(self):
        """Finalize output file with summary statistics"""
        self.report_generator.finalize_output_file()
    
    def get_scan_statistics(self):
        """Get current scan statistics"""
        total_hosts, total_ports = self.network_utils.get_counters()
        return {
            'total_hosts_discovered': len(self.discovered_hosts),
            'total_hosts_scanned': len(self.scan_results),
            'total_open_ports': total_ports,
            'scan_duration': time.time() - self.scan_start_time if self.scan_start_time else 0
        }
    
    def get_vulnerability_summary(self):
        """Get vulnerability assessment summary"""
        risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        vulnerable_hosts = 0
        
        for result in self.scan_results.values():
            if 'vulnerabilities' in result and result['vulnerabilities']['vulnerabilities']:
                vulnerable_hosts += 1
                risk_level = result['vulnerabilities']['risk_level']
                risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        return {
            'vulnerable_hosts': vulnerable_hosts,
            'risk_distribution': risk_counts,
            'total_assessed': len(self.scan_results)
        }


def main():
    """Main function with enhanced argument parsing"""
    parser = argparse.ArgumentParser(
        description='Advanced Network Mapping and Vulnerability Assessment Tool v2.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24                    # Basic scan
  %(prog)s 192.168.1.0/24 -t 100 --timeout 5 # High-speed scan
  %(prog)s 192.168.1.0/24 -o report -f csv   # Export to CSV
  %(prog)s 192.168.1.0/24 --vuln-report      # Generate vulnerability report
        """
    )
    
    parser.add_argument('network', help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('-t', '--threads', type=int, default=50, 
                       help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=3, 
                       help='Timeout in seconds (default: 3)')
    parser.add_argument('-o', '--output', 
                       help='Output filename (without extension)')
    parser.add_argument('-f', '--format', choices=['json', 'csv'], default='json', 
                       help='Output format (default: json)')
    parser.add_argument('--ping-only', action='store_true', 
                       help='Only perform ping sweep')
    parser.add_argument('--nmap', action='store_true', 
                       help='Use nmap for advanced scanning')
    parser.add_argument('--exclude', action='append', 
                       help='Exclude IP ranges (can be used multiple times)')
    parser.add_argument('--no-smart-filter', action='store_true', 
                       help='Disable smart filtering of common infrastructure IPs')
    parser.add_argument('--vuln-report', action='store_true',
                       help='Generate focused vulnerability assessment report')
    parser.add_argument('--incremental', action='store_true',
                       help='Enable incremental export mode')
    
    args = parser.parse_args()
    
    # Create network mapper instance
    mapper = NetworkMapper(
        args.network, 
        args.threads, 
        args.timeout,
        exclude_ranges=args.exclude,
        smart_filter=not args.no_smart_filter
    )
    
    # Setup incremental export if requested
    if args.incremental and args.output:
        mapper.setup_incremental_export(args.format, args.output)
    
    mapper.print_banner()
    
    try:
        # Discover hosts
        hosts = mapper.ping_sweep()
        
        if not hosts:
            print("[-] No live hosts discovered")
            return
        
        if not args.ping_only:
            # Comprehensive scan with vulnerability assessment
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
        
        # Generate vulnerability report if requested
        if args.vuln_report:
            vuln_report_file = mapper.generate_vulnerability_report()
            print(f"\n{Fore.GREEN}[+] Vulnerability report generated: {vuln_report_file}")
        
        # Export results (only if not using incremental mode)
        if args.output and not mapper.report_generator.incremental_mode:
            mapper.export_results(args.format, args.output)
        
        # Print final statistics
        stats = mapper.get_scan_statistics()
        vuln_summary = mapper.get_vulnerability_summary()
        
        print(f"\n{Fore.CYAN}[+] Final Statistics:")
        print(f"    {Fore.GREEN}Hosts Discovered: {stats['total_hosts_discovered']}")
        print(f"    {Fore.GREEN}Hosts Scanned: {stats['total_hosts_scanned']}")
        print(f"    {Fore.GREEN}Open Ports: {stats['total_open_ports']}")
        print(f"    {Fore.GREEN}Vulnerable Hosts: {vuln_summary['vulnerable_hosts']}")
        print(f"    {Fore.GREEN}Scan Duration: {stats['scan_duration']:.2f}s")
            
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user")
        mapper.finalize_output_file()
    except Exception as e:
        print(f"[-] Error during scan: {e}")
        mapper.finalize_output_file()


if __name__ == "__main__":
    main()