#!/usr/bin/env python3
"""
Advanced Network Mapping and Vulnerability Assessment Tool - Refactored Version

This is the refactored version of the network mapper that uses a modular architecture
for better maintainability, testing, and code organization.

Author: Gustavo Valente
Version: 2.0 (Refactored) - DevSecOps Enhanced
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
from pathlib import Path
import xml.etree.ElementTree as ET

# Import our custom modules
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.device_detector import DeviceDetector
from modules.network_utils import NetworkUtils
from modules.report_generator import ReportGenerator

# Import new security modules
from modules.security_logger import SecurityLogger
from modules.input_validator import InputValidator
from modules.secrets_manager import SecretsManager
from modules.rate_limiter import RateLimiter
from modules.compliance_reporter import ComplianceReporter, ComplianceFramework, ComplianceControl, ComplianceStatus, SecurityMetric
from modules.secure_config import SecureConfigManager, SecurityLevel

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
    Main NetworkMapper class - refactored to use modular components with DevSecOps enhancements
    
    This class orchestrates the various modules to perform comprehensive
    network mapping and vulnerability assessment with integrated security controls.
    """
    
    def __init__(self, target_network, threads=50, timeout=3, exclude_ranges=None, smart_filter=True, security_level=SecurityLevel.STANDARD):
        """
        Initialize NetworkMapper with modular components and security enhancements
        
        Args:
            target_network (str): Target network in CIDR notation
            threads (int): Number of threads for concurrent operations
            timeout (int): Timeout for network operations
            exclude_ranges (list): IP ranges to exclude from scanning
            smart_filter (bool): Enable smart filtering of infrastructure IPs
            security_level (SecurityLevel): Security level for configuration
        """
        # Initialize security components first
        self.security_config = SecureConfigManager(security_level=security_level)
        
        # Initialize DevSecOps security components
        from modules.rate_limiter import RateLimitConfig
        
        self.input_validator = InputValidator()
        self.security_logger = SecurityLogger()
        self.secrets_manager = SecretsManager()
        
        # Create rate limiter with proper configuration
        rate_config = RateLimitConfig(
            requests_per_second=self.security_config.config.rate_limit_per_second,
            max_concurrent_scans=self.security_config.config.max_concurrent_scans
        )
        self.rate_limiter = RateLimiter(config=rate_config)
        self.compliance_reporter = ComplianceReporter()
        
        # Check for emergency shutdown
        if self.security_config.is_emergency_shutdown():
            raise RuntimeError("System is in emergency shutdown mode. Clear emergency state before proceeding.")
        
        # Validate and sanitize inputs
        try:
            self.target_network = self.input_validator.validate_network_target(target_network)
            self.threads = min(threads, self.security_config.config.max_concurrent_scans)
            self.timeout = min(timeout, self.security_config.config.scan_timeout)
        except ValueError as e:
            self.security_logger.log_security_event(
                "INPUT_VALIDATION_FAILURE",
                target_network,
                {"error": str(e), "blocked": True}
            )
            raise
        
        self.exclude_ranges = exclude_ranges or []
        self.smart_filter = smart_filter
        
        # Initialize modular components
        self.vulnerability_scanner = VulnerabilityScanner()
        self.device_detector = DeviceDetector()
        self.network_utils = NetworkUtils(threads=self.threads, timeout=self.timeout)
        self.report_generator = ReportGenerator()
        
        # Scan state
        self.discovered_hosts = []
        self.scan_results = {}
        self.scan_start_time = None
        
        # Log security event for scan initialization
        self.security_logger.log_security_event(
            "SCAN_INITIALIZED",
            self.target_network,
            {
                "threads": self.threads,
                "timeout": self.timeout,
                "security_level": security_level.value,
                "smart_filter": self.smart_filter
            }
        )
        
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
║                    Advanced Network Mapping Tool v2.2                       ║
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
        # Extract the sanitized network string from validation result
        network_target = self.target_network.get('sanitized') if isinstance(self.target_network, dict) else self.target_network
        
        self.discovered_hosts = self.network_utils.ping_sweep(
            network_target, 
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
        
        # Return the scan results
        return self.scan_results
    
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
    
    def export_results(self, format_type='json', filename=None, template_type=None):
        """Export scan results to file"""
        # Extract vulnerability assessments for export
        vulnerability_assessments = {}
        for ip, data in self.scan_results.items():
            if 'vulnerabilities' in data:
                vulnerability_assessments[ip] = data['vulnerabilities']
        
        # Set counter values for statistics
        total_hosts, total_ports = self.network_utils.get_counters()
        self.report_generator.set_counters(total_hosts, total_ports)
        
        if format_type == 'pdf' and template_type:
            self.report_generator.export_results(
                self.scan_results, 
                self.target_network, 
                format_type, 
                filename, 
                vulnerability_assessments,
                template_type=template_type
            )
        else:
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


def load_default_config():
    """Load default configuration from config file"""
    config_path = Path("config/default_flags.json")
    
    # Default configuration if file doesn't exist
    default_config = {
        "scan_options": {
            "threads": {"value": 50},
            "timeout": {"value": 3},
            "format": {"value": "json"}
        },
        "feature_flags": {
            "ping_only": {"enabled": False},
            "nmap": {"enabled": False},
            "smart_filter": {"enabled": True},
            "vuln_report": {"enabled": False},
            "incremental": {"enabled": False}
        },
        "security_options": {
            "security_level": {"value": "STANDARD"},
            "enable_security_logging": {"enabled": True},
            "rate_limiting": {"enabled": True}
        },
        "output_options": {
            "auto_export": {"enabled": False},
            "default_output_prefix": {"value": "scan_results"}
        }
    }
    
    try:
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
                return config
        else:
            print(f"[!] Config file not found at {config_path}, using defaults")
            return default_config
    except Exception as e:
        print(f"[!] Error loading config: {e}, using defaults")
        return default_config


def main():
    """Main function with enhanced argument parsing"""
    # Load default configuration
    config = load_default_config()
    
    parser = argparse.ArgumentParser(
        description='Advanced Network Mapping and Vulnerability Assessment Tool v2.2',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24                    # Basic scan
  %(prog)s 192.168.1.0/24 -t 100 --timeout 5 # High-speed scan
  %(prog)s 192.168.1.0/24 -o report -f csv   # Export to CSV
  %(prog)s 192.168.1.0/24 --vuln-report      # Generate vulnerability report
  
Configuration:
  Edit config/default_flags.json to change default flag values
        """
    )
    
    # Configuration management flags (processed first)
    parser.add_argument('--show-config', action='store_true',
                       help='Show current default configuration and exit')
    parser.add_argument('--reset-config', action='store_true',
                       help='Reset configuration to factory defaults')
    
    parser.add_argument('network', nargs='?', help='Target network (e.g., 192.168.1.0/24)')
    parser.add_argument('-t', '--threads', type=int, 
                       default=config['scan_options']['threads']['value'],
                       help=f'Number of threads (default: {config["scan_options"]["threads"]["value"]})')
    parser.add_argument('--timeout', type=int, 
                       default=config['scan_options']['timeout']['value'],
                       help=f'Timeout in seconds (default: {config["scan_options"]["timeout"]["value"]})')
    parser.add_argument('-o', '--output', 
                       help='Output filename (without extension)')
    parser.add_argument('-f', '--format', choices=['json', 'csv', 'pdf'], 
                       default=config['scan_options']['format']['value'],
                       help=f'Output format (default: {config["scan_options"]["format"]["value"]})')
    parser.add_argument('--template', choices=['executive', 'technical', 'both'], 
                       default='both',
                       help='PDF template type: executive (management summary), technical (detailed analysis), or both (default: both)')
    
    # Feature flags with configurable defaults
    parser.add_argument('--ping-only', action='store_true', 
                       default=config['feature_flags']['ping_only']['enabled'],
                       help=f'Only perform ping sweep (default: {config["feature_flags"]["ping_only"]["enabled"]})')
    parser.add_argument('--nmap', action='store_true', 
                       default=config['feature_flags']['nmap']['enabled'],
                       help=f'Use nmap for advanced scanning (default: {config["feature_flags"]["nmap"]["enabled"]})')
    parser.add_argument('--no-smart-filter', action='store_true', 
                       default=not config['feature_flags']['smart_filter']['enabled'],
                       help=f'Disable smart filtering of common infrastructure IPs (smart filter default: {config["feature_flags"]["smart_filter"]["enabled"]})')
    parser.add_argument('--vuln-report', action='store_true',
                       default=config['feature_flags']['vuln_report']['enabled'],
                       help=f'Generate focused vulnerability assessment report (default: {config["feature_flags"]["vuln_report"]["enabled"]})')
    parser.add_argument('--incremental', action='store_true',
                       default=config['feature_flags']['incremental']['enabled'],
                       help=f'Enable incremental export mode (default: {config["feature_flags"]["incremental"]["enabled"]})')
    
    # IP exclusion options
    parser.add_argument('--exclude', action='append', 
                       help='Exclude IP ranges (can be used multiple times)')
    
    args = parser.parse_args()
    
    # Handle configuration management
    if args.show_config:
        print("\n[+] Current Default Configuration:")
        print(json.dumps(config, indent=2))
        return
    
    if args.reset_config:
        config_path = Path("config/default_flags.json")
        if config_path.exists():
            backup_path = config_path.with_suffix('.json.backup')
            config_path.rename(backup_path)
            print(f"[+] Configuration backed up to {backup_path}")
            print("[+] Configuration reset to defaults. Restart to use factory defaults.")
        else:
            print("[!] No configuration file found to reset.")
        return
    
    # Auto-export handling
    if config['output_options']['auto_export']['enabled'] and not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"{config['output_options']['default_output_prefix']['value']}_{timestamp}"
        print(f"[+] Auto-export enabled: Results will be saved as {args.output}.{args.format}")
    
    # Validate required network argument for scanning operations
    if not args.network:
        parser.error("Network argument is required for scanning operations")
    
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
            if args.format == 'pdf':
                mapper.export_results(args.format, args.output, template_type=args.template)
            else:
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