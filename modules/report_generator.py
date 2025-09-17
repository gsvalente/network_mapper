"""
Report Generator Module

This module handles exporting scan results to various formats
and generating comprehensive reports with statistics.
"""

import json
import csv
import time
from datetime import datetime
from collections import Counter

try:
    from colorama import Fore
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ""


class ReportGenerator:
    """
    Handles report generation and export functionality
    """
    
    def __init__(self):
        self.incremental_mode = False
        self.output_file = None
        self.output_format = 'json'
        self.scan_start_time = None
        self.total_hosts_found = 0
        self.total_ports_found = 0
    
    def setup_incremental_export(self, format_type='json', filename=None):
        """Setup incremental export mode"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}"
        
        self.incremental_mode = True
        self.output_format = format_type.lower()
        
        if self.output_format == 'json':
            self.output_file = filename + '.json'
            # Initialize JSON file with header
            with open(self.output_file, 'w') as f:
                json.dump({
                    'scan_info': {
                        'scan_start': datetime.now().isoformat(),
                        'format': 'incremental'
                    },
                    'results': {}
                }, f, indent=2)
        elif self.output_format == 'csv':
            self.output_file = filename + '.csv'
            # Initialize CSV file with headers
            with open(self.output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                # Excel-friendly headers with separate port columns
                writer.writerow([
                    'IP Address', 'Hostname', 'MAC Address', 'Device Type', 
                    'Open Ports Count', 'Port 1', 'Service 1', 'Port 2', 'Service 2', 
                    'Port 3', 'Service 3', 'Port 4', 'Service 4', 'Port 5', 'Service 5',
                    'All Ports', 'All Services', 'Vulnerability Summary', 'Risk Level', 'Scan Time'
                ])
        
        print(f"{Fore.GREEN}[+] Incremental export enabled: {self.output_file}")
    
    def write_host_result(self, host, result, vulnerability_data=None):
        """Write individual host result to file (incremental mode)"""
        if not self.incremental_mode or not self.output_file:
            return
        
        try:
            if self.output_format == 'json':
                self._write_json_result(host, result, vulnerability_data)
            elif self.output_format == 'csv':
                self._write_csv_result(host, result, vulnerability_data)
        except Exception as e:
            print(f"{Fore.RED}[-] Error writing result for {host}: {e}")
    
    def _write_json_result(self, host, result, vulnerability_data):
        """Write JSON result for a single host"""
        # Read current file
        with open(self.output_file, 'r') as f:
            data = json.load(f)
        
        # Add vulnerability data if available
        if vulnerability_data:
            result['vulnerabilities'] = vulnerability_data
        
        # Add result
        data['results'][host] = result
        
        # Update scan info
        data['scan_info']['last_update'] = datetime.now().isoformat()
        data['scan_info']['hosts_scanned'] = len(data['results'])
        
        # Write back to file
        with open(self.output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _write_csv_result(self, host, result, vulnerability_data):
        """Write CSV result for a single host (Excel-friendly format)"""
        with open(self.output_file, 'a', newline='') as f:
            writer = csv.writer(f)
            
            # Prepare port and service data (up to 5 ports for Excel columns)
            ports = result.get('open_ports', [])
            services = result.get('services', {})
            
            # Excel-friendly port columns
            port_cols = [''] * 5
            service_cols = [''] * 5
            
            for i, port in enumerate(ports[:5]):  # Limit to first 5 ports
                port_cols[i] = str(port)
                service_cols[i] = services.get(port, 'unknown')
            
            # All ports and services as comma-separated strings
            all_ports = ','.join(map(str, ports))
            all_services = '; '.join([f"{port}:{service}" for port, service in services.items()])
            
            # Vulnerability information
            vuln_summary = ''
            risk_level = 'Low'
            if vulnerability_data:
                vuln_summary = vulnerability_data.get('summary', '')
                risk_level = vulnerability_data.get('risk_level', 'Low')
            
            # Write row
            writer.writerow([
                host,
                result.get('hostname', 'Unknown'),
                result.get('mac_address', 'Unknown'),
                result.get('device_type', 'Unknown Device'),
                len(ports),
                port_cols[0], service_cols[0],
                port_cols[1], service_cols[1],
                port_cols[2], service_cols[2],
                port_cols[3], service_cols[3],
                port_cols[4], service_cols[4],
                all_ports,
                all_services,
                vuln_summary,
                risk_level,
                result.get('scan_time', datetime.now().isoformat())
            ])
    
    def finalize_output_file(self):
        """Finalize output file with summary statistics"""
        if not self.incremental_mode or not self.output_file:
            return
        
        try:
            if self.output_format == 'json':
                self._finalize_json_file()
            print(f"{Fore.GREEN}[+] Output file finalized: {self.output_file}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error finalizing output file: {e}")
    
    def _finalize_json_file(self):
        """Add final statistics to JSON file"""
        with open(self.output_file, 'r') as f:
            data = json.load(f)
        
        # Calculate final statistics
        results = data.get('results', {})
        total_hosts = len(results)
        total_ports = sum(len(result.get('open_ports', [])) for result in results.values())
        
        # Update scan info with final statistics
        data['scan_info'].update({
            'scan_end': datetime.now().isoformat(),
            'total_hosts_scanned': total_hosts,
            'total_open_ports': total_ports,
            'scan_completed': True
        })
        
        # Write final version
        with open(self.output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def export_results(self, scan_results, target_network, format_type='json', filename=None, vulnerability_assessments=None):
        """Export scan results to file (batch mode)"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_scan_{timestamp}"
        
        # Filter out hosts with no open ports
        filtered_results = {ip: data for ip, data in scan_results.items() if data.get('open_ports')}
        
        if format_type.lower() == 'json':
            self._export_json(filtered_results, target_network, filename, vulnerability_assessments)
        elif format_type.lower() == 'csv':
            self._export_csv(filtered_results, filename, vulnerability_assessments)
    
    def _export_json(self, filtered_results, target_network, filename, vulnerability_assessments):
        """Export results to JSON format with vulnerability data"""
        filename += '.json'
        
        # Add vulnerability data to results
        enhanced_results = {}
        for ip, data in filtered_results.items():
            enhanced_data = data.copy()
            if vulnerability_assessments and ip in vulnerability_assessments:
                enhanced_data['vulnerabilities'] = vulnerability_assessments[ip]
            enhanced_results[ip] = enhanced_data
        
        export_data = {
            'scan_info': {
                'target_network': target_network,
                'scan_time': datetime.now().isoformat(),
                'total_hosts_discovered': self.total_hosts_found,
                'hosts_with_open_ports': len(filtered_results),
                'total_open_ports': sum(len(result.get('open_ports', [])) for result in filtered_results.values()),
                'scan_duration_seconds': time.time() - self.scan_start_time if self.scan_start_time else 0
            },
            'results': enhanced_results
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Results exported to {filename} ({len(filtered_results)} hosts with open ports)")
    
    def _export_csv(self, filtered_results, filename, vulnerability_assessments):
        """Export results to Excel-friendly CSV format"""
        filename += '.csv'
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Excel-friendly headers
            writer.writerow([
                'IP Address', 'Hostname', 'MAC Address', 'Device Type', 
                'Open Ports Count', 'Port 1', 'Service 1', 'Port 2', 'Service 2', 
                'Port 3', 'Service 3', 'Port 4', 'Service 4', 'Port 5', 'Service 5',
                'All Ports', 'All Services', 'Vulnerability Summary', 'Risk Level', 
                'CVE References', 'Scan Time'
            ])
            
            for ip, data in filtered_results.items():
                ports = data.get('open_ports', [])
                services = data.get('services', {})
                
                # Excel-friendly port columns (up to 5 ports)
                port_cols = [''] * 5
                service_cols = [''] * 5
                
                for i, port in enumerate(ports[:5]):
                    port_cols[i] = str(port)
                    service_cols[i] = services.get(port, 'unknown')
                
                # All ports and services
                all_ports = ','.join(map(str, ports))
                all_services = '; '.join([f"{port}:{service}" for port, service in services.items()])
                
                # Vulnerability data
                vuln_summary = ''
                risk_level = 'Low'
                cve_refs = ''
                
                if vulnerability_assessments and ip in vulnerability_assessments:
                    vuln_data = vulnerability_assessments[ip]
                    vuln_summary = vuln_data.get('summary', '')
                    risk_level = vuln_data.get('risk_level', 'Low')
                    cve_refs = ', '.join(vuln_data.get('cve_references', []))
                
                writer.writerow([
                    ip,
                    data.get('hostname', 'Unknown'),
                    data.get('mac_address', 'Unknown'),
                    data.get('device_type', 'Unknown Device'),
                    len(ports),
                    port_cols[0], service_cols[0],
                    port_cols[1], service_cols[1],
                    port_cols[2], service_cols[2],
                    port_cols[3], service_cols[3],
                    port_cols[4], service_cols[4],
                    all_ports,
                    all_services,
                    vuln_summary,
                    risk_level,
                    cve_refs,
                    data.get('scan_time', datetime.now().isoformat())
                ])
        
        print(f"{Fore.GREEN}[+] Results exported to {filename} ({len(filtered_results)} hosts with open ports)")
    
    def print_summary(self, scan_results, discovered_hosts):
        """Print comprehensive scan summary with statistics"""
        if not scan_results:
            print(f"{Fore.RED}[-] No scan results to display")
            return
        
        # Calculate statistics
        total_hosts = len(scan_results)
        total_open_ports = sum(len(result.get('open_ports', [])) for result in scan_results.values())
        unique_services = set()
        device_types = Counter()
        
        for result in scan_results.values():
            # Collect unique services
            for service in result.get('services', {}).values():
                if service != 'unknown':
                    unique_services.add(service)
            
            # Count device types
            device_type = result.get('device_type', 'Unknown Device')
            device_types[device_type] += 1
        
        # Print summary header
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}                    SCAN SUMMARY")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Print statistics
        print(f"{Fore.GREEN}[+] Total Hosts Discovered: {Fore.YELLOW}{len(discovered_hosts)}")
        print(f"{Fore.GREEN}[+] Total Hosts Scanned: {Fore.YELLOW}{total_hosts}")
        print(f"{Fore.GREEN}[+] Total Open Ports Found: {Fore.YELLOW}{total_open_ports}")
        print(f"{Fore.GREEN}[+] Unique Services Identified: {Fore.YELLOW}{len(unique_services)}")
        
        # Print timing statistics
        if self.scan_start_time:
            elapsed_time = time.time() - self.scan_start_time
            print(f"{Fore.GREEN}[+] Total Scan Time: {Fore.YELLOW}{elapsed_time:.2f} seconds")
            if elapsed_time > 0:
                hosts_per_sec = total_hosts / elapsed_time
                ports_per_sec = total_open_ports / elapsed_time
                print(f"{Fore.GREEN}[+] Average Scan Rate: {Fore.YELLOW}{hosts_per_sec:.2f} hosts/sec, {ports_per_sec:.2f} ports/sec")
        
        # Print device type distribution
        if device_types:
            print(f"\n{Fore.CYAN}[+] Device Type Distribution:")
            for device_type, count in device_types.most_common():
                percentage = (count / total_hosts) * 100
                print(f"    {Fore.WHITE}{device_type}: {Fore.YELLOW}{count} ({percentage:.1f}%)")
        
        # Print discovered services
        if unique_services:
            print(f"\n{Fore.CYAN}[+] Services Discovered: {Fore.YELLOW}{', '.join(sorted(unique_services))}")
        
        print(f"{Fore.CYAN}{'='*60}")
        
        # Print detailed results
        self._print_detailed_results(scan_results)
    
    def _print_detailed_results(self, scan_results):
        """Print detailed results for each host"""
        for host, result in scan_results.items():
            print(f"\n{Fore.CYAN}[+] Host: {Fore.WHITE}{host}")
            print(f"    {Fore.MAGENTA}Hostname: {Fore.GREEN}{result.get('hostname', 'Unknown')}")
            print(f"    {Fore.MAGENTA}MAC Address: {Fore.GREEN}{result.get('mac_address', 'Unknown')}")
            print(f"    {Fore.MAGENTA}Device Type: {Fore.CYAN}{result.get('device_type', 'Unknown Device')}")
            
            open_ports = result.get('open_ports', [])
            services = result.get('services', {})
            
            if open_ports:
                print(f"    {Fore.MAGENTA}Open Ports ({len(open_ports)}): {Fore.YELLOW}{', '.join(map(str, open_ports))}")
                for port, service in services.items():
                    print(f"        {Fore.WHITE}Port {port}: {Fore.YELLOW}{service}")
            else:
                print(f"    {Fore.RED}No open ports found")
            
            # Print vulnerability information if available
            if 'vulnerabilities' in result:
                vuln_data = result['vulnerabilities']
                risk_level = vuln_data.get('risk_level', 'Low')
                risk_color = self._get_risk_color(risk_level)
                print(f"    {Fore.MAGENTA}Risk Level: {risk_color}{risk_level}")
                
                if vuln_data.get('summary'):
                    print(f"    {Fore.MAGENTA}Vulnerabilities: {Fore.YELLOW}{vuln_data['summary']}")
    
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
    
    def generate_vulnerability_report(self, scan_results, vulnerability_assessments, filename=None):
        """Generate a focused vulnerability assessment report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vulnerability_report_{timestamp}.json"
        
        # Filter hosts with vulnerabilities
        vulnerable_hosts = {}
        risk_summary = Counter()
        
        for ip, vuln_data in vulnerability_assessments.items():
            if vuln_data.get('vulnerabilities'):
                vulnerable_hosts[ip] = {
                    'host_info': scan_results.get(ip, {}),
                    'vulnerability_assessment': vuln_data
                }
                risk_summary[vuln_data.get('risk_level', 'Low')] += 1
        
        report_data = {
            'report_info': {
                'report_type': 'vulnerability_assessment',
                'generated_at': datetime.now().isoformat(),
                'total_hosts_assessed': len(vulnerability_assessments),
                'vulnerable_hosts_count': len(vulnerable_hosts),
                'risk_distribution': dict(risk_summary)
            },
            'vulnerable_hosts': vulnerable_hosts,
            'recommendations': self._generate_recommendations(vulnerable_hosts)
        }
        
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Vulnerability report generated: {filename}")
        return filename
    
    def _generate_recommendations(self, vulnerable_hosts):
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        # Analyze common vulnerabilities
        common_ports = Counter()
        common_services = Counter()
        
        for host_data in vulnerable_hosts.values():
            host_info = host_data.get('host_info', {})
            for port in host_info.get('open_ports', []):
                common_ports[port] += 1
            for service in host_info.get('services', {}).values():
                common_services[service] += 1
        
        # Generate recommendations
        if common_ports.get(22, 0) > 1:
            recommendations.append("Consider implementing SSH key-based authentication and disabling password authentication")
        
        if common_ports.get(23, 0) > 0:
            recommendations.append("Replace Telnet with SSH for secure remote access")
        
        if common_ports.get(80, 0) > 1:
            recommendations.append("Implement HTTPS and redirect HTTP traffic for web services")
        
        if common_services.get('ftp', 0) > 0:
            recommendations.append("Replace FTP with SFTP or FTPS for secure file transfers")
        
        recommendations.append("Regularly update all systems and services to patch known vulnerabilities")
        recommendations.append("Implement network segmentation to limit attack surface")
        recommendations.append("Deploy intrusion detection systems (IDS) for monitoring")
        
        return recommendations
    
    def set_scan_timing(self, start_time):
        """Set scan start time for timing calculations"""
        self.scan_start_time = start_time
    
    def set_counters(self, total_hosts_found, total_ports_found):
        """Set counter values for statistics"""
        self.total_hosts_found = total_hosts_found
        self.total_ports_found = total_ports_found