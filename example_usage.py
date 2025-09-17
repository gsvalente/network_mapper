#!/usr/bin/env python3
"""
Example Usage Scripts for Network Mapper
Demonstrates various ways to use the NetworkMapper class programmatically
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from network_mapper import NetworkMapper
import json

def example_basic_scan():
    """Example 1: Basic network scan"""
    print("=== Example 1: Basic Network Scan ===")
    
    # Create mapper instance
    mapper = NetworkMapper("192.168.1.0/24", threads=30, timeout=2)
    
    # Discover hosts
    hosts = mapper.ping_sweep()
    
    if hosts:
        print(f"Found {len(hosts)} hosts: {', '.join(hosts)}")
        
        # Scan first host only for demo
        if hosts:
            host = hosts[0]
            ports = mapper.port_scan(host)
            print(f"Open ports on {host}: {ports}")
    else:
        print("No hosts discovered")

def example_comprehensive_scan():
    """Example 2: Comprehensive scan with service detection"""
    print("\n=== Example 2: Comprehensive Scan ===")
    
    mapper = NetworkMapper("127.0.0.0/30", threads=10, timeout=1)  # Small range for demo
    
    # Discover hosts
    hosts = mapper.ping_sweep()
    
    if hosts:
        # Full comprehensive scan
        mapper.comprehensive_scan()
        
        # Print results
        for ip, data in mapper.scan_results.items():
            print(f"\nHost: {ip}")
            print(f"  Hostname: {data['hostname']}")
            print(f"  Open Ports: {data['open_ports']}")
            for port, service in data['services'].items():
                print(f"    {port}: {service}")

def example_custom_ports():
    """Example 3: Custom port scanning"""
    print("\n=== Example 3: Custom Port Scanning ===")
    
    mapper = NetworkMapper("127.0.0.1/32")  # Localhost only
    
    # Discover hosts
    hosts = mapper.ping_sweep()
    
    if hosts:
        # Custom port list (common web ports)
        web_ports = [80, 443, 8000, 8080, 8443, 9000, 9090]
        
        for host in hosts:
            open_ports = mapper.port_scan(host, web_ports)
            print(f"Web ports open on {host}: {open_ports}")

def example_export_results():
    """Example 4: Export results to different formats"""
    print("\n=== Example 4: Export Results ===")
    
    mapper = NetworkMapper("127.0.0.1/32")
    
    # Perform scan
    hosts = mapper.ping_sweep()
    if hosts:
        mapper.comprehensive_scan()
        
        # Export to JSON
        mapper.export_results('json', 'example_scan_results')
        print("Results exported to example_scan_results.json")
        
        # Export to CSV
        mapper.export_results('csv', 'example_scan_results')
        print("Results exported to example_scan_results.csv")

def example_single_host_analysis():
    """Example 5: Detailed analysis of a single host"""
    print("\n=== Example 5: Single Host Analysis ===")
    
    target_host = "127.0.0.1"  # Change to your target
    mapper = NetworkMapper(f"{target_host}/32")
    
    # Check if host is alive
    hosts = mapper.ping_sweep()
    
    if target_host in hosts:
        print(f"Analyzing {target_host}...")
        
        # Get hostname
        hostname = mapper.get_hostname(target_host)
        print(f"Hostname: {hostname}")
        
        # Comprehensive port scan (top 100 ports)
        top_ports = list(range(1, 101)) + [135, 139, 443, 445, 993, 995, 1433, 3389, 5432, 5900]
        open_ports = mapper.port_scan(target_host, top_ports)
        
        print(f"Open ports: {open_ports}")
        
        # Service detection
        for port in open_ports[:5]:  # Limit to first 5 for demo
            service = mapper.service_detection(target_host, port)
            print(f"  Port {port}: {service}")

def example_network_range_comparison():
    """Example 6: Compare multiple network ranges"""
    print("\n=== Example 6: Network Range Comparison ===")
    
    networks = ["127.0.0.0/30", "169.254.0.0/30"]  # Small ranges for demo
    
    results = {}
    
    for network in networks:
        print(f"\nScanning {network}...")
        mapper = NetworkMapper(network, threads=5, timeout=1)
        
        hosts = mapper.ping_sweep()
        results[network] = {
            'total_hosts': len(hosts),
            'hosts': hosts
        }
    
    # Compare results
    print("\n--- Network Comparison ---")
    for network, data in results.items():
        print(f"{network}: {data['total_hosts']} hosts - {', '.join(data['hosts']) if data['hosts'] else 'None'}")

def example_performance_testing():
    """Example 7: Performance testing with different configurations"""
    print("\n=== Example 7: Performance Testing ===")
    
    import time
    
    network = "127.0.0.0/30"  # Small network for testing
    
    configs = [
        {"threads": 10, "timeout": 1},
        {"threads": 25, "timeout": 2},
        {"threads": 50, "timeout": 3}
    ]
    
    for config in configs:
        print(f"\nTesting with {config['threads']} threads, {config['timeout']}s timeout")
        
        start_time = time.time()
        mapper = NetworkMapper(network, **config)
        hosts = mapper.ping_sweep()
        end_time = time.time()
        
        print(f"  Found {len(hosts)} hosts in {end_time - start_time:.2f} seconds")

def main():
    """Run all examples"""
    print("Network Mapper - Example Usage Scripts")
    print("=" * 50)
    
    try:
        example_basic_scan()
        example_comprehensive_scan()
        example_custom_ports()
        example_export_results()
        example_single_host_analysis()
        example_network_range_comparison()
        example_performance_testing()
        
        print("\n" + "=" * 50)
        print("All examples completed successfully!")
        print("Check the generated files: example_scan_results.json and example_scan_results.csv")
        
    except KeyboardInterrupt:
        print("\nExamples interrupted by user")
    except Exception as e:
        print(f"Error running examples: {e}")

if __name__ == "__main__":
    main()