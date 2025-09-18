"""
Advanced Network Traffic Analysis Module

This module provides comprehensive network traffic monitoring and analysis capabilities
including pattern detection, anomaly identification, and behavioral analysis.

Features:
- Real-time traffic monitoring
- Protocol analysis and classification
- Anomaly detection using statistical methods
- Traffic pattern recognition
- Bandwidth utilization tracking
- Security event correlation
- Performance metrics collection
"""

import socket
import struct
import threading
import time
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
import statistics
import re

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Some traffic analysis features will be limited.")

class TrafficAnalyzer:
    """Advanced network traffic analyzer with anomaly detection"""
    
    def __init__(self, interface: str = None, capture_duration: int = 300):
        """
        Initialize the traffic analyzer
        
        Args:
            interface: Network interface to monitor (auto-detect if None)
            capture_duration: Duration to capture traffic in seconds
        """
        self.interface = interface
        self.capture_duration = capture_duration
        self.is_monitoring = False
        self.traffic_data = defaultdict(list)
        self.protocol_stats = defaultdict(int)
        self.connection_stats = defaultdict(int)
        self.bandwidth_data = deque(maxlen=1000)  # Last 1000 measurements
        self.anomalies = []
        self.baseline_established = False
        self.baseline_stats = {}
        
        # Traffic patterns and thresholds
        self.suspicious_patterns = {
            'port_scan': {'threshold': 10, 'timeframe': 60},  # 10+ ports in 60 seconds
            'dos_attack': {'threshold': 1000, 'timeframe': 10},  # 1000+ packets in 10 seconds
            'data_exfiltration': {'threshold': 100*1024*1024, 'timeframe': 300},  # 100MB in 5 minutes
            'unusual_protocol': {'threshold': 0.05}  # Less than 5% of total traffic
        }
        
        # Initialize monitoring thread
        self.monitor_thread = None
        self.stop_monitoring = threading.Event()
    
    def start_monitoring(self) -> bool:
        """Start traffic monitoring in a separate thread"""
        if self.is_monitoring:
            return False
        
        if not SCAPY_AVAILABLE:
            print("Cannot start monitoring: Scapy library not available")
            return False
        
        self.is_monitoring = True
        self.stop_monitoring.clear()
        self.monitor_thread = threading.Thread(target=self._monitor_traffic, daemon=True)
        self.monitor_thread.start()
        return True
    
    def stop_traffic_monitoring(self):
        """Stop traffic monitoring"""
        self.is_monitoring = False
        self.stop_monitoring.set()
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=5)
    
    def _monitor_traffic(self):
        """Internal method to monitor network traffic"""
        try:
            if SCAPY_AVAILABLE:
                scapy.sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    stop_filter=lambda x: self.stop_monitoring.is_set(),
                    timeout=self.capture_duration
                )
        except Exception as e:
            print(f"Error monitoring traffic: {e}")
        finally:
            self.is_monitoring = False
    
    def _process_packet(self, packet):
        """Process individual network packets"""
        try:
            timestamp = datetime.now()
            packet_info = {
                'timestamp': timestamp,
                'size': len(packet),
                'protocol': self._get_protocol(packet),
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None
            }
            
            # Extract IP information
            if packet.haslayer(scapy.IP):
                packet_info['src_ip'] = packet[scapy.IP].src
                packet_info['dst_ip'] = packet[scapy.IP].dst
            
            # Extract port information
            if packet.haslayer(scapy.TCP):
                packet_info['src_port'] = packet[scapy.TCP].sport
                packet_info['dst_port'] = packet[scapy.TCP].dport
                packet_info['protocol'] = 'TCP'
            elif packet.haslayer(scapy.UDP):
                packet_info['src_port'] = packet[scapy.UDP].sport
                packet_info['dst_port'] = packet[scapy.UDP].dport
                packet_info['protocol'] = 'UDP'
            
            # Store packet information
            self._store_packet_data(packet_info)
            
            # Update statistics
            self._update_statistics(packet_info)
            
            # Check for anomalies
            self._check_anomalies(packet_info)
            
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _get_protocol(self, packet) -> str:
        """Determine packet protocol"""
        if packet.haslayer(scapy.TCP):
            return 'TCP'
        elif packet.haslayer(scapy.UDP):
            return 'UDP'
        elif packet.haslayer(scapy.ICMP):
            return 'ICMP'
        elif packet.haslayer(scapy.ARP):
            return 'ARP'
        else:
            return 'Other'
    
    def _store_packet_data(self, packet_info: Dict):
        """Store packet data for analysis"""
        # Store by source IP
        if packet_info['src_ip']:
            self.traffic_data[packet_info['src_ip']].append(packet_info)
        
        # Store bandwidth data
        self.bandwidth_data.append({
            'timestamp': packet_info['timestamp'],
            'bytes': packet_info['size']
        })
    
    def _update_statistics(self, packet_info: Dict):
        """Update traffic statistics"""
        # Protocol statistics
        self.protocol_stats[packet_info['protocol']] += 1
        
        # Connection statistics
        if packet_info['src_ip'] and packet_info['dst_ip']:
            connection = f"{packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}"
            self.connection_stats[connection] += 1
    
    def _check_anomalies(self, packet_info: Dict):
        """Check for traffic anomalies"""
        current_time = datetime.now()
        
        # Check for port scanning
        self._check_port_scan(packet_info, current_time)
        
        # Check for DoS attacks
        self._check_dos_attack(packet_info, current_time)
        
        # Check for data exfiltration
        self._check_data_exfiltration(packet_info, current_time)
        
        # Check for unusual protocols
        self._check_unusual_protocols()
    
    def _check_port_scan(self, packet_info: Dict, current_time: datetime):
        """Detect potential port scanning activity"""
        if not packet_info['src_ip'] or not packet_info['dst_port']:
            return
        
        src_ip = packet_info['src_ip']
        timeframe = timedelta(seconds=self.suspicious_patterns['port_scan']['timeframe'])
        threshold = self.suspicious_patterns['port_scan']['threshold']
        
        # Get recent packets from this source
        recent_packets = [
            p for p in self.traffic_data[src_ip]
            if current_time - p['timestamp'] <= timeframe
        ]
        
        # Count unique destination ports
        unique_ports = set(p['dst_port'] for p in recent_packets if p['dst_port'])
        
        if len(unique_ports) >= threshold:
            anomaly = {
                'type': 'port_scan',
                'severity': 'High',
                'timestamp': current_time,
                'source_ip': src_ip,
                'description': f"Potential port scan detected from {src_ip} - {len(unique_ports)} ports accessed",
                'details': {
                    'ports_scanned': list(unique_ports),
                    'packet_count': len(recent_packets)
                }
            }
            self.anomalies.append(anomaly)
    
    def _check_dos_attack(self, packet_info: Dict, current_time: datetime):
        """Detect potential DoS attacks"""
        if not packet_info['src_ip']:
            return
        
        src_ip = packet_info['src_ip']
        timeframe = timedelta(seconds=self.suspicious_patterns['dos_attack']['timeframe'])
        threshold = self.suspicious_patterns['dos_attack']['threshold']
        
        # Get recent packets from this source
        recent_packets = [
            p for p in self.traffic_data[src_ip]
            if current_time - p['timestamp'] <= timeframe
        ]
        
        if len(recent_packets) >= threshold:
            anomaly = {
                'type': 'dos_attack',
                'severity': 'Critical',
                'timestamp': current_time,
                'source_ip': src_ip,
                'description': f"Potential DoS attack detected from {src_ip} - {len(recent_packets)} packets in {timeframe.seconds} seconds",
                'details': {
                    'packet_count': len(recent_packets),
                    'timeframe': timeframe.seconds
                }
            }
            self.anomalies.append(anomaly)
    
    def _check_data_exfiltration(self, packet_info: Dict, current_time: datetime):
        """Detect potential data exfiltration"""
        if not packet_info['src_ip']:
            return
        
        src_ip = packet_info['src_ip']
        timeframe = timedelta(seconds=self.suspicious_patterns['data_exfiltration']['timeframe'])
        threshold = self.suspicious_patterns['data_exfiltration']['threshold']
        
        # Get recent packets from this source
        recent_packets = [
            p for p in self.traffic_data[src_ip]
            if current_time - p['timestamp'] <= timeframe
        ]
        
        # Calculate total bytes transferred
        total_bytes = sum(p['size'] for p in recent_packets)
        
        if total_bytes >= threshold:
            anomaly = {
                'type': 'data_exfiltration',
                'severity': 'High',
                'timestamp': current_time,
                'source_ip': src_ip,
                'description': f"Potential data exfiltration detected from {src_ip} - {total_bytes / (1024*1024):.2f} MB transferred",
                'details': {
                    'bytes_transferred': total_bytes,
                    'packet_count': len(recent_packets),
                    'timeframe': timeframe.seconds
                }
            }
            self.anomalies.append(anomaly)
    
    def _check_unusual_protocols(self):
        """Detect unusual protocol usage"""
        if not self.protocol_stats:
            return
        
        total_packets = sum(self.protocol_stats.values())
        threshold = self.suspicious_patterns['unusual_protocol']['threshold']
        
        for protocol, count in self.protocol_stats.items():
            percentage = count / total_packets
            
            if percentage < threshold and count > 10:  # At least 10 packets to be significant
                anomaly = {
                    'type': 'unusual_protocol',
                    'severity': 'Medium',
                    'timestamp': datetime.now(),
                    'description': f"Unusual protocol usage detected: {protocol} ({percentage*100:.2f}% of traffic)",
                    'details': {
                        'protocol': protocol,
                        'packet_count': count,
                        'percentage': percentage * 100
                    }
                }
                self.anomalies.append(anomaly)
    
    def get_traffic_summary(self) -> Dict[str, Any]:
        """Get comprehensive traffic analysis summary"""
        current_time = datetime.now()
        
        # Calculate bandwidth statistics
        bandwidth_stats = self._calculate_bandwidth_stats()
        
        # Get top talkers
        top_talkers = self._get_top_talkers()
        
        # Get protocol distribution
        protocol_distribution = self._get_protocol_distribution()
        
        # Get recent anomalies
        recent_anomalies = [
            a for a in self.anomalies
            if current_time - a['timestamp'] <= timedelta(hours=1)
        ]
        
        return {
            'timestamp': current_time,
            'monitoring_status': self.is_monitoring,
            'total_packets': sum(self.protocol_stats.values()),
            'bandwidth_stats': bandwidth_stats,
            'protocol_distribution': protocol_distribution,
            'top_talkers': top_talkers,
            'anomalies': {
                'total': len(self.anomalies),
                'recent': len(recent_anomalies),
                'by_severity': self._group_anomalies_by_severity(recent_anomalies)
            },
            'connection_count': len(self.connection_stats)
        }
    
    def _calculate_bandwidth_stats(self) -> Dict[str, float]:
        """Calculate bandwidth utilization statistics"""
        if not self.bandwidth_data:
            return {'current_bps': 0, 'average_bps': 0, 'peak_bps': 0}
        
        current_time = datetime.now()
        recent_data = [
            d for d in self.bandwidth_data
            if current_time - d['timestamp'] <= timedelta(seconds=60)
        ]
        
        if not recent_data:
            return {'current_bps': 0, 'average_bps': 0, 'peak_bps': 0}
        
        # Calculate bytes per second
        total_bytes = sum(d['bytes'] for d in recent_data)
        duration = 60  # seconds
        
        current_bps = total_bytes / duration
        
        # Calculate average and peak from all data
        all_bps = []
        for i in range(len(self.bandwidth_data) - 1):
            time_diff = (self.bandwidth_data[i+1]['timestamp'] - self.bandwidth_data[i]['timestamp']).total_seconds()
            if time_diff > 0:
                bps = self.bandwidth_data[i]['bytes'] / time_diff
                all_bps.append(bps)
        
        average_bps = statistics.mean(all_bps) if all_bps else 0
        peak_bps = max(all_bps) if all_bps else 0
        
        return {
            'current_bps': current_bps,
            'average_bps': average_bps,
            'peak_bps': peak_bps
        }
    
    def _get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top traffic generators"""
        talker_stats = {}
        
        for ip, packets in self.traffic_data.items():
            total_bytes = sum(p['size'] for p in packets)
            packet_count = len(packets)
            
            talker_stats[ip] = {
                'ip': ip,
                'total_bytes': total_bytes,
                'packet_count': packet_count,
                'avg_packet_size': total_bytes / packet_count if packet_count > 0 else 0
            }
        
        # Sort by total bytes and return top talkers
        sorted_talkers = sorted(
            talker_stats.values(),
            key=lambda x: x['total_bytes'],
            reverse=True
        )
        
        return sorted_talkers[:limit]
    
    def _get_protocol_distribution(self) -> Dict[str, Dict[str, Any]]:
        """Get protocol usage distribution"""
        total_packets = sum(self.protocol_stats.values())
        
        if total_packets == 0:
            return {}
        
        distribution = {}
        for protocol, count in self.protocol_stats.items():
            percentage = (count / total_packets) * 100
            distribution[protocol] = {
                'packet_count': count,
                'percentage': percentage
            }
        
        return distribution
    
    def _group_anomalies_by_severity(self, anomalies: List[Dict]) -> Dict[str, int]:
        """Group anomalies by severity level"""
        severity_counts = defaultdict(int)
        
        for anomaly in anomalies:
            severity = anomaly.get('severity', 'Unknown')
            severity_counts[severity] += 1
        
        return dict(severity_counts)
    
    def export_traffic_data(self, filename: str = None) -> str:
        """Export traffic analysis data to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"traffic_analysis_{timestamp}.json"
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'summary': self.get_traffic_summary(),
            'anomalies': self.anomalies,
            'protocol_stats': dict(self.protocol_stats),
            'connection_stats': dict(self.connection_stats)
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            return filename
        except Exception as e:
            print(f"Error exporting traffic data: {e}")
            return None
    
    def generate_traffic_report(self) -> str:
        """Generate a comprehensive traffic analysis report"""
        summary = self.get_traffic_summary()
        
        report = f"""
NETWORK TRAFFIC ANALYSIS REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

MONITORING STATUS
- Status: {'Active' if summary['monitoring_status'] else 'Inactive'}
- Total Packets Analyzed: {summary['total_packets']:,}
- Active Connections: {summary['connection_count']:,}

BANDWIDTH UTILIZATION
- Current: {summary['bandwidth_stats']['current_bps']/1024:.2f} KB/s
- Average: {summary['bandwidth_stats']['average_bps']/1024:.2f} KB/s
- Peak: {summary['bandwidth_stats']['peak_bps']/1024:.2f} KB/s

PROTOCOL DISTRIBUTION
"""
        
        for protocol, stats in summary['protocol_distribution'].items():
            report += f"- {protocol}: {stats['packet_count']:,} packets ({stats['percentage']:.1f}%)\n"
        
        report += f"""
TOP TRAFFIC GENERATORS
"""
        
        for i, talker in enumerate(summary['top_talkers'][:5], 1):
            report += f"{i}. {talker['ip']}: {talker['total_bytes']/1024:.2f} KB ({talker['packet_count']} packets)\n"
        
        report += f"""
SECURITY ANOMALIES
- Total Anomalies: {summary['anomalies']['total']}
- Recent (1 hour): {summary['anomalies']['recent']}
"""
        
        for severity, count in summary['anomalies']['by_severity'].items():
            report += f"- {severity}: {count}\n"
        
        if self.anomalies:
            report += f"\nRECENT ANOMALIES:\n"
            recent_anomalies = sorted(self.anomalies, key=lambda x: x['timestamp'], reverse=True)[:5]
            
            for anomaly in recent_anomalies:
                report += f"- [{anomaly['severity']}] {anomaly['description']}\n"
                report += f"  Time: {anomaly['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}\n"
        
        return report