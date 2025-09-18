"""
Network Topology Mapper Module

This module provides advanced network topology mapping capabilities including:
- Device relationship analysis
- Network graph generation
- Visual topology representation
- Connection strength analysis
- Network segmentation detection
"""

import networkx as nx
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend to avoid threading issues
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import ipaddress
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Set
import threading
import queue
import time

class NetworkTopologyMapper:
    """Advanced network topology mapping and visualization"""
    
    def __init__(self):
        self.graph = nx.Graph()
        self.device_positions = {}
        self.network_segments = {}
        self.connection_strengths = {}
        self.topology_data = {}
        
    def analyze_network_topology(self, scan_results: Dict) -> Dict:
        """
        Analyze scan results to build network topology
        
        Args:
            scan_results: Dictionary of scan results from network mapper
            
        Returns:
            Dictionary containing topology analysis
        """
        self.topology_data = {
            'devices': {},
            'connections': [],
            'segments': {},
            'gateways': [],
            'analysis_time': datetime.now().isoformat()
        }
        
        # Clear previous graph
        self.graph.clear()
        
        # Analyze each device
        for ip, device_info in scan_results.items():
            self._analyze_device(ip, device_info)
        
        # Detect network segments
        self._detect_network_segments(scan_results)
        
        # Identify potential gateways and routers
        self._identify_gateways(scan_results)
        
        # Calculate connection strengths
        self._calculate_connection_strengths(scan_results)
        
        # Generate network graph
        self._generate_network_graph()
        
        return self.topology_data
    
    def _analyze_device(self, ip: str, device_info: Dict):
        """Analyze individual device and add to topology"""
        device_type = device_info.get('device_type', 'Unknown')
        hostname = device_info.get('hostname', 'Unknown')
        mac_address = device_info.get('mac_address', 'Unknown')
        open_ports = device_info.get('open_ports', [])
        services = device_info.get('services', {})
        
        # Determine device role based on services and ports
        device_role = self._determine_device_role(open_ports, services, device_type)
        
        # Add device to graph
        self.graph.add_node(ip, 
                           hostname=hostname,
                           device_type=device_type,
                           device_role=device_role,
                           mac_address=mac_address,
                           open_ports=open_ports,
                           services=services)
        
        # Store device information
        self.topology_data['devices'][ip] = {
            'hostname': hostname,
            'device_type': device_type,
            'device_role': device_role,
            'mac_address': mac_address,
            'open_ports': open_ports,
            'services': services,
            'risk_level': self._calculate_device_risk(open_ports, services)
        }
    
    def _determine_device_role(self, open_ports: List, services: Dict, device_type: str) -> str:
        """Determine the role of a device based on its characteristics"""
        # Check for common server ports
        server_ports = {80, 443, 21, 22, 23, 25, 53, 110, 143, 993, 995}
        database_ports = {1433, 3306, 5432, 1521, 27017}
        router_ports = {161, 162, 179}
        
        open_port_set = set(open_ports)
        
        if open_port_set.intersection(router_ports) or 'router' in device_type.lower():
            return 'Router/Gateway'
        elif open_port_set.intersection(database_ports):
            return 'Database Server'
        elif open_port_set.intersection(server_ports):
            return 'Web/Application Server'
        elif 22 in open_ports or 3389 in open_ports:
            return 'Remote Access Server'
        elif len(open_ports) > 10:
            return 'Multi-Service Server'
        elif len(open_ports) == 0:
            return 'Filtered/Stealth Device'
        else:
            return 'Workstation/Client'
    
    def _detect_network_segments(self, scan_results: Dict):
        """Detect network segments based on IP ranges and device characteristics"""
        segments = {}
        
        for ip in scan_results.keys():
            try:
                ip_obj = ipaddress.IPv4Address(ip)
                # Assume /24 network for segmentation analysis
                network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                network_str = str(network.network_address)
                
                if network_str not in segments:
                    segments[network_str] = {
                        'network': str(network),
                        'devices': [],
                        'device_count': 0,
                        'segment_type': 'Unknown'
                    }
                
                segments[network_str]['devices'].append(ip)
                segments[network_str]['device_count'] += 1
                
            except Exception:
                continue
        
        # Classify segments based on device types
        for segment_id, segment_info in segments.items():
            device_roles = []
            for device_ip in segment_info['devices']:
                if device_ip in self.topology_data['devices']:
                    device_roles.append(self.topology_data['devices'][device_ip]['device_role'])
            
            segment_info['segment_type'] = self._classify_segment(device_roles)
        
        self.topology_data['segments'] = segments
        self.network_segments = segments
    
    def _classify_segment(self, device_roles: List[str]) -> str:
        """Classify network segment based on device roles"""
        if any('Server' in role for role in device_roles):
            return 'Server Segment'
        elif any('Router' in role for role in device_roles):
            return 'Infrastructure Segment'
        elif len(set(device_roles)) == 1 and 'Workstation' in device_roles[0]:
            return 'Client Segment'
        else:
            return 'Mixed Segment'
    
    def _identify_gateways(self, scan_results: Dict):
        """Identify potential gateways and critical infrastructure"""
        gateways = []
        
        for ip, device_info in scan_results.items():
            device_role = self.topology_data['devices'][ip]['device_role']
            open_ports = device_info.get('open_ports', [])
            
            # Check for gateway characteristics
            is_gateway = (
                'Router' in device_role or
                'Gateway' in device_role or
                161 in open_ports or  # SNMP
                179 in open_ports or  # BGP
                ip.endswith('.1') or  # Common gateway IP
                ip.endswith('.254')   # Common gateway IP
            )
            
            if is_gateway:
                gateways.append({
                    'ip': ip,
                    'hostname': device_info.get('hostname', 'Unknown'),
                    'device_type': device_info.get('device_type', 'Unknown'),
                    'confidence': self._calculate_gateway_confidence(ip, device_info)
                })
        
        self.topology_data['gateways'] = sorted(gateways, key=lambda x: x['confidence'], reverse=True)
    
    def _calculate_gateway_confidence(self, ip: str, device_info: Dict) -> float:
        """Calculate confidence score for gateway identification"""
        confidence = 0.0
        open_ports = device_info.get('open_ports', [])
        
        # IP address patterns
        if ip.endswith('.1'):
            confidence += 0.3
        elif ip.endswith('.254'):
            confidence += 0.2
        
        # Port-based indicators
        if 161 in open_ports:  # SNMP
            confidence += 0.3
        if 179 in open_ports:  # BGP
            confidence += 0.2
        if 22 in open_ports:   # SSH (common on routers)
            confidence += 0.1
        
        # Device type
        device_type = device_info.get('device_type', '').lower()
        if 'router' in device_type or 'gateway' in device_type:
            confidence += 0.4
        
        return min(confidence, 1.0)
    
    def _calculate_connection_strengths(self, scan_results: Dict):
        """Calculate connection strengths between devices"""
        for ip1 in scan_results.keys():
            for ip2 in scan_results.keys():
                if ip1 != ip2:
                    strength = self._calculate_connection_strength(ip1, ip2, scan_results)
                    if strength > 0:
                        self.graph.add_edge(ip1, ip2, weight=strength)
                        self.topology_data['connections'].append({
                            'source': ip1,
                            'target': ip2,
                            'strength': strength,
                            'connection_type': self._determine_connection_type(ip1, ip2, scan_results)
                        })
    
    def _calculate_connection_strength(self, ip1: str, ip2: str, scan_results: Dict) -> float:
        """Calculate connection strength between two devices"""
        strength = 0.0
        
        # Same subnet = higher connection probability
        try:
            net1 = ipaddress.IPv4Network(f"{ip1}/24", strict=False)
            net2 = ipaddress.IPv4Network(f"{ip2}/24", strict=False)
            if net1.network_address == net2.network_address:
                strength += 0.5
        except:
            pass
        
        # Similar services = potential communication
        services1 = set(scan_results[ip1].get('services', {}).keys())
        services2 = set(scan_results[ip2].get('services', {}).keys())
        common_services = services1.intersection(services2)
        strength += len(common_services) * 0.1
        
        # Complementary roles (client-server relationships)
        role1 = self.topology_data['devices'][ip1]['device_role']
        role2 = self.topology_data['devices'][ip2]['device_role']
        
        if ('Server' in role1 and 'Workstation' in role2) or ('Server' in role2 and 'Workstation' in role1):
            strength += 0.3
        elif 'Gateway' in role1 or 'Gateway' in role2:
            strength += 0.4
        
        return min(strength, 1.0)
    
    def _determine_connection_type(self, ip1: str, ip2: str, scan_results: Dict) -> str:
        """Determine the type of connection between devices"""
        role1 = self.topology_data['devices'][ip1]['device_role']
        role2 = self.topology_data['devices'][ip2]['device_role']
        
        if 'Gateway' in role1 or 'Gateway' in role2:
            return 'Gateway Connection'
        elif 'Server' in role1 and 'Workstation' in role2:
            return 'Client-Server'
        elif 'Server' in role2 and 'Workstation' in role1:
            return 'Client-Server'
        elif 'Server' in role1 and 'Server' in role2:
            return 'Server-Server'
        else:
            return 'Peer-to-Peer'
    
    def _generate_network_graph(self):
        """Generate network graph layout"""
        if len(self.graph.nodes()) > 0:
            # Use spring layout for better visualization
            self.device_positions = nx.spring_layout(self.graph, k=3, iterations=50)
        
    def _calculate_device_risk(self, open_ports: List, services: Dict) -> str:
        """Calculate risk level for a device"""
        risk_score = 0
        
        # High-risk ports
        high_risk_ports = {21, 23, 135, 139, 445, 1433, 3389}
        medium_risk_ports = {22, 80, 443, 3306, 5432}
        
        for port in open_ports:
            if port in high_risk_ports:
                risk_score += 3
            elif port in medium_risk_ports:
                risk_score += 1
            else:
                risk_score += 0.5
        
        # Service-based risk
        for service_info in services.values():
            if isinstance(service_info, dict) and service_info.get('vulnerabilities'):
                risk_score += len(service_info['vulnerabilities'])
        
        if risk_score >= 10:
            return 'High'
        elif risk_score >= 5:
            return 'Medium'
        else:
            return 'Low'
    
    def create_topology_visualization(self, canvas_frame, width=800, height=600):
        """Create interactive topology visualization"""
        # Ensure we're using the correct backend for threading safety
        import matplotlib
        matplotlib.use('Agg')
        
        fig, ax = plt.subplots(figsize=(width/100, height/100))
        fig.patch.set_facecolor('white')
        
        if len(self.graph.nodes()) == 0:
            ax.text(0.5, 0.5, 'No topology data available\nRun a network scan first', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=14)
            ax.set_xlim(0, 1)
            ax.set_ylim(0, 1)
            ax.axis('off')
        else:
            # Draw network segments as background regions
            self._draw_network_segments(ax)
            
            # Draw connections
            self._draw_connections(ax)
            
            # Draw devices
            self._draw_devices(ax)
            
            # Add legend
            self._add_topology_legend(ax)
            
            ax.set_title('Network Topology Map', fontsize=16, fontweight='bold')
            ax.axis('off')
        
        # Embed in tkinter with thread safety
        try:
            canvas = FigureCanvasTkAgg(fig, canvas_frame)
            canvas.draw()
            plt.close(fig)  # Close figure to free memory and prevent threading issues
            return canvas.get_tk_widget()
        except Exception as e:
            print(f"Error creating topology visualization: {e}")
            plt.close(fig)  # Ensure figure is closed even on error
            return None
    
    def _draw_network_segments(self, ax):
        """Draw network segments as colored background regions"""
        colors = ['lightblue', 'lightgreen', 'lightyellow', 'lightcoral', 'lightgray']
        
        for i, (segment_id, segment_info) in enumerate(self.network_segments.items()):
            if len(segment_info['devices']) > 1:
                # Get positions of devices in this segment
                segment_positions = [self.device_positions[ip] for ip in segment_info['devices'] 
                                   if ip in self.device_positions]
                
                if segment_positions:
                    # Create convex hull around segment devices
                    positions = np.array(segment_positions)
                    x_coords = positions[:, 0]
                    y_coords = positions[:, 1]
                    
                    # Add padding around the segment
                    padding = 0.1
                    x_min, x_max = x_coords.min() - padding, x_coords.max() + padding
                    y_min, y_max = y_coords.min() - padding, y_coords.max() + padding
                    
                    # Draw segment background
                    rect = patches.Rectangle((x_min, y_min), x_max - x_min, y_max - y_min,
                                           linewidth=1, edgecolor='gray', 
                                           facecolor=colors[i % len(colors)], alpha=0.3)
                    ax.add_patch(rect)
                    
                    # Add segment label
                    ax.text(x_min + 0.02, y_max - 0.02, f"{segment_info['segment_type']}\n({segment_info['device_count']} devices)",
                           fontsize=8, bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8))
    
    def _draw_connections(self, ax):
        """Draw connections between devices"""
        for edge in self.graph.edges(data=True):
            source, target, data = edge
            if source in self.device_positions and target in self.device_positions:
                x1, y1 = self.device_positions[source]
                x2, y2 = self.device_positions[target]
                
                # Line thickness based on connection strength
                weight = data.get('weight', 0.1)
                line_width = max(0.5, weight * 3)
                
                # Line color based on connection type
                connection_type = next((conn['connection_type'] for conn in self.topology_data['connections'] 
                                      if (conn['source'] == source and conn['target'] == target) or
                                         (conn['source'] == target and conn['target'] == source)), 'Unknown')
                
                color_map = {
                    'Gateway Connection': 'red',
                    'Client-Server': 'blue',
                    'Server-Server': 'green',
                    'Peer-to-Peer': 'gray'
                }
                color = color_map.get(connection_type, 'gray')
                
                ax.plot([x1, x2], [y1, y2], color=color, linewidth=line_width, alpha=0.6)
    
    def _draw_devices(self, ax):
        """Draw devices as nodes"""
        for ip, pos in self.device_positions.items():
            device_info = self.topology_data['devices'][ip]
            
            # Node size based on number of open ports
            port_count = len(device_info['open_ports'])
            node_size = max(200, port_count * 50)
            
            # Node color based on device role
            role_colors = {
                'Router/Gateway': 'red',
                'Database Server': 'orange',
                'Web/Application Server': 'green',
                'Remote Access Server': 'purple',
                'Multi-Service Server': 'blue',
                'Workstation/Client': 'lightblue',
                'Filtered/Stealth Device': 'gray'
            }
            color = role_colors.get(device_info['device_role'], 'lightgray')
            
            # Draw node
            ax.scatter(pos[0], pos[1], s=node_size, c=color, alpha=0.8, edgecolors='black', linewidth=2)
            
            # Add device label
            hostname = device_info['hostname'] if device_info['hostname'] != 'Unknown' else ip
            ax.annotate(f"{hostname}\n{ip}", (pos[0], pos[1]), xytext=(5, 5), 
                       textcoords='offset points', fontsize=8, 
                       bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8))
    
    def _add_topology_legend(self, ax):
        """Add legend to topology visualization"""
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=10, label='Router/Gateway'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=10, label='Web/App Server'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='orange', markersize=10, label='Database Server'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='lightblue', markersize=10, label='Workstation'),
            plt.Line2D([0], [0], color='red', linewidth=2, label='Gateway Connection'),
            plt.Line2D([0], [0], color='blue', linewidth=2, label='Client-Server'),
            plt.Line2D([0], [0], color='green', linewidth=2, label='Server-Server')
        ]
        
        ax.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(0, 1))
    
    def export_topology_data(self, filename: str):
        """Export topology data to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.topology_data, f, indent=2)
    
    def get_topology_summary(self) -> Dict:
        """Get summary statistics of the network topology"""
        return {
            'total_devices': len(self.topology_data['devices']),
            'total_connections': len(self.topology_data['connections']),
            'network_segments': len(self.topology_data['segments']),
            'identified_gateways': len(self.topology_data['gateways']),
            'device_roles': {role: sum(1 for d in self.topology_data['devices'].values() 
                                     if d['device_role'] == role) 
                           for role in set(d['device_role'] for d in self.topology_data['devices'].values())},
            'risk_distribution': {risk: sum(1 for d in self.topology_data['devices'].values() 
                                          if d['risk_level'] == risk) 
                                for risk in ['Low', 'Medium', 'High']}
        }