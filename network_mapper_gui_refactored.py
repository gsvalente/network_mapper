"""
Refactored Network Mapper GUI - Clean Architecture Implementation
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
from datetime import datetime, timedelta
from pathlib import Path
import json
from typing import Dict, Any, Optional

# Import GUI components
from gui.scan_tab import ScanTab
from gui.results_tab import ResultsTab
from gui.scan_controller import ScanController

# Import other modules (keeping existing functionality)
from modules.topology_mapper import NetworkTopologyMapper
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.traffic_analyzer import TrafficAnalyzer


class NetworkMapperGUI:
    """
    Refactored Network Mapper GUI using Clean Architecture principles
    
    This class now acts as the main coordinator, delegating specific
    responsibilities to dedicated components and controllers.
    """
    
    def __init__(self, root):
        self.root = root
        self._setup_window()
        self._initialize_components()
        self._setup_gui()
        self._bind_events()
    
    def _setup_window(self):
        """Setup the main window properties"""
        self.root.title("Network Mapper - Professional Security Scanner")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Configure main window grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Setup styles
        self._setup_styles()
    
    def _setup_styles(self):
        """Setup TTK styles"""
        style = ttk.Style()
        
        # Configure notebook style
        style.configure('TNotebook', tabposition='n')
        style.configure('TNotebook.Tab', padding=[20, 10])
        
        # Configure button styles
        style.configure('Accent.TButton', foreground='white')
        
        # Configure frame styles
        style.configure('Card.TFrame', relief='raised', borderwidth=1)
    
    def _initialize_components(self):
        """Initialize controllers and other components"""
        # Controllers
        self.scan_controller = ScanController()
        
        # Other components (keeping existing functionality)
        self.topology_mapper = NetworkTopologyMapper()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.traffic_analyzer = TrafficAnalyzer()
        
        # State tracking
        self.current_tab = 0
    
    def _setup_gui(self):
        """Setup the main GUI structure"""
        # Create main notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Create tabs
        self.scan_tab = ScanTab(self.notebook, controller=self)
        self.results_tab = ResultsTab(self.notebook, controller=self)
        
        # Create other tabs (simplified versions of existing functionality)
        self._create_topology_tab()
        self._create_traffic_tab()
        
        # Set default tab
        self.notebook.select(0)
    
    def _create_topology_tab(self):
        """Create the topology analysis tab with full functionality"""
        topology_frame = ttk.Frame(self.notebook)
        self.notebook.add(topology_frame, text="Network Topology")
        
        # Main container for topology
        main_frame = ttk.Frame(topology_frame, padding="10")
        main_frame.pack(fill="both", expand=True)
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Topology Controls", padding="10")
        control_frame.pack(fill="x", pady=(0, 10))
        
        # Generate topology button
        self.generate_topology_btn = ttk.Button(control_frame, text="Generate Topology Map", 
                                              command=self.generate_topology_map)
        self.generate_topology_btn.pack(side="left", padx=(0, 10))
        
        # Export topology button
        self.export_topology_btn = ttk.Button(control_frame, text="Export Topology Data", 
                                            command=self.export_topology_data)
        self.export_topology_btn.pack(side="left", padx=(0, 10))
        
        # Topology summary button
        self.topology_summary_btn = ttk.Button(control_frame, text="Show Summary", 
                                             command=self.show_topology_summary)
        self.topology_summary_btn.pack(side="left")
        
        # Canvas frame for topology visualization
        self.topology_canvas_frame = ttk.LabelFrame(main_frame, text="Network Topology Map", padding="10")
        self.topology_canvas_frame.pack(fill="both", expand=True)
        
        # Create a container for the topology content with summary overlay
        self.topology_content_frame = ttk.Frame(self.topology_canvas_frame)
        self.topology_content_frame.pack(fill="both", expand=True)
        
        # Summary panel in top-left corner (initially hidden)
        self.topology_summary_frame = ttk.LabelFrame(self.topology_content_frame, text="Summary", padding="5")
        self.topology_summary_frame.place(x=10, y=10, width=250, height=150)
        self.topology_summary_frame.place_forget()  # Hide initially
        
        # Summary text widget
        self.topology_summary_text = tk.Text(self.topology_summary_frame, wrap=tk.WORD, 
                                           font=('Arial', 8), height=8, width=30,
                                           bg='#f0f0f0', relief=tk.FLAT)
        self.topology_summary_text.pack(fill="both", expand=True, padx=2, pady=2)
        
        # Initially show placeholder
        self.topology_placeholder = ttk.Label(self.topology_content_frame, 
                                            text="Run a network scan first, then click 'Generate Topology Map' to visualize the network structure",
                                            font=('Arial', 12))
        self.topology_placeholder.pack(expand=True)
    
    def _create_traffic_tab(self):
        """Create the traffic analysis tab with full monitoring interface"""
        traffic_frame = ttk.Frame(self.notebook)
        self.notebook.add(traffic_frame, text="Traffic Analysis")
        
        # Configure main traffic frame grid weights
        traffic_frame.grid_rowconfigure(2, weight=1)  # Results area should expand
        traffic_frame.grid_columnconfigure(0, weight=1)
        
        # Control frame
        control_frame = ttk.LabelFrame(traffic_frame, text="Traffic Monitoring Controls")
        control_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=5)
        control_frame.grid_columnconfigure(1, weight=1)
        
        # Monitoring controls
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.interface_var = tk.StringVar(value="auto-detect")
        interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var, 
                                     values=["auto-detect", "eth0", "wlan0", "lo"])
        interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        ttk.Label(control_frame, text="Duration (seconds):").grid(row=0, column=2, padx=5, pady=5, sticky="w")
        self.duration_var = tk.StringVar(value="300")
        duration_entry = ttk.Entry(control_frame, textvariable=self.duration_var, width=10)
        duration_entry.grid(row=0, column=3, padx=5, pady=5)
        
        # Control buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=1, column=0, columnspan=4, pady=10)
        
        self.start_monitoring_btn = ttk.Button(button_frame, text="Start Monitoring", 
                                             command=self._start_traffic_monitoring)
        self.start_monitoring_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_monitoring_btn = ttk.Button(button_frame, text="Stop Monitoring", 
                                            command=self._stop_traffic_monitoring, state="disabled")
        self.stop_monitoring_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Export Data", 
                  command=self._export_traffic_data).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Generate Report", 
                  command=self._generate_traffic_report).pack(side=tk.LEFT, padx=5)
        
        # Status frame
        status_frame = ttk.LabelFrame(traffic_frame, text="Monitoring Status")
        status_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
        status_frame.grid_columnconfigure(1, weight=1)
        
        # Status indicators
        ttk.Label(status_frame, text="Status:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.monitoring_status_label = ttk.Label(status_frame, text="Stopped", foreground="red")
        self.monitoring_status_label.grid(row=0, column=1, padx=5, pady=2, sticky="w")
        
        ttk.Label(status_frame, text="Packets Captured:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.packets_captured_label = ttk.Label(status_frame, text="0")
        self.packets_captured_label.grid(row=1, column=1, padx=5, pady=2, sticky="w")
        
        ttk.Label(status_frame, text="Anomalies Detected:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
        self.anomalies_detected_label = ttk.Label(status_frame, text="0")
        self.anomalies_detected_label.grid(row=2, column=1, padx=5, pady=2, sticky="w")
        
        # Results frame
        results_frame = ttk.LabelFrame(traffic_frame, text="Traffic Analysis Results")
        results_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
        
        # Results text area with scrollbar
        text_frame = ttk.Frame(results_frame)
        text_frame.grid(row=0, column=0, sticky="nsew")
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)
        
        self.traffic_results_text = tk.Text(text_frame, wrap=tk.WORD, height=15)
        self.traffic_results_text.grid(row=0, column=0, sticky="nsew")
        
        # Scrollbar for results
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.traffic_results_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.traffic_results_text.configure(yscrollcommand=scrollbar.set)
        
        # Initial message
        self.traffic_results_text.insert(tk.END, "Traffic monitoring ready. Click 'Start Monitoring' to begin.\n\n")
    
    def _bind_events(self):
        """Bind events between components"""
        # Scan tab events
        self.scan_tab.bind_event('start_scan', self._on_start_scan)
        self.scan_tab.bind_event('stop_scan', self._on_stop_scan)
        
        # Results tab events
        self.results_tab.bind_event('filter_change', self._on_filter_change)
        
        # Controller callbacks
        self.scan_controller.add_status_callback(self._on_status_update)
        self.scan_controller.add_results_callback(self._on_results_update)
        
        # Window events
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
    
    def _on_start_scan(self, config: Dict[str, Any]):
        """Handle scan start event"""
        success = self.scan_controller.start_scan(config)
        if success:
            # Update UI state
            self.scan_tab.get_status_panel().set_scan_running(True)
            self.results_tab.clear_results()
        else:
            messagebox.showerror("Scan Error", "Failed to start scan. Please check your configuration.")
    
    def _on_stop_scan(self):
        """Handle scan stop event"""
        self.scan_controller.stop_scan()
        self.scan_tab.get_status_panel().set_scan_running(False)
    
    def _on_status_update(self, status: Dict[str, Any]):
        """Handle status updates from the controller"""
        # Update status panel
        status_panel = self.scan_tab.get_status_panel()
        
        # Update progress
        status_panel.update_progress(status['progress'], status['current_host'])
        
        # Update hosts count
        status_panel.update_hosts_count(status['completed_hosts'])
        
        # Update elapsed time
        if status['start_time']:
            elapsed = datetime.now() - status['start_time']
            elapsed_str = str(elapsed).split('.')[0]  # Remove microseconds
            status_panel.update_elapsed_time(elapsed_str)
        
        # Update scan state
        status_panel.set_scan_running(status['running'])
        
        # Handle errors
        if status['error']:
            messagebox.showerror("Scan Error", status['error'])
    
    def _on_results_update(self, results: Dict[str, Any]):
        """Handle results updates from the controller"""
        print(f"[DEBUG] _on_results_update called with {len(results)} hosts")
        print(f"[DEBUG] Results data: {results}")
        
        # Update results tab
        print("[DEBUG] Updating results tab...")
        self.results_tab.update_results(results)
        print("[DEBUG] Results tab updated")
        
        # Update quick results panel
        print("[DEBUG] Updating quick results panel...")
        results_panel = self.scan_tab.get_results_panel()
        
        # Calculate summary statistics
        total_hosts = len(results)
        
        # Debug: Print the structure of each host's data
        for host_ip, host_data in results.items():
            print(f"[DEBUG] Host {host_ip} structure:")
            print(f"[DEBUG]   - Direct risk_level: {host_data.get('risk_level')}")
            print(f"[DEBUG]   - Vulnerabilities risk_level: {host_data.get('vulnerabilities', {}).get('risk_level')}")
        
        # Check for high risk in the vulnerabilities section (correct location)
        high_risk_hosts = sum(1 for host_data in results.values() 
                             if host_data.get('vulnerabilities', {}).get('risk_level') in ['High', 'Critical'])
        
        print(f"[DEBUG] Summary: {total_hosts} total hosts, {high_risk_hosts} high risk")
        results_panel.update_summary(total_hosts, high_risk_hosts)
        print("[DEBUG] Quick results panel updated")
        
        # Store scan results for topology generation
        self.scan_results = results
        
        # Auto-generate topology map after scan completion
        if total_hosts > 0:
            print("[DEBUG] Auto-generating topology map...")
            try:
                self._auto_generate_topology(results)
            except Exception as e:
                print(f"[DEBUG] Error auto-generating topology: {e}")
                # Continue without topology if there's an error
    
    def _auto_generate_topology(self, results: Dict[str, Any]):
        """Automatically generate topology map after scan completion"""
        try:
            print("[DEBUG] Generating topology data...")
            topology_data = self.topology_mapper.analyze_network_topology(results)
            print(f"[DEBUG] Topology analysis complete: {len(topology_data.get('devices', {}))} devices")
            
            # Clear existing topology display
            for widget in self.topology_content_frame.winfo_children():
                if widget != self.topology_summary_frame:  # Keep summary frame
                    widget.destroy()
            
            # Create topology visualization
            print("[DEBUG] Creating topology visualization...")
            topology_widget = self.topology_mapper.create_topology_visualization(self.topology_content_frame)
            topology_widget.pack(fill="both", expand=True)
            
            # Update and show summary
            self.update_topology_summary()
            print("[DEBUG] Topology map auto-generated successfully")
            
        except Exception as e:
            print(f"[DEBUG] Error auto-generating topology: {e}")
    
    def generate_topology_map(self):
        """Generate and display network topology map"""
        if not hasattr(self, 'scan_results') or not self.scan_results:
            messagebox.showwarning("No Data", "Please run a network scan first!")
            return
            
        try:
            # Clear existing topology display
            for widget in self.topology_content_frame.winfo_children():
                if widget != self.topology_summary_frame:  # Keep summary frame
                    widget.destroy()
                
            # Generate topology data
            topology_data = self.topology_mapper.analyze_network_topology(self.scan_results)
            
            # Create topology visualization
            topology_widget = self.topology_mapper.create_topology_visualization(self.topology_content_frame)
            
            if topology_widget:
                topology_widget.pack(fill="both", expand=True)
                print("[DEBUG] Topology visualization created successfully")
            else:
                # Show error message if visualization failed
                error_label = ttk.Label(
                    self.topology_content_frame,
                    text="Error creating topology visualization.\nPlease check the console for details.",
                    font=("Arial", 12),
                    foreground="red"
                )
                error_label.pack(expand=True)
            
            # Update and show summary in top-left corner
            self.update_topology_summary()
            
            messagebox.showinfo("Success", "Topology map generated successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate topology map: {str(e)}")
            
            # Show error in topology area
            for widget in self.topology_content_frame.winfo_children():
                if widget != self.topology_summary_frame:
                    widget.destroy()
            error_label = ttk.Label(
                self.topology_content_frame,
                text=f"Error generating topology:\n{str(e)}",
                font=("Arial", 12),
                foreground="red"
            )
            error_label.pack(expand=True)
    
    def export_topology_data(self):
        """Export topology data to JSON file"""
        if not hasattr(self, 'scan_results') or not self.scan_results:
            messagebox.showwarning("No Data", "Please run a network scan first!")
            return
            
        try:
            topology_data = self.topology_mapper.analyze_network_topology(self.scan_results)
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                title="Export Topology Data"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(topology_data, f, indent=2, default=str)
                messagebox.showinfo("Success", f"Topology data exported to {filename}")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export topology data: {str(e)}")
    
    def update_topology_summary(self):
        """Update the topology summary display in the top-left corner"""
        try:
            summary = self.topology_mapper.get_topology_summary()
            
            # Clear existing text
            self.topology_summary_text.config(state=tk.NORMAL)
            self.topology_summary_text.delete(1.0, tk.END)
            
            # Format summary for compact display
            summary_text = ""
            for key, value in summary.items():
                # Shorten key names for compact display
                short_key = key.replace("Total ", "").replace("Network ", "").replace("Device ", "")
                if isinstance(value, dict):
                    # For nested dictionaries (like device roles), show count
                    summary_text += f"{short_key}: {len(value)}\n"
                else:
                    summary_text += f"{short_key}: {value}\n"
                    
            self.topology_summary_text.insert(tk.END, summary_text.strip())
            self.topology_summary_text.config(state=tk.DISABLED)
            
            # Show the summary frame
            self.topology_summary_frame.place(x=10, y=10, width=250, height=150)
            
        except Exception as e:
            print(f"Error updating topology summary: {e}")
    
    def show_topology_summary(self):
        """Show topology summary in a popup window"""
        if not hasattr(self, 'scan_results') or not self.scan_results:
            messagebox.showwarning("No Data", "Please run a network scan first!")
            return
            
        try:
            topology_data = self.topology_mapper.analyze_network_topology(self.scan_results)
            summary = self.topology_mapper.get_topology_summary()
            
            # Create summary window
            summary_window = tk.Toplevel(self.root)
            summary_window.title("Network Topology Summary")
            summary_window.geometry("500x400")
            
            text_widget = scrolledtext.ScrolledText(summary_window, wrap=tk.WORD, padx=10, pady=10)
            text_widget.pack(fill="both", expand=True, padx=10, pady=10)
            
            # Format summary
            summary_text = "Network Topology Summary\n"
            summary_text += "=" * 30 + "\n\n"
            for key, value in summary.items():
                summary_text += f"{key}: {value}\n"
                
            text_widget.insert(tk.END, summary_text)
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate topology summary: {str(e)}")
    
    def _on_filter_change(self, filter_value: str):
        """Handle filter changes in results tab"""
        # Apply filter to results display
        self.results_tab.filter_results(filter_value)
    
    def switch_to_results_tab(self):
        """Switch to the results tab"""
        self.notebook.select(1)  # Results tab is index 1
    
    def show_host_details(self, host_ip: str):
        """Show detailed information for a host"""
        host_data = self.scan_controller.get_host_details(host_ip)
        if host_data:
            details = self._format_host_details(host_ip, host_data)
            self.results_tab.update_host_details(host_ip, details)
    
    def _format_host_details(self, host_ip: str, host_data: Dict[str, Any]) -> str:
        """Format host details for display"""
        details = [f"Host Details: {host_ip}"]
        details.append("=" * 50)
        
        # Basic information
        details.append(f"Hostname: {host_data.get('hostname', 'Unknown')}")
        details.append(f"MAC Address: {host_data.get('mac_address', 'Unknown')}")
        details.append(f"Device Type: {host_data.get('device_type', 'Unknown')}")
        details.append(f"Risk Level: {host_data.get('risk_level', 'Unknown')}")
        details.append("")
        
        # Open ports
        open_ports = host_data.get('open_ports', [])
        details.append(f"Open Ports ({len(open_ports)}):")
        for port in open_ports:
            details.append(f"  - {port}")
        details.append("")
        
        # Services
        services = host_data.get('services', {})
        if services:
            details.append("Services:")
            for port, service_info in services.items():
                if isinstance(service_info, dict):
                    service_name = service_info.get('service', 'Unknown')
                    version = service_info.get('version', '')
                    details.append(f"  - Port {port}: {service_name} {version}")
                else:
                    details.append(f"  - Port {port}: {service_info}")
            details.append("")
        
        # Vulnerabilities
        vulnerabilities = host_data.get('vulnerabilities', [])
        if vulnerabilities:
            details.append("Vulnerabilities:")
            for vuln in vulnerabilities:
                if isinstance(vuln, dict):
                    details.append(f"  - {vuln.get('description', 'Unknown vulnerability')}")
                else:
                    details.append(f"  - {vuln}")
        
        return "\\n".join(details)
    
    def export_results(self, format_type: str):
        """Export scan results"""
        success = self.scan_controller.export_results(format_type)
        if success:
            messagebox.showinfo("Export Complete", f"Results exported successfully as {format_type.upper()}")
        else:
            messagebox.showerror("Export Error", "Failed to export results")
    
    def generate_report(self):
        """Generate a detailed report"""
        success = self.scan_controller.generate_report()
        if success:
            messagebox.showinfo("Report Generated", "Detailed report generated successfully")
        else:
            messagebox.showerror("Report Error", "Failed to generate report")
    
    def export_host_data(self, host_ip: str):
        """Export data for a specific host"""
        host_data = self.scan_controller.get_host_details(host_ip)
        if host_data:
            # Create a simple export (could be enhanced)
            filename = f"host_{host_ip.replace('.', '_')}_data.json"
            try:
                with open(filename, 'w') as f:
                    json.dump({host_ip: host_data}, f, indent=2, default=str)
                messagebox.showinfo("Export Complete", f"Host data exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export host data: {e}")
    
    def _start_traffic_monitoring(self):
        """Start traffic monitoring with enhanced UI feedback"""
        try:
            interface = self.interface_var.get() if self.interface_var.get() != "auto-detect" else None
            duration = int(self.duration_var.get())
            
            # Update traffic analyzer settings
            self.traffic_analyzer.interface = interface
            self.traffic_analyzer.capture_duration = duration
            
            # Start monitoring
            if self.traffic_analyzer.start_monitoring():
                self.monitoring_status_label.config(text="Running", foreground="green")
                self.start_monitoring_btn.config(state="disabled")
                self.stop_monitoring_btn.config(state="normal")
                
                # Start periodic updates
                self._update_traffic_display()
                
                self.traffic_results_text.insert(tk.END, f"Traffic monitoring started on interface: {interface or 'auto-detect'}\n")
                self.traffic_results_text.insert(tk.END, f"Capture duration: {duration} seconds\n")
                self.traffic_results_text.insert(tk.END, "Monitoring for network anomalies...\n\n")
                self.traffic_results_text.see(tk.END)
                
                messagebox.showinfo("Traffic Monitoring", "Traffic monitoring started successfully")
            else:
                self.traffic_results_text.insert(tk.END, "Failed to start traffic monitoring. Check if Scapy is installed.\n")
                self.traffic_results_text.see(tk.END)
                messagebox.showerror("Traffic Monitoring", "Failed to start traffic monitoring")
                
        except ValueError:
            self.traffic_results_text.insert(tk.END, "Error: Invalid duration value\n")
            self.traffic_results_text.see(tk.END)
            messagebox.showerror("Traffic Monitoring", "Invalid duration value")
        except Exception as e:
            self.traffic_results_text.insert(tk.END, f"Error starting monitoring: {e}\n")
            self.traffic_results_text.see(tk.END)
            messagebox.showerror("Traffic Monitoring", f"Error: {e}")

    def _stop_traffic_monitoring(self):
        """Stop traffic monitoring with UI updates"""
        try:
            self.traffic_analyzer.stop_traffic_monitoring()
            self.monitoring_status_label.config(text="Stopped", foreground="red")
            self.start_monitoring_btn.config(state="normal")
            self.stop_monitoring_btn.config(state="disabled")
            
            self.traffic_results_text.insert(tk.END, "Traffic monitoring stopped.\n\n")
            self.traffic_results_text.see(tk.END)
            
            # Display final summary
            summary = self.traffic_analyzer.get_traffic_summary()
            self._display_traffic_summary(summary)
            
            messagebox.showinfo("Traffic Monitoring", "Traffic monitoring stopped")
        except Exception as e:
            messagebox.showerror("Traffic Monitoring", f"Error stopping monitoring: {e}")

    def _update_traffic_display(self):
        """Update traffic monitoring display periodically"""
        if self.traffic_analyzer.is_monitoring:
            try:
                summary = self.traffic_analyzer.get_traffic_summary()
                
                # Update status labels
                self.packets_captured_label.config(text=str(summary['total_packets']))
                self.anomalies_detected_label.config(text=str(summary['anomalies']['total']))
                
                # Schedule next update only if window still exists
                if self.root and self.root.winfo_exists():
                    self.root.after(5000, self._update_traffic_display)  # Update every 5 seconds
            except Exception as e:
                print(f"Error updating traffic display: {e}")

    def _display_traffic_summary(self, summary):
        """Display traffic monitoring summary"""
        try:
            self.traffic_results_text.insert(tk.END, "\n--- TRAFFIC MONITORING SUMMARY ---\n")
            self.traffic_results_text.insert(tk.END, f"Total Packets: {summary['total_packets']}\n")
            self.traffic_results_text.insert(tk.END, f"Active Connections: {summary['connection_count']}\n")
            self.traffic_results_text.insert(tk.END, f"Anomalies Detected: {summary['anomalies']['total']}\n")
            
            if summary['protocol_distribution']:
                self.traffic_results_text.insert(tk.END, "\nProtocol Distribution:\n")
                for protocol, stats in summary['protocol_distribution'].items():
                    self.traffic_results_text.insert(tk.END, f"  {protocol}: {stats['packet_count']} packets\n")
            
            if summary['top_talkers']:
                self.traffic_results_text.insert(tk.END, "\nTop Traffic Sources:\n")
                for talker in summary['top_talkers'][:5]:
                    self.traffic_results_text.insert(tk.END, f"  {talker['ip']}: {talker['packet_count']} packets\n")
            
            self.traffic_results_text.insert(tk.END, "\n")
            self.traffic_results_text.see(tk.END)
        except Exception as e:
            print(f"Error displaying traffic summary: {e}")

    def _export_traffic_data(self):
        """Export traffic monitoring data"""
        try:
            summary = self.traffic_analyzer.get_traffic_summary()
            if summary['total_packets'] == 0:
                messagebox.showwarning("Export", "No traffic data to export")
                return
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(summary, f, indent=2, default=str)
                messagebox.showinfo("Export", f"Traffic data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {e}")

    def _generate_traffic_report(self):
        """Generate traffic monitoring report"""
        try:
            report = self.traffic_analyzer.generate_traffic_report()
            
            # Display report in results area
            self.traffic_results_text.insert(tk.END, "\n" + "="*60 + "\n")
            self.traffic_results_text.insert(tk.END, report)
            self.traffic_results_text.insert(tk.END, "\n" + "="*60 + "\n")
            self.traffic_results_text.see(tk.END)
            
            messagebox.showinfo("Report", "Traffic report generated and displayed")
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {e}")
    
    def _on_closing(self):
        """Handle application closing"""
        # Stop any running scans
        self.scan_controller.stop_scan()
        
        # Cleanup resources
        self.scan_controller.cleanup()
        
        # Stop traffic monitoring if running
        try:
            self.traffic_analyzer.stop_traffic_monitoring()
        except:
            pass
        
        # Close the application
        self.root.destroy()


def main():
    """Main entry point"""
    root = tk.Tk()
    app = NetworkMapperGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()