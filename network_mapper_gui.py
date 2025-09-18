#!/usr/bin/env python3
"""
Network Mapper Desktop GUI Application

A professional desktop GUI for the Network Mapper tool using Tkinter.
Integrates with network_mapper_refactored.py for core functionality.

Author: Gustavo Valente
Version: 1.0 - Phase 1 (Desktop GUI Implementation)
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import json
import time
from datetime import datetime
import os
import sys
from pathlib import Path
from queue import Queue, Empty

# Import the refactored network mapper
from network_mapper_refactored import NetworkMapper
from modules.secure_config import SecurityLevel
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.topology_mapper import NetworkTopologyMapper
from modules.traffic_analyzer import TrafficAnalyzer
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend to avoid threading issues
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from datetime import datetime
class NetworkMapperGUI:
    """Main GUI Application Class"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Network Mapper - Professional Security Scanner")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Configure main window grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        # Load configuration flags
        self.load_flag_config()
        
        # Configure style
        self.setup_styles()
        
        # Initialize variables
        self.current_scan = None
        self.scan_thread = None
        self.scan_results = {}
        self.scan_status = {
            'running': False,
            'progress': 0,
            'current_host': '',
            'total_hosts': 0,
            'completed_hosts': 0,
            'start_time': None,
            'error': None
        }
        
        # Queue for thread communication
        self.update_queue = Queue()
        self.topology_mapper = NetworkTopologyMapper()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.traffic_analyzer = TrafficAnalyzer()
        
        # Create GUI components
        self.create_widgets()
        
        # Start update checker
        self.check_updates()
        
    def load_flag_config(self):
        """Load flag configuration from default_flags.json"""
        try:
            config_path = Path("config/default_flags.json")
            if config_path.exists():
                with open(config_path, 'r') as f:
                    self.flag_config = json.load(f)
            else:
                # Default configuration if file doesn't exist
                self.flag_config = {
                    "feature_flags": {
                        "ping_only": {"enabled": False, "description": "Only perform ping sweep"},
                        "nmap": {"enabled": False, "description": "Use nmap for advanced scanning"},
                        "smart_filter": {"enabled": True, "description": "Enable smart filtering"},
                        "vuln_report": {"enabled": True, "description": "Generate vulnerability report"},
                        "incremental": {"enabled": False, "description": "Enable incremental export"}
                    },
                    "security_options": {
                        "enable_security_logging": {"enabled": False, "description": "Enable security logging"},
                        "rate_limiting": {"enabled": False, "description": "Enable rate limiting"}
                    },
                    "output_options": {
                        "auto_export": {"enabled": False, "description": "Auto export results"}
                    }
                }
        except Exception as e:
            print(f"Error loading flag config: {e}")
            # Use default configuration
            self.flag_config = {
                "feature_flags": {
                    "ping_only": {"enabled": False, "description": "Only perform ping sweep"},
                    "nmap": {"enabled": False, "description": "Use nmap for advanced scanning"},
                    "smart_filter": {"enabled": True, "description": "Enable smart filtering"},
                    "vuln_report": {"enabled": True, "description": "Generate vulnerability report"},
                    "incremental": {"enabled": False, "description": "Enable incremental export"}
                },
                "security_options": {
                    "enable_security_logging": {"enabled": False, "description": "Enable security logging"},
                    "rate_limiting": {"enabled": False, "description": "Enable rate limiting"}
                },
                "output_options": {
                    "auto_export": {"enabled": False, "description": "Auto export results"}
                }
            }
        
    def setup_styles(self):
        """Configure ttk styles for professional appearance"""
        style = ttk.Style()
        
        # Configure colors and fonts
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Heading.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 10))
        style.configure('Success.TLabel', foreground='green', font=('Arial', 10, 'bold'))
        style.configure('Error.TLabel', foreground='red', font=('Arial', 10, 'bold'))
        style.configure('Warning.TLabel', foreground='orange', font=('Arial', 10, 'bold'))
        
    def create_widgets(self):
        """Create and layout all GUI widgets"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create main tabs
        self.scan_frame = ttk.Frame(self.notebook)
        self.topology_frame = ttk.Frame(self.notebook)
        self.results_frame = ttk.Frame(self.notebook)
        self.traffic_frame = ttk.Frame(self.notebook)
        
        self.notebook.add(self.scan_frame, text="Network Scan")
        self.notebook.add(self.topology_frame, text="Topology Map")
        self.notebook.add(self.results_frame, text="Scan Results")
        self.notebook.add(self.traffic_frame, text="Traffic Analysis")
        
        # Setup each tab
        self.setup_scan_tab()
        self.setup_topology_tab()
        self.setup_results_tab()
        self.setup_traffic_tab()
        
    def setup_scan_tab(self):
        """Setup the main scan tab"""
        print("DEBUG: Setting up scan tab...")
        # Main container
        main_frame = ttk.Frame(self.scan_frame, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        print("DEBUG: Main frame created and gridded")
        
        # Configure grid weights
        self.scan_frame.columnconfigure(0, weight=1)
        self.scan_frame.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)  # This should allow row 2 (results panel) to expand
        print("DEBUG: Grid weights configured - row 2 should expand")
        
        # Title
        title_label = ttk.Label(main_frame, text="🛡️ Network Mapper - Security Scanner", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        print("DEBUG: Title label created at row 0")
        
        # Left panel - Configuration
        print("DEBUG: Creating config panel at row 1, column 0")
        self.create_config_panel(main_frame)
        
        # Right panel - Status and Results
        print("DEBUG: Creating status panel at row 1, column 1")
        self.create_status_panel(main_frame)
        
        # Bottom panel - Results viewer
        print("DEBUG: Creating results panel at row 2, columnspan 2")
        self.create_results_panel(main_frame)
        print("DEBUG: Scan tab setup completed")
        
    def create_config_panel(self, parent):
        """Create scan configuration panel"""
        config_frame = ttk.LabelFrame(parent, text="Scan Configuration", padding="10")
        config_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # Configure config frame grid
        config_frame.columnconfigure(0, weight=1)
        
        # Target Network
        ttk.Label(config_frame, text="Target Network:", style='Heading.TLabel').grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.target_var = tk.StringVar(value="192.168.1.0/24")
        target_entry = ttk.Entry(config_frame, textvariable=self.target_var, width=25)
        target_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Threads
        ttk.Label(config_frame, text="Threads:", style='Heading.TLabel').grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        self.threads_var = tk.IntVar(value=50)
        threads_spin = ttk.Spinbox(config_frame, from_=1, to=200, textvariable=self.threads_var, width=25)
        threads_spin.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Timeout
        ttk.Label(config_frame, text="Timeout (seconds):", style='Heading.TLabel').grid(row=4, column=0, sticky=tk.W, pady=(0, 5))
        self.timeout_var = tk.IntVar(value=3)
        timeout_spin = ttk.Spinbox(config_frame, from_=1, to=30, textvariable=self.timeout_var, width=25)
        timeout_spin.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Security Level
        ttk.Label(config_frame, text="Security Level:", style='Heading.TLabel').grid(row=6, column=0, sticky=tk.W, pady=(0, 5))
        self.security_var = tk.StringVar(value="STANDARD")
        security_combo = ttk.Combobox(config_frame, textvariable=self.security_var, width=22, state="readonly")
        security_combo['values'] = ('MINIMAL', 'STANDARD', 'STRICT', 'PARANOID')
        security_combo.grid(row=7, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Smart Filter
        self.smart_filter_var = tk.BooleanVar(value=self.flag_config.get("feature_flags", {}).get("smart_filter", {}).get("enabled", True))
        smart_check = ttk.Checkbutton(config_frame, text="Enable Smart Filtering", variable=self.smart_filter_var)
        smart_check.grid(row=8, column=0, sticky=tk.W, pady=(0, 5))
        
        # Show Only Active Hosts Filter
        self.show_active_only_var = tk.BooleanVar(value=False)
        active_check = ttk.Checkbutton(config_frame, text="Show Only Hosts with Open Ports", 
                                     variable=self.show_active_only_var,
                                     command=self.on_filter_change)
        active_check.grid(row=9, column=0, sticky=tk.W, pady=(0, 5))
        
        # Feature Flags Section
        flags_label = ttk.Label(config_frame, text="Feature Flags:", style='Heading.TLabel')
        flags_label.grid(row=10, column=0, sticky=tk.W, pady=(10, 5))
        
        # Ping Only
        self.ping_only_var = tk.BooleanVar(value=self.flag_config.get("feature_flags", {}).get("ping_only", {}).get("enabled", False))
        ping_check = ttk.Checkbutton(config_frame, text="Ping Only (Skip Port Scanning)", variable=self.ping_only_var)
        ping_check.grid(row=11, column=0, sticky=tk.W, pady=(0, 2))
        
        # Nmap
        self.nmap_var = tk.BooleanVar(value=self.flag_config.get("feature_flags", {}).get("nmap", {}).get("enabled", False))
        nmap_check = ttk.Checkbutton(config_frame, text="Use Nmap for Advanced Scanning", variable=self.nmap_var)
        nmap_check.grid(row=12, column=0, sticky=tk.W, pady=(0, 2))
        
        # Vulnerability Report
        self.vuln_report_var = tk.BooleanVar(value=self.flag_config.get("feature_flags", {}).get("vuln_report", {}).get("enabled", True))
        vuln_check = ttk.Checkbutton(config_frame, text="Generate Vulnerability Report", variable=self.vuln_report_var)
        vuln_check.grid(row=13, column=0, sticky=tk.W, pady=(0, 2))
        
        # Incremental Export
        self.incremental_var = tk.BooleanVar(value=self.flag_config.get("feature_flags", {}).get("incremental", {}).get("enabled", False))
        incremental_check = ttk.Checkbutton(config_frame, text="Enable Incremental Export", variable=self.incremental_var)
        incremental_check.grid(row=14, column=0, sticky=tk.W, pady=(0, 2))
        
        # Security Options Section
        security_label = ttk.Label(config_frame, text="Security Options:", style='Heading.TLabel')
        security_label.grid(row=15, column=0, sticky=tk.W, pady=(10, 5))
        
        # Security Logging
        self.security_logging_var = tk.BooleanVar(value=self.flag_config.get("security_options", {}).get("enable_security_logging", {}).get("enabled", False))
        security_logging_check = ttk.Checkbutton(config_frame, text="Enable Security Logging", variable=self.security_logging_var)
        security_logging_check.grid(row=16, column=0, sticky=tk.W, pady=(0, 2))
        
        # Rate Limiting
        self.rate_limiting_var = tk.BooleanVar(value=self.flag_config.get("security_options", {}).get("rate_limiting", {}).get("enabled", False))
        rate_limiting_check = ttk.Checkbutton(config_frame, text="Enable Rate Limiting", variable=self.rate_limiting_var)
        rate_limiting_check.grid(row=17, column=0, sticky=tk.W, pady=(0, 2))
        
        # Output Options Section
        output_label = ttk.Label(config_frame, text="Output Options:", style='Heading.TLabel')
        output_label.grid(row=18, column=0, sticky=tk.W, pady=(10, 5))
        
        # Auto Export
        self.auto_export_var = tk.BooleanVar(value=self.flag_config.get("output_options", {}).get("auto_export", {}).get("enabled", False))
        auto_export_check = ttk.Checkbutton(config_frame, text="Auto Export Results", variable=self.auto_export_var)
        auto_export_check.grid(row=19, column=0, sticky=tk.W, pady=(0, 15))
        
        # Buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=20, column=0, sticky=(tk.W, tk.E))
        
        self.start_button = ttk.Button(button_frame, text="🚀 Start Scan", command=self.start_scan)
        self.start_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_button = ttk.Button(button_frame, text="⏹️ Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)
        
        config_frame.columnconfigure(0, weight=1)
        
    def create_status_panel(self, parent):
        """Create status monitoring panel"""
        status_frame = ttk.LabelFrame(parent, text="Scan Status", padding="10")
        status_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure status frame grid
        status_frame.columnconfigure(0, weight=1)
        
        # Status indicators
        self.status_label = ttk.Label(status_frame, text="Ready", style='Status.TLabel')
        self.status_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        
        # Progress bar
        ttk.Label(status_frame, text="Overall Progress:", style='Heading.TLabel').grid(row=1, column=0, sticky=tk.W, pady=(0, 5))
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Statistics
        stats_frame = ttk.Frame(status_frame)
        stats_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(stats_frame, text="Hosts Discovered:", style='Heading.TLabel').grid(row=0, column=0, sticky=tk.W)
        self.hosts_discovered_label = ttk.Label(stats_frame, text="0", style='Status.TLabel')
        self.hosts_discovered_label.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(stats_frame, text="Hosts Scanned:", style='Heading.TLabel').grid(row=1, column=0, sticky=tk.W)
        self.hosts_scanned_label = ttk.Label(stats_frame, text="0", style='Status.TLabel')
        self.hosts_scanned_label.grid(row=1, column=1, sticky=tk.W, padx=(10, 0))
        
        ttk.Label(stats_frame, text="Current Host:", style='Heading.TLabel').grid(row=2, column=0, sticky=tk.W)
        self.current_host_label = ttk.Label(stats_frame, text="-", style='Status.TLabel')
        self.current_host_label.grid(row=2, column=1, sticky=tk.W, padx=(10, 0))
        
        status_frame.columnconfigure(0, weight=1)
        
    def create_main_results_tree(self, parent):
        """Create the main results tree view for the results tab"""
        print("DEBUG: Creating main results tree in results tab...")
        results_frame = ttk.LabelFrame(parent, text="Scan Results", padding="10")
        results_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        print(f"DEBUG: Results frame created and gridded in results tab")
        
        # Create Treeview for results
        columns = ('Host', 'Hostname', 'MAC Address', 'Device Type', 'Open Ports', 'Risk Level')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=20)
        print(f"DEBUG: Treeview created with columns: {columns}")
        
        # Configure columns
        self.results_tree.heading('Host', text='IP Address')
        self.results_tree.heading('Hostname', text='Hostname')
        self.results_tree.heading('MAC Address', text='MAC Address')
        self.results_tree.heading('Device Type', text='Device Type')
        self.results_tree.heading('Open Ports', text='Open Ports')
        self.results_tree.heading('Risk Level', text='Risk Level')
        
        # Column widths
        self.results_tree.column('Host', width=120)
        self.results_tree.column('Hostname', width=150)
        self.results_tree.column('MAC Address', width=140)
        self.results_tree.column('Device Type', width=120)
        self.results_tree.column('Open Ports', width=200)
        self.results_tree.column('Risk Level', width=100)
        print("DEBUG: Treeview columns configured")
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.results_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        print("DEBUG: Treeview and scrollbars gridded")
        
        # Configure grid weights
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        print("DEBUG: Grid weights configured")
        
        # Bind double-click for detailed view
        self.results_tree.bind('<Double-1>', self.show_host_details)
        
        # Export button
        export_frame = ttk.Frame(results_frame)
        export_frame.grid(row=2, column=0, columnspan=2, pady=(10, 0))
        
        self.export_button = ttk.Button(export_frame, text="📊 Export Results", command=self.export_results, state=tk.DISABLED)
        self.export_button.pack(side=tk.LEFT, padx=(0, 10))
        
        print("DEBUG: Main results tree creation completed")

    def create_results_panel(self, parent):
        """Create a simplified results panel for the scan tab (now just shows basic info)"""
        print("DEBUG: Creating simplified results panel for scan tab...")
        results_frame = ttk.LabelFrame(parent, text="Quick Results Preview", padding="10")
        results_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N), pady=(10, 0))
        print(f"DEBUG: Quick results frame created and gridded")
        
        # Quick summary labels
        summary_frame = ttk.Frame(results_frame)
        summary_frame.pack(fill=tk.X)
        
        ttk.Label(summary_frame, text="Hosts Found:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.quick_hosts_label = ttk.Label(summary_frame, text="0")
        self.quick_hosts_label.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        ttk.Label(summary_frame, text="High Risk:", font=('Arial', 10, 'bold')).grid(row=0, column=2, sticky=tk.W, padx=(0, 10))
        self.quick_risk_label = ttk.Label(summary_frame, text="0", foreground="red")
        self.quick_risk_label.grid(row=0, column=3, sticky=tk.W, padx=(0, 20))
        
        # View full results button
        view_button = ttk.Button(summary_frame, text="📋 View Full Results", 
                                command=lambda: self.notebook.select(self.results_frame))
        view_button.grid(row=0, column=4, sticky=tk.E, padx=(20, 0))
        
        # Configure grid weights
        summary_frame.columnconfigure(4, weight=1)
        
        print("DEBUG: Simplified results panel creation completed")
        
    def start_scan(self):
        """Start network scan in background thread"""
        if self.scan_status['running']:
            messagebox.showwarning("Scan Running", "A scan is already in progress!")
            return
            
        # Validate inputs
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Invalid Input", "Please enter a target network!")
            return
            
        try:
            threads = self.threads_var.get()
            timeout = self.timeout_var.get()
            security_level = getattr(SecurityLevel, self.security_var.get())
            smart_filter = self.smart_filter_var.get()
            
            # Collect flag values
            flags = {
                'ping_only': self.ping_only_var.get(),
                'nmap': self.nmap_var.get(),
                'vuln_report': self.vuln_report_var.get(),
                'incremental': self.incremental_var.get(),
                'security_logging': self.security_logging_var.get(),
                'rate_limiting': self.rate_limiting_var.get(),
                'auto_export': self.auto_export_var.get()
            }
            
            # Clear previous results
            self.scan_results.clear()
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
                
            # Update UI state
            self.scan_status.update({
                'running': True,
                'progress': 0,
                'current_host': '',
                'total_hosts': 0,
                'completed_hosts': 0,
                'start_time': datetime.now(),
                'error': None
            })
            
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.export_button.config(state=tk.DISABLED)
            self.status_label.config(text="🔄 Initializing scan...", style='Status.TLabel')
            
            # Start scan thread
            self.scan_thread = threading.Thread(
                target=self.run_scan,
                args=(target, threads, timeout, security_level, smart_filter, flags),
                daemon=True
            )
            self.scan_thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start scan: {str(e)}")
            self.reset_ui_state()
            
    def run_scan(self, target, threads, timeout, security_level, smart_filter, flags):
        """Run network scan in background thread"""
        try:
            # Initialize NetworkMapper
            self.update_queue.put(('status', 'Initializing NetworkMapper...'))
            
            # Create a custom NetworkMapper that doesn't set up signal handlers
            self.current_scan = self.create_thread_safe_mapper(
                target, threads, timeout, security_level, smart_filter, flags
            )
            
            # Ping sweep
            self.update_queue.put(('status', 'Discovering hosts...'))
            discovered_hosts = self.current_scan.ping_sweep()
            
            if not discovered_hosts:
                self.update_queue.put(('error', 'No hosts discovered in the target network'))
                return
                
            self.update_queue.put(('hosts_discovered', len(discovered_hosts)))
            self.update_queue.put(('status', f'Found {len(discovered_hosts)} hosts. Starting comprehensive scan...'))
            
            # Comprehensive scan
            self.current_scan.comprehensive_scan()
            
            # Get results
            results = self.current_scan.get_scan_results()
            self.update_queue.put(('results', results))
            
            # Generate topology data for visualization
            try:
                self.topology_mapper.analyze_network_topology(results)
            except Exception as e:
                print(f"Warning: Could not generate topology data: {e}")
            
            # Perform enhanced vulnerability assessment
            try:
                for host, data in results.items():
                    # Debug: Check data type and structure
                    if not isinstance(data, dict):
                        print(f"Warning: Host {host} has non-dict data: {type(data)} - {data}")
                        continue
                    
                    # Ensure required keys exist
                    if 'open_ports' not in data or 'services' not in data:
                        print(f"Warning: Host {host} missing required keys: {list(data.keys())}")
                        continue
                        
                    open_ports = data.get('open_ports', [])
                    service_info = data.get('services', {})
                    
                    # Enhanced vulnerability scan with CVE scoring
                    vuln_assessment = self.vulnerability_scanner.scan_host_vulnerabilities(
                        host, open_ports, service_info
                    )
                    
                    # Store vulnerability data
                    results[host]['vulnerabilities'] = vuln_assessment
                    
            except Exception as e:
                print(f"Warning: Enhanced vulnerability assessment failed: {e}")
                # Print more detailed error information
                import traceback
                print(f"Traceback: {traceback.format_exc()}")
                print(f"Results structure: {type(results)} with keys: {list(results.keys()) if isinstance(results, dict) else 'Not a dict'}")
                if isinstance(results, dict):
                    for k, v in results.items():
                        print(f"  {k}: {type(v)} - {v if not isinstance(v, dict) else list(v.keys())}")
            
            self.update_queue.put(('status', 'Scan completed successfully!'))
            self.update_queue.put(('scan_complete', True))
            
            # Auto-export results if flag is enabled
            if flags.get('auto_export', False):
                self.update_queue.put(('status', 'Auto-exporting results...'))
                self.update_queue.put(('auto_export', True))
            
        except Exception as e:
            error_msg = f'Scan failed: {str(e)}'
            print(f"ERROR in run_scan: {error_msg}")
            import traceback
            print(f"Full traceback: {traceback.format_exc()}")
            self.update_queue.put(('error', error_msg))
            
    def create_thread_safe_mapper(self, target, threads, timeout, security_level, smart_filter, flags):
        """Create a NetworkMapper instance that's safe to use in threads"""
        # Import here to avoid circular imports
        from modules.secure_config import SecureConfigManager
        from modules.input_validator import InputValidator
        from modules.security_logger import SecurityLogger
        from modules.secrets_manager import SecretsManager
        from modules.rate_limiter import RateLimiter, RateLimitConfig
        from modules.compliance_reporter import ComplianceReporter
        from modules.vulnerability_scanner import VulnerabilityScanner
        from modules.device_detector import DeviceDetector
        from modules.network_utils import NetworkUtils
        from modules.report_generator import ReportGenerator
        import time
        from datetime import datetime
        
        # Store reference to update_queue for the inner class
        update_queue = self.update_queue
        
        # Create a custom mapper class that skips signal handling
        class ThreadSafeNetworkMapper:
            def __init__(self, target_network, threads=50, timeout=3, exclude_ranges=None, smart_filter=True, security_level=SecurityLevel.STANDARD, flags=None):
                # Store flags for use throughout the scan
                self.flags = flags or {}
                
                # Initialize security components first
                self.security_config = SecureConfigManager(security_level=security_level)
                
                # Initialize DevSecOps security components
                self.input_validator = InputValidator()
                
                # Initialize security logger based on flag
                if self.flags.get('security_logging', True):
                    self.security_logger = SecurityLogger()
                else:
                    # Create a dummy logger that doesn't log
                    class DummyLogger:
                        def log_security_event(self, *args, **kwargs):
                            pass
                    self.security_logger = DummyLogger()
                
                self.secrets_manager = SecretsManager()
                
                # Create rate limiter with proper configuration, respecting rate_limiting flag
                if self.flags.get('rate_limiting', True):
                    rate_config = RateLimitConfig(
                        requests_per_second=self.security_config.config.rate_limit_per_second,
                        max_concurrent_scans=self.security_config.config.max_concurrent_scans
                    )
                    self.rate_limiter = RateLimiter(config=rate_config)
                else:
                    # Create a dummy rate limiter that doesn't limit
                    class DummyRateLimiter:
                        def start_scan(self, *args, **kwargs):
                            return True
                        def end_scan(self, *args, **kwargs):
                            pass
                    self.rate_limiter = DummyRateLimiter()
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
                
                # Skip signal handlers when running in thread
                # signal.signal(signal.SIGINT, self.signal_handler)
                # signal.signal(signal.SIGTERM, self.signal_handler)
                # atexit.register(self.cleanup_on_exit)
            
            def ping_sweep(self):
                """Perform ping sweep to discover live hosts"""
                # Check if ping_only flag is set
                if self.flags.get('ping_only', False):
                    update_queue.put(('status', 'Ping-only mode: Discovering hosts without port scanning...'))
                
                network_target = self.target_network.get('sanitized') if isinstance(self.target_network, dict) else self.target_network
                
                self.discovered_hosts = self.network_utils.ping_sweep(
                    network_target, 
                    self.exclude_ranges, 
                    self.smart_filter
                )
                return self.discovered_hosts
            
            def comprehensive_scan(self):
                """Perform comprehensive network scan with vulnerability assessment"""
                # Check if ping_only flag is set - skip comprehensive scan
                if self.flags.get('ping_only', False):
                    update_queue.put(('status', 'Ping-only mode: Skipping port scanning and vulnerability assessment'))
                    # Create basic results for discovered hosts
                    for host in self.discovered_hosts:
                        hostname = self.network_utils.get_hostname(host)
                        mac_address = self.network_utils.get_mac_address(host)
                        self.scan_results[host] = {
                            'hostname': hostname,
                            'mac_address': mac_address,
                            'device_type': 'Unknown (ping-only)',
                            'open_ports': [],
                            'services': {},
                            'scan_time': datetime.now().isoformat(),
                            'vulnerabilities': {'risk_level': 'Unknown', 'vulnerabilities': []}
                        }
                    return
                
                self.scan_start_time = time.time()
                self.report_generator.set_scan_timing(self.scan_start_time)
                
                for i, host in enumerate(self.discovered_hosts):
                    # Update progress
                    progress = (i / len(self.discovered_hosts)) * 100
                    update_queue.put(('progress', progress))
                    update_queue.put(('current_host', host))
                    update_queue.put(('hosts_scanned', i))
                    
                    # Get hostname
                    hostname = self.network_utils.get_hostname(host)
                    
                    # Get MAC address
                    mac_address = self.network_utils.get_mac_address(host)
                    
                    # Port scan
                    open_ports = self.network_utils.port_scan(host)
                    
                    # Service detection with vulnerability database
                    services = {}
                    if open_ports:
                        vuln_db = self.vulnerability_scanner.get_vulnerability_database()
                        for port in open_ports:
                            service_string = self.network_utils.service_detection(host, port, vuln_db)
                            # Parse the service string to extract service name and version
                            service_name = "unknown"
                            version = ""
                            
                            if service_string:
                                # Extract service name (before the first " - " or use the whole string)
                                if " - " in service_string:
                                    service_name = service_string.split(" - ")[0].strip()
                                    # Try to extract version info
                                    remaining = service_string.split(" - ", 1)[1]
                                    if "/" in remaining:
                                        version = remaining.split("/")[1].split()[0] if "/" in remaining else ""
                                else:
                                    service_name = service_string.strip()
                            
                            # Create proper dictionary structure expected by vulnerability scanner
                            services[port] = {
                                'service': service_name.lower(),
                                'version': version,
                                'raw_banner': service_string
                            }
                    
                    # Device type detection
                    device_type = self.device_detector.detect_device_type(host, open_ports, services, hostname)
                    
                    # Vulnerability assessment
                    if self.flags.get('vuln_report', True):
                        vulnerability_assessment = self.vulnerability_scanner.assess_vulnerabilities(host, open_ports, services)
                    else:
                        # Skip vulnerability assessment if flag is disabled
                        vulnerability_assessment = {'risk_level': 'Not Assessed', 'vulnerabilities': []}
                    
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
                    if self.flags.get('incremental', False):
                        self.report_generator.write_host_result(host, self.scan_results[host], vulnerability_assessment)
                
                # Final progress update
                update_queue.put(('progress', 100))
                update_queue.put(('hosts_scanned', len(self.discovered_hosts)))
            
            def get_scan_results(self):
                """Get scan results"""
                return self.scan_results
        
        # Create and return the thread-safe mapper
        return ThreadSafeNetworkMapper(
            target_network=target,
            threads=threads,
            timeout=timeout,
            smart_filter=smart_filter,
            security_level=security_level,
            flags=flags
        )
            
    def stop_scan(self):
        """Stop current scan"""
        if self.current_scan and hasattr(self.current_scan, 'stop_scan'):
            self.current_scan.stop_scan()
        self.update_queue.put(('status', 'Scan stopped by user'))
        self.update_queue.put(('scan_complete', False))
        
    def check_updates(self):
        """Check for updates from scan thread"""
        try:
            while True:
                update_type, data = self.update_queue.get_nowait()
                
                if update_type == 'status':
                    self.status_label.config(text=f"🔄 {data}")
                elif update_type == 'error':
                    self.status_label.config(text=f"❌ {data}", style='Error.TLabel')
                    # Clear results table on error to avoid showing stale data
                    for item in self.results_tree.get_children():
                        self.results_tree.delete(item)
                    self.scan_results.clear()
                    self.reset_ui_state()
                elif update_type == 'hosts_discovered':
                    self.scan_status['total_hosts'] = data
                    self.hosts_discovered_label.config(text=str(data))
                elif update_type == 'progress':
                    self.progress_var.set(data)
                elif update_type == 'current_host':
                    self.current_host_label.config(text=data)
                elif update_type == 'hosts_scanned':
                    self.hosts_scanned_label.config(text=str(data))
                elif update_type == 'results':
                    print(f"DEBUG: Received results update: {data}")
                    self.display_results(data)
                elif update_type == 'scan_complete':
                    if data:  # Successful completion
                        self.status_label.config(text="✅ Scan completed successfully!", style='Success.TLabel')
                    # Don't reset UI state immediately - let user see results
                    # self.reset_ui_state()  # Commented out to prevent clearing results
                    # Just reset the scan state and buttons
                    self.scan_status['running'] = False
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    self.progress_var.set(100)  # Show completion
                elif update_type == 'auto_export':
                    if data:  # Auto-export triggered
                        self.export_results()
                    
        except Empty:
            pass
            
        # Schedule next check only if window still exists
        try:
            if self.root and self.root.winfo_exists():
                self.root.after(100, self.check_updates)
        except tk.TclError:
            # Window has been destroyed, stop the timer
            pass
        
    def display_results(self, results):
        """Display scan results in the tree view"""
        print(f"DEBUG: display_results called with {len(results) if results else 0} results")
        print(f"DEBUG: Results data: {results}")
        
        self.scan_results = results
        
        # Clear existing results from tree
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        if not results:
            print("DEBUG: No results to display")
            return
        
        # Apply filtering based on toggle
        filtered_results = results
        if self.show_active_only_var.get():
            # Filter to show only hosts with open ports
            filtered_results = {host: data for host, data in results.items() 
                              if data.get('open_ports') and len(data.get('open_ports', [])) > 0}
        
        print(f"DEBUG: Filtered results: {len(filtered_results)} hosts")
        
        for host, data in filtered_results.items():
            print(f"DEBUG: Processing host {host} with data: {data}")
            
            # Format open ports
            ports_str = ', '.join(map(str, data.get('open_ports', [])))
            if len(ports_str) > 50:
                ports_str = ports_str[:47] + '...'
                
            # Get risk level
            risk_level = data.get('vulnerabilities', {}).get('risk_level', 'Unknown')
            
            # Insert into tree
            item_id = self.results_tree.insert('', tk.END, values=(
                host,
                data.get('hostname', 'Unknown'),
                data.get('mac_address', 'Unknown'),
                data.get('device_type', 'Unknown'),
                ports_str,
                risk_level
            ))
            print(f"DEBUG: Inserted item {item_id} for host {host}")
            
        print(f"DEBUG: Tree now has {len(self.results_tree.get_children())} items")
        print(f"DEBUG: Tree widget visibility: {self.results_tree.winfo_viewable()}")
        print(f"DEBUG: Tree widget mapped: {self.results_tree.winfo_ismapped()}")
        print(f"DEBUG: Tree widget geometry: {self.results_tree.winfo_geometry()}")
        
        # Force tree update
        self.results_tree.update_idletasks()
        print(f"DEBUG: Forced tree update completed")
        self.export_button.config(state=tk.NORMAL)
        
        # Update summary statistics in both quick preview and detailed results tab
        total_hosts = len(filtered_results)
        high_risk_count = sum(1 for data in filtered_results.values() 
                             if data.get('vulnerabilities', {}).get('risk_level') == 'High')
        total_ports = sum(len(data.get('open_ports', [])) for data in filtered_results.values())
        
        # Update quick preview (scan tab)
        if hasattr(self, 'quick_hosts_label'):
            self.quick_hosts_label.config(text=str(total_hosts))
        if hasattr(self, 'quick_risk_label'):
            self.quick_risk_label.config(text=str(high_risk_count))
            
        # Update detailed summary (results tab)
        if hasattr(self, 'total_hosts_label'):
            self.total_hosts_label.config(text=str(total_hosts))
        if hasattr(self, 'high_risk_label'):
            self.high_risk_label.config(text=str(high_risk_count))
        if hasattr(self, 'open_ports_label'):
            self.open_ports_label.config(text=str(total_ports))
        
        # Auto-switch to results tab when scan completes
        if total_hosts > 0:
            self.notebook.select(self.results_frame)
        
        # Update results tab display
        self.update_results_display()
        
    def update_results_display(self):
        """Update the results display with enhanced vulnerability information"""
        if not self.scan_results:
            return
        
        # Apply filtering based on toggle
        filtered_results = self.scan_results
        if self.show_active_only_var.get():
            # Filter to show only hosts with open ports
            filtered_results = {host: data for host, data in self.scan_results.items() 
                              if data.get('open_ports') and len(data.get('open_ports', [])) > 0}
            
        # Update summary statistics
        total_hosts = len(filtered_results)
        high_risk_count = sum(1 for data in filtered_results.values() 
                             if data.get('vulnerabilities', {}).get('risk_level') in ['High', 'Critical'])
        total_open_ports = sum(len(data.get('open_ports', [])) for data in filtered_results.values())
        critical_vulns = sum(len([v for v in data.get('vulnerabilities', {}).get('vulnerabilities', []) 
                                 if v.get('severity') == 'Critical']) for data in filtered_results.values())
        
        self.total_hosts_label.config(text=str(total_hosts))
        self.high_risk_label.config(text=str(high_risk_count))
        self.open_ports_label.config(text=str(total_open_ports))
        
        # Update the results tree (detailed results are shown in the results tab)
        # Clear existing items in results tree
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        if not filtered_results:
            # No results to display in tree
            return
        
        # Populate the results tree with scan data
        for host, data in filtered_results.items():
            # Prepare display values
            hostname = data.get('hostname', 'Unknown')
            mac_address = data.get('mac_address', 'Unknown')
            device_type = data.get('device_type', 'Unknown')
            open_ports = ', '.join(map(str, data.get('open_ports', []))) or 'None'
            
            # Get risk level from vulnerability data
            vuln_info = data.get('vulnerabilities', {})
            risk_level = vuln_info.get('risk_level', 'Unknown')
            
            # Insert into tree
            self.results_tree.insert('', 'end', values=(
                host, hostname, mac_address, device_type, open_ports, risk_level
            ))
        
    def show_host_details(self, event):
        """Show detailed information for selected host"""
        selection = self.results_tree.selection()
        if not selection:
            return
            
        item = self.results_tree.item(selection[0])
        host_ip = item['values'][0]
        
        if host_ip in self.scan_results:
            self.show_host_detail_window(host_ip, self.scan_results[host_ip])
            
    def show_host_detail_window(self, host_ip, host_data):
        """Show detailed host information in new window"""
        detail_window = tk.Toplevel(self.root)
        detail_window.title(f"Host Details - {host_ip}")
        detail_window.geometry("600x500")
        
        # Create scrolled text widget
        text_widget = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD, padx=10, pady=10)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Format and display host information
        details = f"Host Information: {host_ip}\n"
        details += "=" * 50 + "\n\n"
        details += f"Hostname: {host_data.get('hostname', 'Unknown')}\n"
        details += f"MAC Address: {host_data.get('mac_address', 'Unknown')}\n"
        details += f"Device Type: {host_data.get('device_type', 'Unknown')}\n"
        details += f"Scan Time: {host_data.get('scan_time', 'Unknown')}\n\n"
        
        # Open ports and services
        details += "Open Ports and Services:\n"
        details += "-" * 30 + "\n"
        open_ports = host_data.get('open_ports', [])
        services = host_data.get('services', {})
        
        if open_ports:
            for port in open_ports:
                service = services.get(port, 'Unknown')
                details += f"Port {port}: {service}\n"
        else:
            details += "No open ports detected\n"
            
        # Vulnerability information
        vuln_data = host_data.get('vulnerabilities', {})
        if vuln_data:
            details += f"\nVulnerability Assessment:\n"
            details += "-" * 30 + "\n"
            details += f"Risk Level: {vuln_data.get('risk_level', 'Unknown')}\n"
            details += f"Summary: {vuln_data.get('summary', 'No summary available')}\n"
            
            vulnerabilities = vuln_data.get('vulnerabilities', [])
            if vulnerabilities:
                details += f"\nDetailed Vulnerabilities:\n"
                for i, vuln in enumerate(vulnerabilities, 1):
                    details += f"{i}. {vuln}\n"
                    
        text_widget.insert(tk.END, details)
        text_widget.config(state=tk.DISABLED)
        
    def export_results(self):
        """Export scan results with format selection"""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export!")
            return
        
        # Apply the same filtering as the display
        results_to_export = self.scan_results
        if self.show_active_only_var.get():
            results_to_export = {host: data for host, data in self.scan_results.items() 
                               if data.get('open_ports') and len(data.get('open_ports', [])) > 0}
            
        if not results_to_export:
            messagebox.showwarning("No Results", "No hosts with open ports to export!")
            return
        
        # Create format selection dialog
        format_dialog = tk.Toplevel(self.root)
        format_dialog.title("Export Format Selection")
        format_dialog.geometry("450x400")
        format_dialog.transient(self.root)
        format_dialog.grab_set()
        
        # Center the dialog
        format_dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        # Format selection frame
        format_frame = ttk.LabelFrame(format_dialog, text="Select Export Format", padding="10")
        format_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Format variable
        format_var = tk.StringVar(value="json")
        
        # Format options
        formats = [
            ("JSON", "json", "Standard JSON format for data interchange"),
            ("CSV", "csv", "Excel-compatible CSV format"),
            ("PDF Report", "pdf", "Professional PDF security report"),
            ("HTML Report", "html", "Web-based security report")
        ]
        
        for i, (name, value, description) in enumerate(formats):
            frame = ttk.Frame(format_frame)
            frame.pack(fill=tk.X, pady=2)
            
            radio = ttk.Radiobutton(frame, text=name, variable=format_var, value=value)
            radio.pack(side=tk.LEFT)
            
            desc_label = ttk.Label(frame, text=description, font=('Arial', 8), foreground='gray')
            desc_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # PDF Template selection frame (initially hidden)
        template_frame = ttk.LabelFrame(format_dialog, text="PDF Template Options", padding="10")
        template_var = tk.StringVar(value="both")
        
        template_options = [
            ("Executive Summary", "executive", "Management-focused report with high-level overview"),
            ("Technical Details", "technical", "Detailed technical analysis for security teams"),
            ("Both Reports", "both", "Generate both executive and technical reports")
        ]
        
        for name, value, description in template_options:
            frame = ttk.Frame(template_frame)
            frame.pack(fill=tk.X, pady=2)
            
            radio = ttk.Radiobutton(frame, text=name, variable=template_var, value=value)
            radio.pack(side=tk.LEFT)
            
            desc_label = ttk.Label(frame, text=description, font=('Arial', 8), foreground='gray')
            desc_label.pack(side=tk.LEFT, padx=(10, 0))
        
        def on_format_change(*args):
            """Show/hide template options based on format selection"""
            if format_var.get() == "pdf":
                template_frame.pack(fill=tk.X, padx=10, pady=(0, 10), after=format_frame)
            else:
                template_frame.pack_forget()
        
        # Bind format change event
        format_var.trace('w', on_format_change)
        
        # Buttons frame
        button_frame = ttk.Frame(format_dialog)
        button_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        def export_with_format():
            selected_format = format_var.get()
            template_type = template_var.get() if selected_format == "pdf" else None
            format_dialog.destroy()
            self._perform_export(results_to_export, selected_format, template_type)
        
        def cancel_export():
            format_dialog.destroy()
        
        ttk.Button(button_frame, text="Export", command=export_with_format).pack(side=tk.RIGHT, padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=cancel_export).pack(side=tk.RIGHT)
    
    def _perform_export(self, results_to_export, format_type, template_type=None):
        """Perform the actual export based on selected format"""
        try:
            if format_type == "html":
                # Use existing HTML report generation
                self._export_html_report(results_to_export)
            elif format_type in ["json", "csv", "pdf"]:
                # Use report generator for other formats
                self._export_with_report_generator(results_to_export, format_type, template_type)
            else:
                messagebox.showerror("Error", f"Unsupported format: {format_type}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Failed to export results: {str(e)}")
    
    def _export_html_report(self, results_to_export):
        """Export HTML report using existing functionality"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            title="Export HTML Report"
        )
        
        if filename:
            html_content = self.create_html_report()
            with open(filename, 'w') as f:
                f.write(html_content)
            messagebox.showinfo("Export Successful", f"HTML report exported to {filename}")
    
    def _export_with_report_generator(self, results_to_export, format_type, template_type=None):
        """Export using the report generator module"""
        from modules.report_generator import ReportGenerator
        
        # File extension mapping
        extensions = {
            "json": ".json",
            "csv": ".csv", 
            "pdf": ".pdf"
        }
        
        # File type mapping for dialog
        filetypes = {
            "json": [("JSON files", "*.json"), ("All files", "*.*")],
            "csv": [("CSV files", "*.csv"), ("All files", "*.*")],
            "pdf": [("PDF files", "*.pdf"), ("All files", "*.*")]
        }
        
        # Generate filename based on template type for PDF
        if format_type == "pdf" and template_type:
            if template_type == "executive":
                default_name = "network_scan_executive.pdf"
            elif template_type == "technical":
                default_name = "network_scan_technical.pdf"
            else:  # both
                default_name = "network_scan_reports.pdf"
        else:
            default_name = f"network_scan.{format_type}"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=extensions[format_type],
            filetypes=filetypes[format_type],
            title=f"Export {format_type.upper()} Report"
        )
        
        if filename:
            # Remove extension from filename as report generator adds it
            base_filename = filename
            for ext in extensions.values():
                if filename.endswith(ext):
                    base_filename = filename[:-len(ext)]
                    break
            
            # Initialize report generator
            report_gen = ReportGenerator()
            
            # Export results with template_type for PDF
            target_network = self.target_var.get() or "Unknown Network"
            if format_type == "pdf" and template_type:
                report_gen.export_results(
                    scan_results=results_to_export,
                    target_network=target_network,
                    format_type=format_type,
                    filename=base_filename,
                    vulnerability_assessments=getattr(self, 'vulnerability_assessments', None),
                    template_type=template_type
                )
            else:
                report_gen.export_results(
                    scan_results=results_to_export,
                    target_network=target_network,
                    format_type=format_type,
                    filename=base_filename,
                    vulnerability_assessments=getattr(self, 'vulnerability_assessments', None)
                )
            
            # Show success message
            filter_msg = f" (filtered: {len(results_to_export)} of {len(self.scan_results)} hosts)" if self.show_active_only_var.get() else ""
            template_msg = f" ({template_type} template)" if template_type else ""
            messagebox.showinfo("Export Successful", f"{format_type.upper()} report{template_msg} exported successfully{filter_msg}")
                
    def reset_ui_state(self):
        """Reset UI to ready state - called when starting a new scan"""
        self.scan_status['running'] = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_var.set(0)
        
        # Clear the results table when resetting UI state
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Clear scan results data
        self.scan_results.clear()
        
        # Reset status labels
        self.hosts_discovered_label.config(text="0")
        self.hosts_scanned_label.config(text="0")
        self.current_host_label.config(text="None")
        self.status_label.config(text="Ready to scan", style='Status.TLabel')
        
    def setup_topology_tab(self):
        """Setup the network topology visualization tab"""
        # Main container for topology
        main_frame = ttk.Frame(self.topology_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Topology Controls", padding="10")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Generate topology button
        self.generate_topology_btn = ttk.Button(control_frame, text="Generate Topology Map", 
                                              command=self.generate_topology_map)
        self.generate_topology_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Export topology button
        self.export_topology_btn = ttk.Button(control_frame, text="Export Topology Data", 
                                            command=self.export_topology_data)
        self.export_topology_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Topology summary button
        self.topology_summary_btn = ttk.Button(control_frame, text="Show Summary", 
                                             command=self.show_topology_summary)
        self.topology_summary_btn.pack(side=tk.LEFT)
        
        # Canvas frame for topology visualization
        self.topology_canvas_frame = ttk.LabelFrame(main_frame, text="Network Topology Map", padding="10")
        self.topology_canvas_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a container for the topology content with summary overlay
        self.topology_content_frame = ttk.Frame(self.topology_canvas_frame)
        self.topology_content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Summary panel in top-left corner (initially hidden)
        self.topology_summary_frame = ttk.LabelFrame(self.topology_content_frame, text="Summary", padding="5")
        self.topology_summary_frame.place(x=10, y=10, width=250, height=150)
        self.topology_summary_frame.place_forget()  # Hide initially
        
        # Summary text widget
        self.topology_summary_text = tk.Text(self.topology_summary_frame, wrap=tk.WORD, 
                                           font=('Arial', 8), height=8, width=30,
                                           bg='#f0f0f0', relief=tk.FLAT)
        self.topology_summary_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Initially show placeholder
        self.topology_placeholder = ttk.Label(self.topology_content_frame, 
                                            text="Run a network scan first, then click 'Generate Topology Map' to visualize the network structure",
                                            font=('Arial', 12))
        self.topology_placeholder.pack(expand=True)
    
    def setup_results_tab(self):
        """Setup the detailed results tab with the main results tree view"""
        # Main container for results
        main_frame = ttk.Frame(self.results_frame, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid weights for expansion
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)  # Results tree should expand
        
        # Results summary frame
        summary_frame = ttk.LabelFrame(main_frame, text="Scan Summary", padding="10")
        summary_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Summary statistics
        stats_frame = ttk.Frame(summary_frame)
        stats_frame.pack(fill=tk.X)
        
        # Total hosts
        ttk.Label(stats_frame, text="Total Hosts:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.total_hosts_label = ttk.Label(stats_frame, text="0")
        self.total_hosts_label.grid(row=0, column=1, sticky=tk.W, padx=(0, 20))
        
        # High risk hosts
        ttk.Label(stats_frame, text="High Risk Hosts:", font=('Arial', 10, 'bold')).grid(row=0, column=2, sticky=tk.W, padx=(0, 10))
        self.high_risk_label = ttk.Label(stats_frame, text="0", foreground="red")
        self.high_risk_label.grid(row=0, column=3, sticky=tk.W, padx=(0, 20))
        
        # Open ports total
        ttk.Label(stats_frame, text="Total Open Ports:", font=('Arial', 10, 'bold')).grid(row=0, column=4, sticky=tk.W, padx=(0, 10))
        self.open_ports_label = ttk.Label(stats_frame, text="0")
        self.open_ports_label.grid(row=0, column=5, sticky=tk.W)
        
        # Main results tree view (moved from scan tab)
        self.create_main_results_tree(main_frame)
        
    def generate_topology_map(self):
        """Generate and display network topology map"""
        if not self.scan_results:
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
            topology_widget.pack(fill=tk.BOTH, expand=True)
            
            # Update and show summary in top-left corner
            self.update_topology_summary()
            
            messagebox.showinfo("Success", "Topology map generated successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate topology map: {str(e)}")
            
    def export_topology_data(self):
        """Export topology data to file"""
        if not self.scan_results:
            messagebox.showwarning("No Data", "Please run a network scan first!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Export Topology Data"
        )
        
        if filename:
            try:
                topology_data = self.topology_mapper.analyze_network_topology(self.scan_results)
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
        if not self.scan_results:
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
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Format summary
            summary_text = "Network Topology Summary\n"
            summary_text += "=" * 30 + "\n\n"
            for key, value in summary.items():
                summary_text += f"{key}: {value}\n"
                
            text_widget.insert(tk.END, summary_text)
            text_widget.config(state=tk.DISABLED)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate topology summary: {str(e)}")
            
    def export_csv(self):
        """Export scan results to CSV file"""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to export!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Export Scan Results to CSV"
        )
        
        if filename:
            try:
                import csv
                with open(filename, 'w', newline='') as csvfile:
                    fieldnames = ['IP Address', 'Hostname', 'MAC Address', 'Device Type', 'Open Ports', 'Risk Level']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    
                    writer.writeheader()
                    for host, data in self.scan_results.items():
                        writer.writerow({
                            'IP Address': host,
                            'Hostname': data.get('hostname', 'Unknown'),
                            'MAC Address': data.get('mac_address', 'Unknown'),
                            'Device Type': data.get('device_type', 'Unknown'),
                            'Open Ports': ', '.join(map(str, data.get('open_ports', []))),
                            'Risk Level': data.get('vulnerabilities', {}).get('risk_level', 'Unknown')
                        })
                        
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Failed", f"Failed to export results: {str(e)}")
                
    def generate_report(self):
        """Generate comprehensive security report"""
        if not self.scan_results:
            messagebox.showwarning("No Results", "No scan results to generate report from!")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            title="Generate Security Report"
        )
        
        if filename:
            try:
                # Generate HTML report
                html_content = self.create_html_report()
                with open(filename, 'w') as f:
                    f.write(html_content)
                messagebox.showinfo("Report Generated", f"Security report generated: {filename}")
            except Exception as e:
                messagebox.showerror("Report Failed", f"Failed to generate report: {str(e)}")
                
    def create_html_report(self):
        """Create HTML security report"""
        # Apply the same filtering as the display
        filtered_results = self.scan_results
        if self.show_active_only_var.get():
            filtered_results = {host: data for host, data in self.scan_results.items() 
                              if data.get('open_ports') and len(data.get('open_ports', [])) > 0}
        
        filter_note = ""
        if self.show_active_only_var.get():
            filter_note = f"<p><strong>Note:</strong> This report shows only hosts with open ports ({len(filtered_results)} of {len(self.scan_results)} total hosts scanned).</p>"
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .summary {{ margin: 20px 0; }}
                .host {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .high-risk {{ border-left: 5px solid red; }}
                .medium-risk {{ border-left: 5px solid orange; }}
                .low-risk {{ border-left: 5px solid green; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .filter-note {{ background-color: #e7f3ff; padding: 10px; border-radius: 5px; margin: 10px 0; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Network Security Scan Report</h1>
                <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Total Hosts Scanned: {len(self.scan_results)}</p>
                <p>Hosts in Report: {len(filtered_results)}</p>
            </div>
            
            {f'<div class="filter-note">{filter_note}</div>' if filter_note else ''}
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>This report contains the results of a comprehensive network security scan.</p>
            </div>
            
            <h2>Detailed Results</h2>
        """
        
        if not filtered_results:
            html += "<p>No hosts match the current filter criteria.</p>"
        else:
            for host, data in filtered_results.items():
                risk_level = data.get('vulnerabilities', {}).get('risk_level', 'Unknown')
                risk_class = f"{risk_level.lower()}-risk" if risk_level != 'Unknown' else ''
                
                html += f"""
                <div class="host {risk_class}">
                    <h3>{host} - {data.get('hostname', 'Unknown')}</h3>
                    <table>
                        <tr><th>Property</th><th>Value</th></tr>
                        <tr><td>MAC Address</td><td>{data.get('mac_address', 'Unknown')}</td></tr>
                        <tr><td>Device Type</td><td>{data.get('device_type', 'Unknown')}</td></tr>
                        <tr><td>Open Ports</td><td>{', '.join(map(str, data.get('open_ports', [])))}</td></tr>
                        <tr><td>Risk Level</td><td>{risk_level}</td></tr>
                    </table>
                </div>
                """
            
        html += """
        </body>
        </html>
        """
        
        return html
    
    def setup_traffic_tab(self):
        """Setup the traffic analysis tab"""
        # Configure main traffic frame grid weights
        self.traffic_frame.grid_rowconfigure(2, weight=1)  # Results area should expand
        self.traffic_frame.grid_columnconfigure(0, weight=1)
        
        # Control frame
        control_frame = ttk.LabelFrame(self.traffic_frame, text="Traffic Monitoring Controls")
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
                                             command=self.start_traffic_monitoring)
        self.start_monitoring_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_monitoring_btn = ttk.Button(button_frame, text="Stop Monitoring", 
                                            command=self.stop_traffic_monitoring, state="disabled")
        self.stop_monitoring_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Export Data", 
                  command=self.export_traffic_data).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Generate Report", 
                  command=self.generate_traffic_report).pack(side=tk.LEFT, padx=5)
        
        # Status frame
        status_frame = ttk.LabelFrame(self.traffic_frame, text="Monitoring Status")
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
        
        # Analysis results frame
        results_frame = ttk.LabelFrame(self.traffic_frame, text="Traffic Analysis Results")
        results_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
        
        # Results text area with scrollbar
        text_frame = ttk.Frame(results_frame)
        text_frame.grid(row=0, column=0, sticky="nsew")
        text_frame.grid_rowconfigure(0, weight=1)
        text_frame.grid_columnconfigure(0, weight=1)
        
        self.traffic_results_text = tk.Text(text_frame, wrap=tk.WORD, height=15)
        traffic_scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.traffic_results_text.yview)
        self.traffic_results_text.configure(yscrollcommand=traffic_scrollbar.set)
        
        self.traffic_results_text.grid(row=0, column=0, sticky="nsew")
        traffic_scrollbar.grid(row=0, column=1, sticky="ns")
        
        # Configure tab grid weights
        self.traffic_frame.grid_rowconfigure(2, weight=1)
    
    def start_traffic_monitoring(self):
        """Start traffic monitoring"""
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
                self.update_traffic_display()
                
                self.traffic_results_text.insert(tk.END, f"Traffic monitoring started on interface: {interface or 'auto-detect'}\n")
                self.traffic_results_text.insert(tk.END, f"Capture duration: {duration} seconds\n")
                self.traffic_results_text.insert(tk.END, "Monitoring for network anomalies...\n\n")
            else:
                self.traffic_results_text.insert(tk.END, "Failed to start traffic monitoring. Check if Scapy is installed.\n")
                
        except ValueError:
            self.traffic_results_text.insert(tk.END, "Error: Invalid duration value\n")
        except Exception as e:
            self.traffic_results_text.insert(tk.END, f"Error starting monitoring: {e}\n")
    
    def stop_traffic_monitoring(self):
        """Stop traffic monitoring"""
        self.traffic_analyzer.stop_traffic_monitoring()
        self.monitoring_status_label.config(text="Stopped", foreground="red")
        self.start_monitoring_btn.config(state="normal")
        self.stop_monitoring_btn.config(state="disabled")
        
        self.traffic_results_text.insert(tk.END, "Traffic monitoring stopped.\n\n")
        
        # Display final summary
        summary = self.traffic_analyzer.get_traffic_summary()
        self.display_traffic_summary(summary)
    
    def update_traffic_display(self):
        """Update traffic monitoring display"""
        if self.traffic_analyzer.is_monitoring:
            summary = self.traffic_analyzer.get_traffic_summary()
            
            # Update status labels
            self.packets_captured_label.config(text=str(summary['total_packets']))
            self.anomalies_detected_label.config(text=str(summary['anomalies']['total']))
            
            # Schedule next update only if window still exists
            try:
                if self.root and self.root.winfo_exists():
                    self.root.after(5000, self.update_traffic_display)  # Update every 5 seconds
            except tk.TclError:
                # Window has been destroyed, stop the timer
                pass
    
    def display_traffic_summary(self, summary):
        """Display traffic analysis summary"""
        self.traffic_results_text.insert(tk.END, "=== TRAFFIC ANALYSIS SUMMARY ===\n")
        self.traffic_results_text.insert(tk.END, f"Total Packets: {summary['total_packets']:,}\n")
        self.traffic_results_text.insert(tk.END, f"Active Connections: {summary['connection_count']:,}\n")
        
        # Bandwidth stats
        bw_stats = summary['bandwidth_stats']
        self.traffic_results_text.insert(tk.END, f"\nBandwidth Utilization:\n")
        self.traffic_results_text.insert(tk.END, f"  Current: {bw_stats['current_bps']/1024:.2f} KB/s\n")
        self.traffic_results_text.insert(tk.END, f"  Average: {bw_stats['average_bps']/1024:.2f} KB/s\n")
        self.traffic_results_text.insert(tk.END, f"  Peak: {bw_stats['peak_bps']/1024:.2f} KB/s\n")
        
        # Protocol distribution
        if summary['protocol_distribution']:
            self.traffic_results_text.insert(tk.END, f"\nProtocol Distribution:\n")
            for protocol, stats in summary['protocol_distribution'].items():
                self.traffic_results_text.insert(tk.END, f"  {protocol}: {stats['packet_count']:,} packets ({stats['percentage']:.1f}%)\n")
        
        # Top talkers
        if summary['top_talkers']:
            self.traffic_results_text.insert(tk.END, f"\nTop Traffic Generators:\n")
            for i, talker in enumerate(summary['top_talkers'][:5], 1):
                self.traffic_results_text.insert(tk.END, f"  {i}. {talker['ip']}: {talker['total_bytes']/1024:.2f} KB ({talker['packet_count']} packets)\n")
        
        # Anomalies
        anomaly_stats = summary['anomalies']
        if anomaly_stats['total'] > 0:
            self.traffic_results_text.insert(tk.END, f"\n🚨 SECURITY ANOMALIES DETECTED:\n")
            self.traffic_results_text.insert(tk.END, f"  Total: {anomaly_stats['total']}\n")
            self.traffic_results_text.insert(tk.END, f"  Recent (1 hour): {anomaly_stats['recent']}\n")
            
            for severity, count in anomaly_stats['by_severity'].items():
                self.traffic_results_text.insert(tk.END, f"  {severity}: {count}\n")
            
            # Show recent anomalies
            recent_anomalies = sorted(self.traffic_analyzer.anomalies, key=lambda x: x['timestamp'], reverse=True)[:3]
            if recent_anomalies:
                self.traffic_results_text.insert(tk.END, f"\nRecent Anomalies:\n")
                for anomaly in recent_anomalies:
                    self.traffic_results_text.insert(tk.END, f"  • [{anomaly['severity']}] {anomaly['description']}\n")
        
        self.traffic_results_text.insert(tk.END, f"\n{'='*50}\n\n")
        self.traffic_results_text.see(tk.END)
    
    def export_traffic_data(self):
        """Export traffic analysis data"""
        try:
            filename = self.traffic_analyzer.export_traffic_data()
            if filename:
                self.traffic_results_text.insert(tk.END, f"Traffic data exported to: {filename}\n")
            else:
                self.traffic_results_text.insert(tk.END, "Failed to export traffic data\n")
        except Exception as e:
            self.traffic_results_text.insert(tk.END, f"Error exporting data: {e}\n")
    
    def generate_traffic_report(self):
        """Generate and display traffic analysis report"""
        try:
            report = self.traffic_analyzer.generate_traffic_report()
            
            # Clear and display report
            self.traffic_results_text.delete(1.0, tk.END)
            self.traffic_results_text.insert(tk.END, report)
            
        except Exception as e:
            self.traffic_results_text.insert(tk.END, f"Error generating report: {e}\n")
    
    def on_filter_change(self):
        """Handle filter checkbox changes"""
        if hasattr(self, 'scan_results') and self.scan_results:
            self.display_results(self.scan_results)
        

def main():
    """Main application entry point"""
    print("Starting Network Mapper Desktop GUI...")
    
    root = tk.Tk()
    app = NetworkMapperGUI(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication terminated by user")
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Application Error", f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()