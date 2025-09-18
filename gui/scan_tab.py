"""
Scan Tab Component - Handles the main scanning interface
"""
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import json
from typing import Dict, Any, Optional, Callable

from .base_component import BaseTab, BasePanel, ValidatedEntry, EventMixin


class ConfigPanel(BasePanel, EventMixin):
    """Configuration panel for scan settings"""
    
    def __init__(self, parent: tk.Widget, controller: Optional[object] = None):
        EventMixin.__init__(self)
        self.controller = controller
        self.flag_vars = {}  # Initialize flag_vars before calling super().__init__
        super().__init__(parent, "Scan Configuration", controller)
    
    def _create_panel_content(self):
        """Create the configuration panel content"""
        # Target configuration
        target_frame = ttk.Frame(self.frame)
        target_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
        target_frame.columnconfigure(1, weight=1)
        
        ttk.Label(target_frame, text="Target Network:").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.widgets['target_entry'] = ValidatedEntry(
            target_frame, 
            validator=self._validate_network_target,
            width=30
        )
        self.widgets['target_entry'].grid(row=0, column=1, sticky="ew", padx=(0, 10))
        
        # Advanced options frame
        advanced_frame = ttk.LabelFrame(self.frame, text="Advanced Options", padding="5")
        advanced_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=10)
        advanced_frame.columnconfigure(1, weight=1)
        
        # Threads
        ttk.Label(advanced_frame, text="Threads:").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.widgets['threads_var'] = tk.StringVar(value="50")
        threads_spinbox = ttk.Spinbox(
            advanced_frame, 
            from_=1, to=200, 
            textvariable=self.widgets['threads_var'],
            width=10
        )
        threads_spinbox.grid(row=0, column=1, sticky="w", padx=(0, 10))
        
        # Timeout
        ttk.Label(advanced_frame, text="Timeout (s):").grid(row=0, column=2, sticky="w", padx=(10, 10))
        self.widgets['timeout_var'] = tk.StringVar(value="3")
        timeout_spinbox = ttk.Spinbox(
            advanced_frame,
            from_=1, to=30,
            textvariable=self.widgets['timeout_var'],
            width=10
        )
        timeout_spinbox.grid(row=0, column=3, sticky="w")
        
        # Security level
        ttk.Label(advanced_frame, text="Security Level:").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(5, 0))
        self.widgets['security_var'] = tk.StringVar(value="STANDARD")
        security_combo = ttk.Combobox(
            advanced_frame,
            textvariable=self.widgets['security_var'],
            values=["MINIMAL", "STANDARD", "ENHANCED", "MAXIMUM"],
            state="readonly",
            width=15
        )
        security_combo.grid(row=1, column=1, sticky="w", padx=(0, 10), pady=(5, 0))
        
        # Smart filter
        self.widgets['smart_filter_var'] = tk.BooleanVar(value=True)
        smart_filter_check = ttk.Checkbutton(
            advanced_frame,
            text="Smart IP Filtering",
            variable=self.widgets['smart_filter_var']
        )
        smart_filter_check.grid(row=1, column=2, columnspan=2, sticky="w", padx=(10, 0), pady=(5, 0))
        
        # Flags configuration
        flags_frame = ttk.LabelFrame(self.frame, text="Scan Flags", padding="5")
        flags_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
        
        self._create_flags_section(flags_frame)
    
    def _create_flags_section(self, parent):
        """Create the flags configuration section"""
        # Load flag configuration
        flag_config = self.controller.scan_controller.get_flag_config()
        
        # Create sections for different flag categories
        self._create_feature_flags_section(parent, flag_config)
        self._create_security_flags_section(parent, flag_config)
        self._create_output_flags_section(parent, flag_config)
    
    def _create_feature_flags_section(self, parent, flag_config):
        """Create feature flags section"""
        feature_frame = ttk.LabelFrame(parent, text="Feature Flags", padding="5")
        feature_frame.pack(fill="x", pady=(0, 5))
        
        feature_flags = flag_config.get('feature_flags', {})
        
        for flag_name, flag_info in feature_flags.items():
            frame = ttk.Frame(feature_frame)
            frame.pack(fill="x", pady=2)
            
            # Handle both dict and simple value formats
            if isinstance(flag_info, dict):
                default_value = flag_info.get('enabled', False)
                description = flag_info.get('description', '')
            else:
                default_value = bool(flag_info)
                description = ''
            
            var = tk.BooleanVar(value=default_value)
            checkbox = ttk.Checkbutton(
                frame,
                text=flag_name.replace('_', ' ').title(),
                variable=var
            )
            checkbox.pack(side="left")
            
            # Store the variable for later access
            self.flag_vars[flag_name] = var
            
            # Add description if available
            if description:
                ttk.Label(
                    frame,
                    text=f"({description})",
                    foreground="gray"
                ).pack(side="left", padx=(10, 0))
    
    def _create_security_flags_section(self, parent, flag_config):
        """Create security flags section"""
        security_frame = ttk.LabelFrame(parent, text="Security Options", padding="5")
        security_frame.pack(fill="x", pady=(0, 5))
        
        security_options = flag_config.get('security_options', {})
        
        for flag_name, flag_info in security_options.items():
            if flag_name == 'security_level':  # Skip non-boolean options
                continue
                
            frame = ttk.Frame(security_frame)
            frame.pack(fill="x", pady=2)
            
            # Handle both dict and simple value formats
            if isinstance(flag_info, dict):
                default_value = flag_info.get('enabled', False)
                description = flag_info.get('description', '')
            else:
                default_value = bool(flag_info)
                description = ''
            
            var = tk.BooleanVar(value=default_value)
            checkbox = ttk.Checkbutton(
                frame,
                text=flag_name.replace('_', ' ').title(),
                variable=var
            )
            checkbox.pack(side="left")
            
            # Store the variable for later access
            self.flag_vars[flag_name] = var
            
            # Add description if available
            if description:
                ttk.Label(
                    frame,
                    text=f"({description})",
                    foreground="gray"
                ).pack(side="left", padx=(10, 0))
    
    def _create_output_flags_section(self, parent, flag_config):
        """Create output flags section"""
        output_frame = ttk.LabelFrame(parent, text="Output Options", padding="5")
        output_frame.pack(fill="x", pady=(0, 5))
        
        output_options = flag_config.get('output_options', {})
        
        for flag_name, flag_info in output_options.items():
            if flag_name == 'default_output_prefix':  # Skip non-boolean options
                continue
                
            frame = ttk.Frame(output_frame)
            frame.pack(fill="x", pady=2)
            
            # Handle both dict and simple value formats
            if isinstance(flag_info, dict):
                default_value = flag_info.get('enabled', False)
                description = flag_info.get('description', '')
            else:
                default_value = bool(flag_info)
                description = ''
            
            var = tk.BooleanVar(value=default_value)
            checkbox = ttk.Checkbutton(
                frame,
                text=flag_name.replace('_', ' ').title(),
                variable=var
            )
            checkbox.pack(side="left")
            
            # Store the variable for later access
            self.flag_vars[flag_name] = var
            
            # Add description if available
            if description:
                ttk.Label(
                    frame,
                    text=f"({description})",
                    foreground="gray"
                ).pack(side="left", padx=(10, 0))
    
    def _load_flag_config(self) -> Dict[str, Any]:
        """Load flag configuration from file"""
        try:
            config_path = Path("config/default_flags.json")
            if config_path.exists():
                with open(config_path, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        
        # Default flags if file not found
        return {
            "ping_sweep": {"description": "Ping Sweep", "default": True},
            "port_scan": {"description": "Port Scanning", "default": True},
            "service_detection": {"description": "Service Detection", "default": True},
            "vulnerability_scan": {"description": "Vulnerability Assessment", "default": False},
            "os_detection": {"description": "OS Detection", "default": False},
            "aggressive_scan": {"description": "Aggressive Scanning", "default": False}
        }
    
    def _validate_network_target(self, value: str) -> bool:
        """Validate network target input - allow partial input while typing"""
        if not value:
            return True  # Allow empty
        
        # Allow partial input while typing
        import re
        
        # Allow various formats while typing:
        # - Partial IPs: "192", "192.168", "192.168.1"
        # - Complete IPs: "192.168.1.1"
        # - CIDR notation: "192.168.1.0/24"
        # - Hostnames: "example.com", "localhost"
        # - IP ranges: "192.168.1.1-192.168.1.100"
        
        # Basic patterns for common formats
        patterns = [
            r'^\d{1,3}$',                                    # Single number
            r'^\d{1,3}\.$',                                  # Number with dot
            r'^\d{1,3}\.\d{1,3}$',                          # Two numbers
            r'^\d{1,3}\.\d{1,3}\.$',                        # Two numbers with dot
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}$',                # Three numbers
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.$',              # Three numbers with dot
            r'^(\d{1,3}\.){3}\d{1,3}$',                     # Complete IP
            r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$',            # IP with CIDR
            r'^(\d{1,3}\.){3}\d{1,3}-(\d{1,3}\.){3}\d{1,3}$',  # IP range
            r'^[a-zA-Z0-9.-]+$',                            # Hostname/domain
        ]
        
        # Check if value matches any allowed pattern
        for pattern in patterns:
            if re.match(pattern, value):
                return True
        
        return False
    
    def get_scan_config(self) -> Dict[str, Any]:
        """Get the current scan configuration"""
        config = {
            'target': self.widgets['target_entry'].get(),
            'threads': int(self.widgets['threads_var'].get()),
            'timeout': int(self.widgets['timeout_var'].get()),
            'security_level': self.widgets['security_var'].get(),
            'smart_filter': self.widgets['smart_filter_var'].get(),
            'flags': {}
        }
        
        # Get flag values
        for flag_name, var in self.flag_vars.items():
            config['flags'][flag_name] = var.get()
        
        return config
    
    def validate_config(self) -> tuple[bool, str]:
        """Validate the current configuration"""
        config = self.get_scan_config()
        
        if not config['target']:
            return False, "Please enter a target network"
        
        if not self._validate_network_target(config['target']):
            return False, "Invalid network target format"
        
        return True, ""


class StatusPanel(BasePanel, EventMixin):
    """Status panel for displaying scan progress"""
    
    def __init__(self, parent: tk.Widget, controller: Optional[object] = None):
        EventMixin.__init__(self)
        super().__init__(parent, "Scan Status", controller)
    
    def _create_panel_content(self):
        """Create the status panel content"""
        # Progress bar
        self.widgets['progress_var'] = tk.DoubleVar()
        self.widgets['progress_bar'] = ttk.Progressbar(
            self.frame,
            variable=self.widgets['progress_var'],
            maximum=100
        )
        self.widgets['progress_bar'].grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
        
        # Status labels
        self.widgets['status_label'] = ttk.Label(self.frame, text="Ready to scan")
        self.widgets['status_label'].grid(row=1, column=0, columnspan=2, sticky="w", pady=2)
        
        self.widgets['hosts_label'] = ttk.Label(self.frame, text="Hosts found: 0")
        self.widgets['hosts_label'].grid(row=2, column=0, sticky="w", pady=2)
        
        self.widgets['time_label'] = ttk.Label(self.frame, text="Elapsed: 00:00")
        self.widgets['time_label'].grid(row=2, column=1, sticky="e", pady=2)
        
        # Control buttons
        button_frame = ttk.Frame(self.frame)
        button_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)
        
        self.widgets['start_button'] = ttk.Button(
            button_frame,
            text="Start Scan",
            command=self._on_start_scan
        )
        self.widgets['start_button'].grid(row=0, column=0, padx=(0, 5), sticky="ew")
        
        self.widgets['stop_button'] = ttk.Button(
            button_frame,
            text="Stop Scan",
            command=self._on_stop_scan,
            state="disabled"
        )
        self.widgets['stop_button'].grid(row=0, column=1, padx=(5, 0), sticky="ew")
    
    def _on_start_scan(self):
        """Handle start scan button click"""
        self.trigger_event('start_scan')
    
    def _on_stop_scan(self):
        """Handle stop scan button click"""
        self.trigger_event('stop_scan')
    
    def update_progress(self, progress: float, status: str = ""):
        """Update the progress bar and status"""
        self.widgets['progress_var'].set(progress)
        if status:
            self.widgets['status_label'].config(text=status)
    
    def update_hosts_count(self, count: int):
        """Update the hosts found count"""
        self.widgets['hosts_label'].config(text=f"Hosts found: {count}")
    
    def update_elapsed_time(self, elapsed: str):
        """Update the elapsed time"""
        self.widgets['time_label'].config(text=f"Elapsed: {elapsed}")
    
    def set_scan_running(self, running: bool):
        """Set the scan running state"""
        if running:
            self.widgets['start_button'].config(state="disabled")
            self.widgets['stop_button'].config(state="normal")
        else:
            self.widgets['start_button'].config(state="normal")
            self.widgets['stop_button'].config(state="disabled")


class ResultsPanel(BasePanel):
    """Simple results panel for the scan tab"""
    
    def __init__(self, parent: tk.Widget, controller: Optional[object] = None):
        super().__init__(parent, "Quick Results", controller)
    
    def _create_panel_content(self):
        """Create the results panel content"""
        # Quick summary frame
        summary_frame = ttk.Frame(self.frame)
        summary_frame.grid(row=0, column=0, sticky="ew", pady=5)
        summary_frame.columnconfigure(1, weight=1)
        
        # Hosts found
        ttk.Label(summary_frame, text="Hosts Found:").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.widgets['hosts_found_label'] = ttk.Label(summary_frame, text="0", font=("Arial", 12, "bold"))
        self.widgets['hosts_found_label'].grid(row=0, column=1, sticky="w")
        
        # High risk hosts
        ttk.Label(summary_frame, text="High Risk:").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(5, 0))
        self.widgets['high_risk_label'] = ttk.Label(
            summary_frame, 
            text="0", 
            font=("Arial", 12, "bold"),
            foreground="red"
        )
        self.widgets['high_risk_label'].grid(row=1, column=1, sticky="w", pady=(5, 0))
        
        # View full results button
        self.widgets['view_results_button'] = ttk.Button(
            self.frame,
            text="View Full Results",
            command=self._on_view_results
        )
        self.widgets['view_results_button'].grid(row=1, column=0, pady=10)
    
    def _on_view_results(self):
        """Handle view results button click"""
        if self.controller:
            self.controller.switch_to_results_tab()
    
    def update_summary(self, hosts_found: int, high_risk: int):
        """Update the results summary"""
        print(f"[DEBUG] ResultsPanel.update_summary called: {hosts_found} hosts, {high_risk} high risk")
        self.widgets['hosts_found_label'].config(text=str(hosts_found))
        self.widgets['high_risk_label'].config(text=str(high_risk))
        print(f"[DEBUG] Summary labels updated")


class ScanTab(BaseTab, EventMixin):
    """Main scan tab component"""
    
    def __init__(self, parent: ttk.Notebook, controller: Optional[object] = None):
        EventMixin.__init__(self)
        super().__init__(parent, "Network Scan", controller)
    
    def _create_tab_content(self):
        """Create the scan tab content"""
        # Main container
        main_frame = ttk.Frame(self.frame)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)  # Results panel gets extra space
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="Network Security Scanner",
            font=("Arial", 16, "bold")
        )
        title_label.grid(row=0, column=0, pady=(0, 20))
        
        # Configuration panel
        self.config_panel = ConfigPanel(main_frame, self.controller)
        self.config_panel.get_frame().grid(row=1, column=0, sticky="ew", pady=(0, 10))
        
        # Status panel
        self.status_panel = StatusPanel(main_frame, self.controller)
        self.status_panel.get_frame().grid(row=2, column=0, sticky="ew", pady=(0, 10))
        
        # Results panel
        self.results_panel = ResultsPanel(main_frame, self.controller)
        self.results_panel.get_frame().grid(row=3, column=0, sticky="ew")
        
        # Bind events
        self.status_panel.bind_event('start_scan', self._on_start_scan)
        self.status_panel.bind_event('stop_scan', self._on_stop_scan)
    
    def _on_start_scan(self):
        """Handle start scan event"""
        # Validate configuration
        is_valid, error_msg = self.config_panel.validate_config()
        if not is_valid:
            messagebox.showerror("Configuration Error", error_msg)
            return
        
        # Get scan configuration
        config = self.config_panel.get_scan_config()
        
        # Trigger scan start event
        self.trigger_event('start_scan', config)
    
    def _on_stop_scan(self):
        """Handle stop scan event"""
        self.trigger_event('stop_scan')
    
    def get_config_panel(self) -> ConfigPanel:
        """Get the configuration panel"""
        return self.config_panel
    
    def get_status_panel(self) -> StatusPanel:
        """Get the status panel"""
        return self.status_panel
    
    def get_results_panel(self) -> ResultsPanel:
        """Get the results panel"""
        return self.results_panel