"""
Results Tab Component - Handles the detailed results display
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Dict, Any, Optional, List
import json
from datetime import datetime

from .base_component import BaseTab, EventMixin


class ResultsTab(BaseTab, EventMixin):
    """Results tab component for displaying scan results"""
    
    def __init__(self, parent: ttk.Notebook, controller: Optional[object] = None):
        EventMixin.__init__(self)
        super().__init__(parent, "Results", controller)
    
    def _create_tab_content(self):
        """Create the results tab content"""
        # Main container
        main_frame = ttk.Frame(self.frame)
        main_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Control panel
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        # Export buttons
        export_frame = ttk.LabelFrame(control_frame, text="Export Options", padding="5")
        export_frame.grid(row=0, column=0, sticky="w", padx=(0, 10))
        
        ttk.Button(
            export_frame,
            text="Export CSV",
            command=self._export_csv
        ).grid(row=0, column=0, padx=(0, 5))
        
        ttk.Button(
            export_frame,
            text="Generate Report",
            command=self._generate_report
        ).grid(row=0, column=1, padx=5)
        
        ttk.Button(
            export_frame,
            text="Export HTML",
            command=self._export_html
        ).grid(row=0, column=2, padx=(5, 0))
        
        # Filter frame
        filter_frame = ttk.LabelFrame(control_frame, text="Filters", padding="5")
        filter_frame.grid(row=0, column=1, sticky="w", padx=10)
        
        ttk.Label(filter_frame, text="Risk Level:").grid(row=0, column=0, padx=(0, 5))
        self.widgets['risk_filter_var'] = tk.StringVar(value="All")
        risk_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.widgets['risk_filter_var'],
            values=["All", "High", "Medium", "Low"],
            state="readonly",
            width=10
        )
        risk_combo.grid(row=0, column=1, padx=(0, 10))
        risk_combo.bind('<<ComboboxSelected>>', self._on_filter_change)
        
        ttk.Button(
            filter_frame,
            text="Clear Filters",
            command=self._clear_filters
        ).grid(row=0, column=2)
        
        # Results tree
        self._create_results_tree(main_frame)
        
        # Details panel
        self._create_details_panel(main_frame)
    
    def _create_results_tree(self, parent):
        """Create the results tree view"""
        # Tree frame with scrollbars
        tree_frame = ttk.Frame(parent)
        tree_frame.grid(row=1, column=0, sticky="nsew", pady=(0, 10))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # Create treeview
        columns = ("IP", "Hostname", "Ports", "Services", "Risk", "Device Type")
        self.widgets['results_tree'] = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="tree headings",
            height=15
        )
        
        # Configure columns
        self.widgets['results_tree'].heading("#0", text="Status")
        self.widgets['results_tree'].column("#0", width=80, minwidth=80)
        
        for col in columns:
            self.widgets['results_tree'].heading(col, text=col)
            if col == "IP":
                self.widgets['results_tree'].column(col, width=120, minwidth=100)
            elif col == "Hostname":
                self.widgets['results_tree'].column(col, width=150, minwidth=120)
            elif col == "Ports":
                self.widgets['results_tree'].column(col, width=100, minwidth=80)
            elif col == "Services":
                self.widgets['results_tree'].column(col, width=200, minwidth=150)
            elif col == "Risk":
                self.widgets['results_tree'].column(col, width=80, minwidth=60)
            elif col == "Device Type":
                self.widgets['results_tree'].column(col, width=120, minwidth=100)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.widgets['results_tree'].yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.widgets['results_tree'].xview)
        
        self.widgets['results_tree'].configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout
        self.widgets['results_tree'].grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        # Bind events
        self.widgets['results_tree'].bind('<Double-1>', self._on_item_double_click)
        self.widgets['results_tree'].bind('<Button-3>', self._on_right_click)
    
    def _create_details_panel(self, parent):
        """Create the details panel"""
        details_frame = ttk.LabelFrame(parent, text="Host Details", padding="5")
        details_frame.grid(row=2, column=0, sticky="ew")
        details_frame.columnconfigure(0, weight=1)
        
        # Details text widget
        self.widgets['details_text'] = tk.Text(
            details_frame,
            height=8,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.widgets['details_text'].grid(row=0, column=0, sticky="ew")
        
        # Details scrollbar
        details_scrollbar = ttk.Scrollbar(
            details_frame,
            orient="vertical",
            command=self.widgets['details_text'].yview
        )
        self.widgets['details_text'].configure(yscrollcommand=details_scrollbar.set)
        details_scrollbar.grid(row=0, column=1, sticky="ns")
    
    def _on_item_double_click(self, event):
        """Handle double-click on tree item"""
        selection = self.widgets['results_tree'].selection()
        if selection:
            item = selection[0]
            self._show_host_details(item)
    
    def _on_right_click(self, event):
        """Handle right-click on tree item"""
        # Create context menu
        context_menu = tk.Menu(self.frame, tearoff=0)
        context_menu.add_command(label="View Details", command=self._view_selected_details)
        context_menu.add_command(label="Copy IP", command=self._copy_selected_ip)
        context_menu.add_separator()
        context_menu.add_command(label="Export Host Data", command=self._export_selected_host)
        
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    def _on_filter_change(self, event=None):
        """Handle filter change"""
        self.trigger_event('filter_change', self.widgets['risk_filter_var'].get())
    
    def _clear_filters(self):
        """Clear all filters"""
        self.widgets['risk_filter_var'].set("All")
        self._on_filter_change()
    
    def _show_host_details(self, item):
        """Show details for selected host"""
        if self.controller:
            host_data = self.widgets['results_tree'].item(item)
            ip = host_data['values'][0] if host_data['values'] else ""
            if ip:
                self.controller.show_host_details(ip)
    
    def _view_selected_details(self):
        """View details for selected item"""
        selection = self.widgets['results_tree'].selection()
        if selection:
            self._show_host_details(selection[0])
    
    def _copy_selected_ip(self):
        """Copy selected IP to clipboard"""
        selection = self.widgets['results_tree'].selection()
        if selection:
            item = selection[0]
            host_data = self.widgets['results_tree'].item(item)
            ip = host_data['values'][0] if host_data['values'] else ""
            if ip:
                self.frame.clipboard_clear()
                self.frame.clipboard_append(ip)
    
    def _export_selected_host(self):
        """Export selected host data"""
        selection = self.widgets['results_tree'].selection()
        if selection and self.controller:
            item = selection[0]
            host_data = self.widgets['results_tree'].item(item)
            ip = host_data['values'][0] if host_data['values'] else ""
            if ip:
                self.controller.export_host_data(ip)
    
    def _export_csv(self):
        """Export results to CSV"""
        if self.controller:
            self.controller.export_results('csv')
    
    def _generate_report(self):
        """Generate a detailed report"""
        if self.controller:
            self.controller.generate_report()
    
    def _export_html(self):
        """Export results to HTML"""
        if self.controller:
            self.controller.export_results('html')
    
    def update_results(self, results: Dict[str, Any]):
        """Update the results display"""
        print(f"[DEBUG] ResultsTab.update_results called with {len(results)} hosts")
        
        # Clear existing items
        for item in self.widgets['results_tree'].get_children():
            self.widgets['results_tree'].delete(item)
        
        print(f"[DEBUG] Cleared existing tree items")
        
        # Add new results
        for host_ip, host_data in results.items():
            print(f"[DEBUG] Adding host {host_ip} to tree")
            self._add_host_to_tree(host_ip, host_data)
        
        print(f"[DEBUG] Added {len(results)} hosts to results tree")
    
    def _add_host_to_tree(self, host_ip: str, host_data: Dict[str, Any]):
        """Add a host to the results tree"""
        # Extract data
        hostname = host_data.get('hostname', 'Unknown')
        open_ports = host_data.get('open_ports', [])
        services = host_data.get('services', {})
        # Extract risk level from vulnerabilities section (correct location)
        risk_level = host_data.get('vulnerabilities', {}).get('risk_level', 'Low')
        device_type = host_data.get('device_type', 'Unknown')
        
        # Format ports and services
        ports_str = ', '.join(map(str, open_ports[:5]))  # Show first 5 ports
        if len(open_ports) > 5:
            ports_str += f" (+{len(open_ports) - 5} more)"
        
        services_list = []
        for port, service_info in list(services.items())[:3]:  # Show first 3 services
            if isinstance(service_info, dict):
                service_name = service_info.get('service', 'Unknown')
            else:
                service_name = str(service_info)
            services_list.append(f"{port}:{service_name}")
        
        services_str = ', '.join(services_list)
        if len(services) > 3:
            services_str += f" (+{len(services) - 3} more)"
        
        # Determine status icon
        status_icon = "🔴" if risk_level == "High" else "🟡" if risk_level == "Medium" else "🟢"
        
        # Insert into tree
        item_id = self.widgets['results_tree'].insert(
            "",
            "end",
            text=status_icon,
            values=(host_ip, hostname, ports_str, services_str, risk_level, device_type)
        )
        
        # Store full data in a dictionary for later use (instead of trying to set invalid column)
        if not hasattr(self, '_host_data'):
            self._host_data = {}
        self._host_data[item_id] = host_data
    
    def update_host_details(self, host_ip: str, details: str):
        """Update the host details panel"""
        self.widgets['details_text'].config(state=tk.NORMAL)
        self.widgets['details_text'].delete(1.0, tk.END)
        self.widgets['details_text'].insert(1.0, details)
        self.widgets['details_text'].config(state=tk.DISABLED)
    
    def clear_results(self):
        """Clear all results"""
        for item in self.widgets['results_tree'].get_children():
            self.widgets['results_tree'].delete(item)
        
        self.widgets['details_text'].config(state=tk.NORMAL)
        self.widgets['details_text'].delete(1.0, tk.END)
        self.widgets['details_text'].config(state=tk.DISABLED)
    
    def get_selected_hosts(self) -> List[str]:
        """Get list of selected host IPs"""
        selection = self.widgets['results_tree'].selection()
        hosts = []
        for item in selection:
            host_data = self.widgets['results_tree'].item(item)
            if host_data['values']:
                hosts.append(host_data['values'][0])
        return hosts
    
    def filter_results(self, risk_level: str = "All"):
        """Filter results by risk level"""
        # This would be implemented to hide/show items based on filter
        # For now, just trigger the event
        self.trigger_event('filter_applied', risk_level)