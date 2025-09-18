"""
Scan Controller - Handles business logic and coordinates between UI and scanning engine
"""
import threading
import time
from datetime import datetime, timedelta
from queue import Queue
from typing import Dict, Any, Optional, Callable
import json
from pathlib import Path

from network_mapper_refactored import NetworkMapper
from modules.secure_config import SecurityLevel


class ScanController:
    """Controller for managing scan operations and UI coordination"""
    
    def __init__(self):
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
        
        # Communication queues
        self.update_queue = Queue()
        self.status_callbacks = []
        self.results_callbacks = []
        
        # Timer for UI updates
        self.update_timer = None
    
    def add_status_callback(self, callback: Callable):
        """Add a callback for status updates"""
        self.status_callbacks.append(callback)
    
    def add_results_callback(self, callback: Callable):
        """Add a callback for results updates"""
        self.results_callbacks.append(callback)
    
    def start_scan(self, config: Dict[str, Any]) -> bool:
        """Start a new scan with the given configuration"""
        if self.scan_status['running']:
            return False
        
        try:
            # Validate configuration
            if not self._validate_config(config):
                return False
            
            # Reset status
            self._reset_scan_status()
            
            # Create scanner instance
            security_level = getattr(SecurityLevel, config['security_level'], SecurityLevel.STANDARD)
            
            self.current_scan = NetworkMapper(
                target_network=config['target'],
                threads=config['threads'],
                timeout=config['timeout'],
                security_level=security_level,
                smart_filter=config['smart_filter']
            )
            
            # Start scan thread
            self.scan_thread = threading.Thread(
                target=self._run_scan,
                args=(config,),
                daemon=True
            )
            
            self.scan_status['running'] = True
            self.scan_status['start_time'] = datetime.now()
            
            self.scan_thread.start()
            
            # Start UI update timer
            self._start_update_timer()
            
            # Notify callbacks
            self._notify_status_callbacks()
            
            return True
            
        except Exception as e:
            self.scan_status['error'] = str(e)
            self._notify_status_callbacks()
            return False
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.current_scan and self.scan_status['running']:
            self.current_scan.stop_scan = True
            self.scan_status['running'] = False
            
            # Stop update timer
            if self.update_timer:
                self.update_timer.cancel()
            
            self._notify_status_callbacks()
    
    def _validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate scan configuration"""
        required_fields = ['target', 'threads', 'timeout', 'security_level']
        
        for field in required_fields:
            if field not in config:
                return False
        
        # Additional validation
        if not config['target']:
            return False
        
        if config['threads'] < 1 or config['threads'] > 200:
            return False
        
        if config['timeout'] < 1 or config['timeout'] > 30:
            return False
        
        return True
    
    def _reset_scan_status(self):
        """Reset scan status to initial state"""
        self.scan_status = {
            'running': False,
            'progress': 0,
            'current_host': '',
            'total_hosts': 0,
            'completed_hosts': 0,
            'start_time': None,
            'error': None
        }
        self.scan_results = {}
    
    def _run_scan(self, config: Dict[str, Any]):
        """Run the scan in a separate thread"""
        try:
            # Setup incremental export if needed
            self.current_scan.setup_incremental_export('json')
            
            # Start ping sweep
            self._update_status("Starting ping sweep...", 10)
            discovered_hosts = self.current_scan.ping_sweep()
            
            if not discovered_hosts:
                self._update_status("No hosts discovered", 100)
                return
            
            self.scan_status['total_hosts'] = len(discovered_hosts)
            self._update_status(f"Found {len(discovered_hosts)} hosts, starting comprehensive scan...", 20)
            
            # Run comprehensive scan
            results = self.current_scan.comprehensive_scan()
            
            # Update final results
            self.scan_results = results
            self._update_status("Scan completed", 100)
            
            # Notify results callbacks
            self._notify_results_callbacks()
            
        except Exception as e:
            self.scan_status['error'] = str(e)
            self._update_status(f"Scan failed: {str(e)}", 0)
        
        finally:
            self.scan_status['running'] = False
            if self.update_timer:
                self.update_timer.cancel()
            self._notify_status_callbacks()
    
    def _update_status(self, message: str, progress: float):
        """Update scan status"""
        self.scan_status['progress'] = progress
        self.scan_status['current_host'] = message
        
        # Add to update queue for thread-safe UI updates
        self.update_queue.put({
            'type': 'status',
            'data': self.scan_status.copy()
        })
    
    def _start_update_timer(self):
        """Start the periodic update timer"""
        self._process_updates()
        if self.scan_status['running']:
            self.update_timer = threading.Timer(1.0, self._start_update_timer)
            self.update_timer.start()
    
    def _process_updates(self):
        """Process queued updates"""
        while not self.update_queue.empty():
            try:
                update = self.update_queue.get_nowait()
                if update['type'] == 'status':
                    self._notify_status_callbacks()
                elif update['type'] == 'results':
                    self._notify_results_callbacks()
            except:
                break
    
    def _notify_status_callbacks(self):
        """Notify all status callbacks"""
        for callback in self.status_callbacks:
            try:
                callback(self.scan_status.copy())
            except Exception as e:
                print(f"Error in status callback: {e}")
    
    def _notify_results_callbacks(self):
        """Notify all results callbacks"""
        print(f"[DEBUG] Notifying {len(self.results_callbacks)} results callbacks")
        print(f"[DEBUG] Scan results: {self.scan_results}")
        for callback in self.results_callbacks:
            try:
                # Ensure scan_results is not None before calling copy()
                results = self.scan_results if self.scan_results is not None else {}
                print(f"[DEBUG] Calling callback with results: {len(results)} hosts")
                callback(results.copy())
                print(f"[DEBUG] Callback completed successfully")
            except Exception as e:
                print(f"Error in results callback: {e}")
                import traceback
                traceback.print_exc()
    
    def get_scan_status(self) -> Dict[str, Any]:
        """Get current scan status"""
        return self.scan_status.copy()
    
    def get_scan_results(self) -> Dict[str, Any]:
        """Get current scan results"""
        return self.scan_results.copy()
    
    def export_results(self, format_type: str, filename: Optional[str] = None) -> bool:
        """Export scan results"""
        if not self.scan_results:
            return False
        
        try:
            if self.current_scan:
                self.current_scan.export_results(format_type, filename)
                return True
        except Exception as e:
            print(f"Export error: {e}")
        
        return False
    
    def generate_report(self, template_type: str = 'executive') -> bool:
        """Generate a detailed report"""
        if not self.scan_results:
            return False
        
        try:
            if self.current_scan:
                self.current_scan.export_results('pdf', template_type=template_type)
                return True
        except Exception as e:
            print(f"Report generation error: {e}")
        
        return False
    
    def get_host_details(self, host_ip: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific host"""
        return self.scan_results.get(host_ip)
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get scan statistics"""
        if not self.current_scan:
            return {}
        
        try:
            return self.current_scan.get_scan_statistics()
        except:
            return {}
    
    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """Get vulnerability summary"""
        if not self.current_scan:
            return {}
        
        try:
            return self.current_scan.get_vulnerability_summary()
        except:
            return {}
    
    def get_flag_config(self) -> Dict[str, Any]:
        """Get the flag configuration"""
        return self._load_flag_config()
    
    def _load_flag_config(self) -> Dict[str, Any]:
        """Load flag configuration from file"""
        config_path = Path("config/default_flags.json")
        backup_path = Path("config/default_flags.json.backup")
        
        # Try to load from main config file first, then backup
        for path in [config_path, backup_path]:
            if path.exists():
                try:
                    with open(path, 'r') as f:
                        return json.load(f)
                except (json.JSONDecodeError, IOError):
                    continue
        
        # Return default configuration if no file found
        return {
            "feature_flags": {
                "ping_only": {"enabled": False, "description": "Only perform ping sweep"},
                "nmap": {"enabled": True, "description": "Use nmap for advanced scanning"},
                "smart_filter": {"enabled": True, "description": "Enable smart filtering"},
                "vuln_report": {"enabled": True, "description": "Generate vulnerability report"},
                "incremental": {"enabled": False, "description": "Enable incremental export"}
            }
        }
    
    def cleanup(self):
        """Cleanup resources"""
        self.stop_scan()
        
        if self.update_timer:
            self.update_timer.cancel()
        
        # Clear callbacks
        self.status_callbacks.clear()
        self.results_callbacks.clear()
        
        # Clear queues
        while not self.update_queue.empty():
            try:
                self.update_queue.get_nowait()
            except:
                break