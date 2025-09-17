#!/usr/bin/env python3
"""
Input Validation and Sanitization Module
Implements comprehensive input validation following OWASP guidelines and DevSecOps best practices.

Author: Gustavo Valente
Version: 2.0
"""

import re
import ipaddress
import socket
from pathlib import Path
from typing import Union, List, Dict, Any
import logging

class InputValidator:
    """
    Comprehensive input validation and sanitization class
    Implements OWASP Input Validation guidelines and prevents:
    - Command injection
    - Path traversal
    - Network parameter tampering
    - Malicious input patterns
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Dangerous patterns that should be blocked
        self.dangerous_patterns = [
            r'[;&|`$(){}[\]<>]',  # Command injection characters
            r'\.\./|\.\.\\',       # Path traversal
            r'<script|javascript:', # XSS patterns
            r'union\s+select|drop\s+table', # SQL injection
            r'exec\s*\(|eval\s*\(', # Code execution
        ]
        
        # Compile regex patterns for performance
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.dangerous_patterns]
        
        # Valid port range
        self.MIN_PORT = 1
        self.MAX_PORT = 65535
        
        # Maximum reasonable values
        self.MAX_THREADS = 1000
        self.MAX_TIMEOUT = 300
        self.MAX_FILENAME_LENGTH = 255
    
    def validate_network_target(self, target: str) -> Dict[str, Any]:
        """
        Validate network target (IP address or CIDR notation)
        Returns validation result with sanitized value
        """
        result = {
            'valid': False,
            'sanitized': None,
            'errors': [],
            'warnings': []
        }
        
        if not target or not isinstance(target, str):
            result['errors'].append("Target cannot be empty")
            return result
        
        # Remove whitespace and convert to lowercase
        target = target.strip().lower()
        
        # Check for dangerous patterns
        if self._contains_dangerous_patterns(target):
            result['errors'].append("Target contains potentially dangerous characters")
            return result
        
        # Validate CIDR notation or single IP
        try:
            network = ipaddress.ip_network(target, strict=False)
            
            # Security checks
            if network.is_multicast:
                result['warnings'].append("Multicast address detected")
            
            if network.is_loopback and not self._is_localhost_allowed():
                result['warnings'].append("Loopback address - ensure this is intentional")
            
            # Check for overly broad scans
            if network.num_addresses > 65536:  # /16 or larger
                result['warnings'].append(f"Large network scan ({network.num_addresses} addresses) - consider smaller ranges")
            
            result['valid'] = True
            result['sanitized'] = str(network)
            
        except ValueError as e:
            result['errors'].append(f"Invalid network format: {str(e)}")
        
        return result
    
    def validate_port_list(self, ports: Union[str, List[int]]) -> Dict[str, Any]:
        """
        Validate port list or port range
        """
        result = {
            'valid': False,
            'sanitized': [],
            'errors': [],
            'warnings': []
        }
        
        if isinstance(ports, str):
            ports = self._parse_port_string(ports)
        
        if not ports:
            result['errors'].append("Port list cannot be empty")
            return result
        
        sanitized_ports = []
        for port in ports:
            if not isinstance(port, int):
                try:
                    port = int(port)
                except ValueError:
                    result['errors'].append(f"Invalid port number: {port}")
                    continue
            
            if not (self.MIN_PORT <= port <= self.MAX_PORT):
                result['errors'].append(f"Port {port} out of valid range ({self.MIN_PORT}-{self.MAX_PORT})")
                continue
            
            sanitized_ports.append(port)
        
        if sanitized_ports:
            result['valid'] = True
            result['sanitized'] = sorted(list(set(sanitized_ports)))  # Remove duplicates and sort
            
            # Warning for large port ranges
            if len(result['sanitized']) > 1000:
                result['warnings'].append(f"Large port range ({len(result['sanitized'])} ports) may impact performance")
        
        return result
    
    def validate_thread_count(self, threads: Union[str, int]) -> Dict[str, Any]:
        """
        Validate thread count parameter
        """
        result = {
            'valid': False,
            'sanitized': None,
            'errors': [],
            'warnings': []
        }
        
        try:
            threads = int(threads)
        except (ValueError, TypeError):
            result['errors'].append("Thread count must be a number")
            return result
        
        if threads < 1:
            result['errors'].append("Thread count must be at least 1")
            return result
        
        if threads > self.MAX_THREADS:
            result['errors'].append(f"Thread count cannot exceed {self.MAX_THREADS}")
            return result
        
        # Performance warnings
        if threads > 200:
            result['warnings'].append("High thread count may impact system performance")
        
        result['valid'] = True
        result['sanitized'] = threads
        
        return result
    
    def validate_timeout(self, timeout: Union[str, int, float]) -> Dict[str, Any]:
        """
        Validate timeout parameter
        """
        result = {
            'valid': False,
            'sanitized': None,
            'errors': [],
            'warnings': []
        }
        
        try:
            timeout = float(timeout)
        except (ValueError, TypeError):
            result['errors'].append("Timeout must be a number")
            return result
        
        if timeout <= 0:
            result['errors'].append("Timeout must be greater than 0")
            return result
        
        if timeout > self.MAX_TIMEOUT:
            result['errors'].append(f"Timeout cannot exceed {self.MAX_TIMEOUT} seconds")
            return result
        
        # Performance warnings
        if timeout > 30:
            result['warnings'].append("High timeout value may slow down scans")
        
        result['valid'] = True
        result['sanitized'] = timeout
        
        return result
    
    def validate_filename(self, filename: str) -> Dict[str, Any]:
        """
        Validate output filename for security
        """
        result = {
            'valid': False,
            'sanitized': None,
            'errors': [],
            'warnings': []
        }
        
        if not filename or not isinstance(filename, str):
            result['errors'].append("Filename cannot be empty")
            return result
        
        # Remove dangerous characters and patterns
        if self._contains_dangerous_patterns(filename):
            result['errors'].append("Filename contains potentially dangerous characters")
            return result
        
        # Check for path traversal
        if '..' in filename or filename.startswith('/') or ':' in filename:
            result['errors'].append("Filename contains path traversal patterns")
            return result
        
        # Length check
        if len(filename) > self.MAX_FILENAME_LENGTH:
            result['errors'].append(f"Filename too long (max {self.MAX_FILENAME_LENGTH} characters)")
            return result
        
        # Sanitize filename
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        sanitized = re.sub(r'[^\w\-_.]', '_', sanitized)
        
        result['valid'] = True
        result['sanitized'] = sanitized
        
        return result
    
    def validate_exclusion_list(self, exclusions: List[str]) -> Dict[str, Any]:
        """
        Validate IP exclusion list
        """
        result = {
            'valid': True,
            'sanitized': [],
            'errors': [],
            'warnings': []
        }
        
        if not exclusions:
            return result
        
        for exclusion in exclusions:
            if not isinstance(exclusion, str):
                result['errors'].append(f"Invalid exclusion format: {exclusion}")
                continue
            
            # Check for dangerous patterns
            if self._contains_dangerous_patterns(exclusion):
                result['errors'].append(f"Exclusion contains dangerous patterns: {exclusion}")
                continue
            
            # Validate IP range or single IP
            try:
                if '-' in exclusion:
                    # IP range format (e.g., 192.168.1.1-192.168.1.10)
                    start_ip, end_ip = exclusion.split('-', 1)
                    ipaddress.ip_address(start_ip.strip())
                    ipaddress.ip_address(end_ip.strip())
                else:
                    # Single IP or CIDR
                    ipaddress.ip_network(exclusion.strip(), strict=False)
                
                result['sanitized'].append(exclusion.strip())
                
            except ValueError:
                result['errors'].append(f"Invalid exclusion format: {exclusion}")
        
        if result['errors']:
            result['valid'] = False
        
        return result
    
    def _contains_dangerous_patterns(self, input_str: str) -> bool:
        """
        Check if input contains dangerous patterns
        """
        for pattern in self.compiled_patterns:
            if pattern.search(input_str):
                return True
        return False
    
    def _parse_port_string(self, port_str: str) -> List[int]:
        """
        Parse port string into list of integers
        Supports formats: "80,443,8080" or "80-90,443"
        """
        ports = []
        
        for part in port_str.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-', 1))
                    ports.extend(range(start, end + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    continue
        
        return ports
    
    def _is_localhost_allowed(self) -> bool:
        """
        Check if localhost scanning is allowed (can be configured)
        """
        return True  # For now, allow localhost - can be made configurable
    
    def sanitize_command_args(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive sanitization of all command line arguments
        """
        sanitized = {}
        errors = []
        warnings = []
        
        # Validate network target
        if 'network' in args:
            result = self.validate_network_target(args['network'])
            if result['valid']:
                sanitized['network'] = result['sanitized']
            else:
                errors.extend(result['errors'])
            warnings.extend(result['warnings'])
        
        # Validate threads
        if 'threads' in args:
            result = self.validate_thread_count(args['threads'])
            if result['valid']:
                sanitized['threads'] = result['sanitized']
            else:
                errors.extend(result['errors'])
            warnings.extend(result['warnings'])
        
        # Validate timeout
        if 'timeout' in args:
            result = self.validate_timeout(args['timeout'])
            if result['valid']:
                sanitized['timeout'] = result['sanitized']
            else:
                errors.extend(result['errors'])
            warnings.extend(result['warnings'])
        
        # Validate output filename
        if 'output' in args and args['output']:
            result = self.validate_filename(args['output'])
            if result['valid']:
                sanitized['output'] = result['sanitized']
            else:
                errors.extend(result['errors'])
            warnings.extend(result['warnings'])
        
        # Validate exclusions
        if 'exclude' in args and args['exclude']:
            result = self.validate_exclusion_list(args['exclude'])
            if result['valid']:
                sanitized['exclude'] = result['sanitized']
            else:
                errors.extend(result['errors'])
            warnings.extend(result['warnings'])
        
        # Copy other safe parameters
        safe_params = ['ping_only', 'nmap', 'no_smart_filter', 'format', 'vuln_report']
        for param in safe_params:
            if param in args:
                sanitized[param] = args[param]
        
        return {
            'sanitized_args': sanitized,
            'errors': errors,
            'warnings': warnings,
            'valid': len(errors) == 0
        }