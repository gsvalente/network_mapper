#!/usr/bin/env python3
"""
Secure Configuration Module
Implements secure-by-default configurations and fail-safe mechanisms
for the Network Mapper application.

Author: Gustavo Valente
Version: 2.0 (DevSecOps Enhanced)
"""

import os
import json
import logging
import tempfile
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import stat


class SecurityLevel(Enum):
    """Security configuration levels"""
    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"


class ConfigValidationError(Exception):
    """Custom exception for configuration validation errors"""
    pass


@dataclass
class SecurityConfig:
    """Security configuration settings"""
    # Network security
    max_concurrent_scans: int = 10
    scan_timeout: int = 30
    rate_limit_per_second: int = 5
    max_ports_per_scan: int = 1000
    
    # Input validation
    max_target_length: int = 253  # Max domain name length
    max_filename_length: int = 255
    allowed_file_extensions: List[str] = None
    blocked_ip_ranges: List[str] = None
    
    # Logging and monitoring
    log_level: str = "INFO"
    log_retention_days: int = 90
    enable_security_logging: bool = True
    log_sensitive_data: bool = False
    
    # Cryptography
    min_key_length: int = 2048
    allowed_ciphers: List[str] = None
    require_tls: bool = True
    verify_certificates: bool = True
    
    # File system
    temp_dir_permissions: int = 0o700
    log_file_permissions: int = 0o640
    config_file_permissions: int = 0o600
    
    # Process security
    drop_privileges: bool = True
    chroot_enabled: bool = False
    resource_limits: Dict[str, int] = None
    
    # Fail-safe mechanisms
    fail_secure: bool = True
    auto_recovery: bool = True
    emergency_shutdown: bool = True
    
    def __post_init__(self):
        """Initialize default values for mutable fields"""
        if self.allowed_file_extensions is None:
            self.allowed_file_extensions = ['.json', '.csv', '.txt', '.xml', '.html']
        
        if self.blocked_ip_ranges is None:
            self.blocked_ip_ranges = [
                '0.0.0.0/8',      # "This" network
                '10.0.0.0/8',     # Private network
                '127.0.0.0/8',    # Loopback
                '169.254.0.0/16', # Link-local
                '172.16.0.0/12',  # Private network
                '192.168.0.0/16', # Private network
                '224.0.0.0/4',    # Multicast
                '240.0.0.0/4'     # Reserved
            ]
        
        if self.allowed_ciphers is None:
            self.allowed_ciphers = [
                'AES256-GCM-SHA384',
                'AES128-GCM-SHA256',
                'ECDHE-RSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES128-GCM-SHA256'
            ]
        
        if self.resource_limits is None:
            self.resource_limits = {
                'max_memory_mb': 512,
                'max_cpu_percent': 50,
                'max_file_descriptors': 1024,
                'max_processes': 10
            }


class SecureConfigManager:
    """
    Manages secure configuration with fail-safe mechanisms
    """
    
    def __init__(self, config_dir: str = "config", security_level: SecurityLevel = SecurityLevel.STANDARD):
        """
        Initialize secure configuration manager
        
        Args:
            config_dir: Directory to store configuration files
            security_level: Security level to apply
        """
        self.config_dir = config_dir
        self.security_level = security_level
        self.config_file = os.path.join(config_dir, "security_config.json")
        self.backup_config_file = os.path.join(config_dir, "security_config.backup.json")
        
        # Create secure config directory
        self._create_secure_directory()
        
        # Load or create configuration
        self.config = self._load_or_create_config()
        
        # Apply security level settings
        self._apply_security_level()
        
        # Setup logging
        self._setup_secure_logging()
        
        # Initialize fail-safe mechanisms
        self._init_failsafe_mechanisms()
    
    def _create_secure_directory(self):
        """Create configuration directory with secure permissions"""
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            
            # Set secure permissions (owner read/write/execute only)
            os.chmod(self.config_dir, 0o700)
            
            # Create subdirectories
            for subdir in ['logs', 'backups', 'temp']:
                subdir_path = os.path.join(self.config_dir, subdir)
                os.makedirs(subdir_path, exist_ok=True)
                os.chmod(subdir_path, 0o700)
                
        except Exception as e:
            raise ConfigValidationError(f"Failed to create secure directory: {e}")
    
    def _load_or_create_config(self) -> SecurityConfig:
        """Load existing configuration or create default secure configuration"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Validate configuration integrity
                if not self._validate_config_integrity(config_data):
                    logging.warning("Configuration integrity check failed, using backup")
                    return self._load_backup_config()
                
                return SecurityConfig(**config_data)
                
            except Exception as e:
                logging.error(f"Failed to load configuration: {e}")
                return self._load_backup_config()
        else:
            # Create default secure configuration
            config = SecurityConfig()
            self._save_config(config)
            return config
    
    def _load_backup_config(self) -> SecurityConfig:
        """Load backup configuration or create default"""
        if os.path.exists(self.backup_config_file):
            try:
                with open(self.backup_config_file, 'r') as f:
                    config_data = json.load(f)
                return SecurityConfig(**config_data)
            except Exception as e:
                logging.error(f"Failed to load backup configuration: {e}")
        
        # Return default configuration as last resort
        return SecurityConfig()
    
    def _validate_config_integrity(self, config_data: Dict[str, Any]) -> bool:
        """Validate configuration file integrity"""
        try:
            # Check required fields
            required_fields = ['max_concurrent_scans', 'scan_timeout', 'log_level']
            for field in required_fields:
                if field not in config_data:
                    return False
            
            # Validate value ranges
            if config_data.get('max_concurrent_scans', 0) <= 0:
                return False
            
            if config_data.get('scan_timeout', 0) <= 0:
                return False
            
            # Validate log level
            valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if config_data.get('log_level') not in valid_log_levels:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _apply_security_level(self):
        """Apply security settings based on security level"""
        if self.security_level == SecurityLevel.MINIMAL:
            self.config.max_concurrent_scans = 20
            self.config.rate_limit_per_second = 10
            self.config.log_level = "WARNING"
            self.config.verify_certificates = False
            
        elif self.security_level == SecurityLevel.STANDARD:
            # Default settings are already standard
            pass
            
        elif self.security_level == SecurityLevel.STRICT:
            self.config.max_concurrent_scans = 5
            self.config.rate_limit_per_second = 2
            self.config.scan_timeout = 15
            self.config.log_level = "INFO"
            self.config.log_sensitive_data = False
            self.config.verify_certificates = True
            self.config.fail_secure = True
            
        elif self.security_level == SecurityLevel.PARANOID:
            self.config.max_concurrent_scans = 1
            self.config.rate_limit_per_second = 1
            self.config.scan_timeout = 10
            self.config.max_ports_per_scan = 100
            self.config.log_level = "DEBUG"
            self.config.log_sensitive_data = False
            self.config.verify_certificates = True
            self.config.fail_secure = True
            self.config.drop_privileges = True
            self.config.emergency_shutdown = True
    
    def _setup_secure_logging(self):
        """Setup secure logging configuration"""
        log_dir = os.path.join(self.config_dir, 'logs')
        log_file = os.path.join(log_dir, 'security.log')
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, self.config.log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        # Set secure permissions on log file
        if os.path.exists(log_file):
            os.chmod(log_file, self.config.log_file_permissions)
    
    def _init_failsafe_mechanisms(self):
        """Initialize fail-safe mechanisms"""
        # Create emergency shutdown file
        self.emergency_file = os.path.join(self.config_dir, '.emergency_shutdown')
        
        # Setup resource monitoring
        self._setup_resource_monitoring()
        
        # Create configuration backup
        self._create_config_backup()
    
    def _setup_resource_monitoring(self):
        """Setup resource monitoring for fail-safe mechanisms"""
        try:
            import psutil
            
            # Check system resources
            memory_percent = psutil.virtual_memory().percent
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Log resource usage
            logging.info(f"System resources - Memory: {memory_percent}%, CPU: {cpu_percent}%")
            
            # Trigger fail-safe if resources are critically low
            if memory_percent > 90 or cpu_percent > 95:
                logging.warning("Critical resource usage detected")
                if self.config.fail_secure:
                    self._trigger_failsafe("high_resource_usage")
                    
        except ImportError:
            logging.warning("psutil not available for resource monitoring")
        except Exception as e:
            logging.error(f"Resource monitoring error: {e}")
    
    def _create_config_backup(self):
        """Create backup of current configuration"""
        try:
            if hasattr(self, 'config') and self.config:
                config_data = asdict(self.config)
                with open(self.backup_config_file, 'w') as f:
                    json.dump(config_data, f, indent=2)
                
                # Set secure permissions
                os.chmod(self.backup_config_file, self.config.config_file_permissions)
            else:
                logging.warning("Configuration not yet initialized, skipping backup")
            
        except Exception as e:
            logging.error(f"Failed to create configuration backup: {e}")
    
    def _save_config(self, config: SecurityConfig):
        """Save configuration with secure permissions"""
        try:
            config_data = asdict(config)
            
            # Write to temporary file first
            temp_file = self.config_file + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            # Set secure permissions
            os.chmod(temp_file, config.config_file_permissions)
            
            # Atomic move to final location
            os.replace(temp_file, self.config_file)
            
            # Create backup
            self._create_config_backup()
            
        except Exception as e:
            logging.error(f"Failed to save configuration: {e}")
            raise ConfigValidationError(f"Configuration save failed: {e}")
    
    def update_config(self, **kwargs) -> bool:
        """
        Update configuration with validation
        
        Args:
            **kwargs: Configuration parameters to update
            
        Returns:
            bool: Success status
        """
        try:
            # Create updated configuration
            current_config = asdict(self.config)
            current_config.update(kwargs)
            
            # Validate new configuration
            new_config = SecurityConfig(**current_config)
            
            if not self._validate_security_constraints(new_config):
                raise ConfigValidationError("Security constraints validation failed")
            
            # Save and apply new configuration
            self._save_config(new_config)
            self.config = new_config
            
            logging.info("Configuration updated successfully")
            return True
            
        except Exception as e:
            logging.error(f"Configuration update failed: {e}")
            return False
    
    def _validate_security_constraints(self, config: SecurityConfig) -> bool:
        """Validate security constraints"""
        try:
            # Check concurrent scans limit
            if config.max_concurrent_scans > 100:
                logging.error("Max concurrent scans exceeds security limit")
                return False
            
            # Check timeout values
            if config.scan_timeout > 300:  # 5 minutes max
                logging.error("Scan timeout exceeds security limit")
                return False
            
            # Check rate limiting
            if config.rate_limit_per_second > 50:
                logging.error("Rate limit exceeds security threshold")
                return False
            
            # Validate file permissions
            if config.temp_dir_permissions & 0o077:  # Others should have no access
                logging.error("Temp directory permissions too permissive")
                return False
            
            return True
            
        except Exception as e:
            logging.error(f"Security constraint validation error: {e}")
            return False
    
    def _trigger_failsafe(self, reason: str):
        """Trigger fail-safe mechanisms"""
        logging.critical(f"Fail-safe triggered: {reason}")
        
        try:
            # Create emergency shutdown marker
            with open(self.emergency_file, 'w') as f:
                f.write(f"Emergency shutdown triggered: {reason}\n")
                f.write(f"Timestamp: {os.times()}\n")
            
            # Implement fail-safe actions based on configuration
            if self.config.emergency_shutdown:
                logging.critical("Emergency shutdown initiated")
                # In a real implementation, this would gracefully shut down the application
                
            if self.config.auto_recovery:
                logging.info("Attempting auto-recovery")
                self._attempt_recovery()
                
        except Exception as e:
            logging.error(f"Fail-safe mechanism error: {e}")
    
    def _attempt_recovery(self):
        """Attempt automatic recovery"""
        try:
            # Reset to safe configuration
            safe_config = SecurityConfig()
            safe_config.max_concurrent_scans = 1
            safe_config.rate_limit_per_second = 1
            safe_config.scan_timeout = 10
            
            self.config = safe_config
            self._save_config(safe_config)
            
            logging.info("Auto-recovery completed - safe configuration applied")
            
        except Exception as e:
            logging.error(f"Auto-recovery failed: {e}")
    
    def is_emergency_shutdown(self) -> bool:
        """Check if emergency shutdown is active"""
        return os.path.exists(self.emergency_file)
    
    def clear_emergency_shutdown(self) -> bool:
        """Clear emergency shutdown state"""
        try:
            if os.path.exists(self.emergency_file):
                os.remove(self.emergency_file)
                logging.info("Emergency shutdown cleared")
                return True
            return False
            
        except Exception as e:
            logging.error(f"Failed to clear emergency shutdown: {e}")
            return False
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status"""
        return {
            "security_level": self.security_level.value,
            "emergency_shutdown": self.is_emergency_shutdown(),
            "config_integrity": self._validate_config_integrity(asdict(self.config)),
            "fail_secure_enabled": self.config.fail_secure,
            "auto_recovery_enabled": self.config.auto_recovery,
            "security_logging_enabled": self.config.enable_security_logging,
            "certificate_verification": self.config.verify_certificates,
            "current_limits": {
                "max_concurrent_scans": self.config.max_concurrent_scans,
                "rate_limit_per_second": self.config.rate_limit_per_second,
                "scan_timeout": self.config.scan_timeout
            }
        }
    
    def export_config(self, output_path: str) -> bool:
        """Export configuration to file"""
        try:
            config_data = asdict(self.config)
            config_data['security_level'] = self.security_level.value
            config_data['export_timestamp'] = str(os.times())
            
            with open(output_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            # Set secure permissions
            os.chmod(output_path, 0o600)
            
            return True
            
        except Exception as e:
            logging.error(f"Configuration export failed: {e}")
            return False
    
    def import_config(self, config_path: str) -> bool:
        """Import configuration from file with validation"""
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            
            # Remove metadata fields
            config_data.pop('security_level', None)
            config_data.pop('export_timestamp', None)
            
            # Validate and apply configuration
            new_config = SecurityConfig(**config_data)
            
            if not self._validate_security_constraints(new_config):
                raise ConfigValidationError("Imported configuration violates security constraints")
            
            self._save_config(new_config)
            self.config = new_config
            
            logging.info("Configuration imported successfully")
            return True
            
        except Exception as e:
            logging.error(f"Configuration import failed: {e}")
            return False


# Secure configuration presets
SECURITY_PRESETS = {
    SecurityLevel.MINIMAL: {
        "description": "Minimal security for development/testing",
        "use_case": "Development environments with trusted networks"
    },
    SecurityLevel.STANDARD: {
        "description": "Balanced security for general use",
        "use_case": "Production environments with standard security requirements"
    },
    SecurityLevel.STRICT: {
        "description": "Enhanced security for sensitive environments",
        "use_case": "High-security environments with strict compliance requirements"
    },
    SecurityLevel.PARANOID: {
        "description": "Maximum security with minimal functionality",
        "use_case": "Critical infrastructure or highly sensitive operations"
    }
}


# Example usage and testing
if __name__ == "__main__":
    # Test secure configuration manager
    config_manager = SecureConfigManager(security_level=SecurityLevel.STRICT)
    
    print("Secure Configuration Manager initialized")
    print(f"Security Level: {config_manager.security_level.value}")
    print(f"Emergency Shutdown Active: {config_manager.is_emergency_shutdown()}")
    
    # Test configuration update
    success = config_manager.update_config(max_concurrent_scans=3, scan_timeout=20)
    print(f"Configuration update: {'Success' if success else 'Failed'}")
    
    # Get security status
    status = config_manager.get_security_status()
    print(f"Security Status: {json.dumps(status, indent=2)}")
    
    # Test export/import
    export_path = "test_config_export.json"
    if config_manager.export_config(export_path):
        print(f"Configuration exported to {export_path}")
        
        # Clean up
        os.remove(export_path)
    
    print("Secure configuration testing completed!")