#!/usr/bin/env python3
"""
Secure Secrets Management Module
Implements secure handling of API keys, credentials, and sensitive configuration data.
Follows OWASP guidelines for secrets management and DevSecOps best practices.

Author: Gustavo Valente
Version: 2.0
"""

import os
import json
import base64
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import keyring
import getpass

class SecretsManager:
    """
    Secure secrets management class implementing:
    - Encrypted storage of sensitive data
    - Environment variable fallback
    - System keyring integration
    - Secure configuration loading
    - Audit logging for secret access
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Configuration directory
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            self.config_dir = Path.home() / '.netmapper'
        
        self.config_dir.mkdir(exist_ok=True, mode=0o700)  # Secure permissions
        
        # Encrypted secrets file
        self.secrets_file = self.config_dir / 'secrets.enc'
        self.config_file = self.config_dir / 'config.json'
        
        # Service name for keyring
        self.service_name = 'netmapper'
        
        # Initialize encryption key
        self._encryption_key = None
        
        # Default configuration
        self.default_config = {
            'security': {
                'max_login_attempts': 3,
                'session_timeout': 3600,
                'require_2fa': False,
                'audit_logging': True
            },
            'scanning': {
                'default_timeout': 5,
                'max_threads': 100,
                'rate_limit_per_second': 10,
                'blacklist_networks': ['127.0.0.0/8', '169.254.0.0/16']
            },
            'reporting': {
                'auto_export': False,
                'retention_days': 30,
                'encrypt_reports': True
            }
        }
    
    def initialize_secrets_store(self, master_password: Optional[str] = None) -> bool:
        """
        Initialize the encrypted secrets store
        """
        try:
            if not master_password:
                master_password = self._get_master_password()
            
            # Generate encryption key from password
            self._encryption_key = self._derive_key(master_password)
            
            # Create empty secrets file if it doesn't exist
            if not self.secrets_file.exists():
                self._save_encrypted_secrets({})
                self.logger.info("Initialized new secrets store")
            
            # Test decryption to verify password
            self._load_encrypted_secrets()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize secrets store: {e}")
            return False
    
    def store_secret(self, key: str, value: str, category: str = 'general') -> bool:
        """
        Store a secret securely
        """
        try:
            secrets = self._load_encrypted_secrets()
            
            if category not in secrets:
                secrets[category] = {}
            
            # Hash the value for audit purposes (not stored)
            value_hash = hashlib.sha256(value.encode()).hexdigest()[:8]
            
            secrets[category][key] = {
                'value': value,
                'created_at': self._get_timestamp(),
                'hash': value_hash
            }
            
            self._save_encrypted_secrets(secrets)
            
            # Audit log
            self.logger.info(f"Secret stored: {category}.{key} (hash: {value_hash})")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store secret {key}: {e}")
            return False
    
    def get_secret(self, key: str, category: str = 'general', fallback_env: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a secret with environment variable fallback
        """
        try:
            # Try encrypted store first
            secrets = self._load_encrypted_secrets()
            
            if category in secrets and key in secrets[category]:
                value = secrets[category][key]['value']
                self.logger.debug(f"Retrieved secret from store: {category}.{key}")
                return value
            
            # Fallback to environment variable
            if fallback_env:
                env_value = os.getenv(fallback_env)
                if env_value:
                    self.logger.debug(f"Retrieved secret from environment: {fallback_env}")
                    return env_value
            
            # Fallback to system keyring
            try:
                keyring_value = keyring.get_password(self.service_name, f"{category}.{key}")
                if keyring_value:
                    self.logger.debug(f"Retrieved secret from keyring: {category}.{key}")
                    return keyring_value
            except Exception:
                pass  # Keyring not available
            
            self.logger.warning(f"Secret not found: {category}.{key}")
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve secret {key}: {e}")
            return None
    
    def delete_secret(self, key: str, category: str = 'general') -> bool:
        """
        Delete a secret
        """
        try:
            secrets = self._load_encrypted_secrets()
            
            if category in secrets and key in secrets[category]:
                del secrets[category][key]
                self._save_encrypted_secrets(secrets)
                
                # Also try to delete from keyring
                try:
                    keyring.delete_password(self.service_name, f"{category}.{key}")
                except Exception:
                    pass
                
                self.logger.info(f"Secret deleted: {category}.{key}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to delete secret {key}: {e}")
            return False
    
    def list_secrets(self, category: Optional[str] = None) -> Dict[str, Any]:
        """
        List stored secrets (without values)
        """
        try:
            secrets = self._load_encrypted_secrets()
            
            result = {}
            
            if category:
                if category in secrets:
                    result[category] = {
                        key: {
                            'created_at': data.get('created_at'),
                            'hash': data.get('hash')
                        }
                        for key, data in secrets[category].items()
                    }
            else:
                for cat, cat_secrets in secrets.items():
                    result[cat] = {
                        key: {
                            'created_at': data.get('created_at'),
                            'hash': data.get('hash')
                        }
                        for key, data in cat_secrets.items()
                    }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to list secrets: {e}")
            return {}
    
    def load_config(self) -> Dict[str, Any]:
        """
        Load configuration with secure defaults
        """
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                
                # Merge with defaults
                merged_config = self._deep_merge(self.default_config, config)
                return merged_config
            else:
                # Create default config
                self.save_config(self.default_config)
                return self.default_config.copy()
                
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            return self.default_config.copy()
    
    def save_config(self, config: Dict[str, Any]) -> bool:
        """
        Save configuration securely
        """
        try:
            # Validate configuration
            if not self._validate_config(config):
                return False
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Set secure permissions
            os.chmod(self.config_file, 0o600)
            
            self.logger.info("Configuration saved successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
            return False
    
    def get_api_credentials(self, service: str) -> Optional[Dict[str, str]]:
        """
        Get API credentials for external services
        """
        api_key = self.get_secret('api_key', f'api.{service}', f'{service.upper()}_API_KEY')
        api_secret = self.get_secret('api_secret', f'api.{service}', f'{service.upper()}_API_SECRET')
        
        if api_key:
            result = {'api_key': api_key}
            if api_secret:
                result['api_secret'] = api_secret
            return result
        
        return None
    
    def store_api_credentials(self, service: str, api_key: str, api_secret: Optional[str] = None) -> bool:
        """
        Store API credentials for external services
        """
        success = self.store_secret('api_key', api_key, f'api.{service}')
        
        if api_secret:
            success = success and self.store_secret('api_secret', api_secret, f'api.{service}')
        
        return success
    
    def _derive_key(self, password: str) -> bytes:
        """
        Derive encryption key from password using PBKDF2
        """
        # Use a fixed salt for consistency (in production, use random salt per user)
        salt = b'netmapper_salt_v1'  # Should be random and stored securely
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def _load_encrypted_secrets(self) -> Dict[str, Any]:
        """
        Load and decrypt secrets from file
        """
        if not self.secrets_file.exists():
            return {}
        
        if not self._encryption_key:
            raise ValueError("Encryption key not initialized")
        
        try:
            with open(self.secrets_file, 'rb') as f:
                encrypted_data = f.read()
            
            fernet = Fernet(self._encryption_key)
            decrypted_data = fernet.decrypt(encrypted_data)
            
            return json.loads(decrypted_data.decode())
            
        except Exception as e:
            raise ValueError(f"Failed to decrypt secrets: {e}")
    
    def _save_encrypted_secrets(self, secrets: Dict[str, Any]) -> None:
        """
        Encrypt and save secrets to file
        """
        if not self._encryption_key:
            raise ValueError("Encryption key not initialized")
        
        try:
            fernet = Fernet(self._encryption_key)
            
            json_data = json.dumps(secrets, indent=2)
            encrypted_data = fernet.encrypt(json_data.encode())
            
            with open(self.secrets_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set secure permissions
            os.chmod(self.secrets_file, 0o600)
            
        except Exception as e:
            raise ValueError(f"Failed to encrypt secrets: {e}")
    
    def _get_master_password(self) -> str:
        """
        Get master password from user or environment
        """
        # Try environment variable first
        env_password = os.getenv('NETMAPPER_MASTER_PASSWORD')
        if env_password:
            return env_password
        
        # Prompt user
        return getpass.getpass("Enter master password for secrets store: ")
    
    def _get_timestamp(self) -> str:
        """
        Get current timestamp
        """
        from datetime import datetime
        return datetime.utcnow().isoformat()
    
    def _deep_merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deep merge two dictionaries
        """
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate configuration for security issues
        """
        # Check for dangerous values
        security_config = config.get('security', {})
        
        # Validate timeout values
        if security_config.get('session_timeout', 0) < 300:  # Minimum 5 minutes
            self.logger.warning("Session timeout too low, using minimum value")
            security_config['session_timeout'] = 300
        
        # Validate thread limits
        scanning_config = config.get('scanning', {})
        if scanning_config.get('max_threads', 0) > 1000:
            self.logger.warning("Thread limit too high, capping at 1000")
            scanning_config['max_threads'] = 1000
        
        return True

# Singleton instance
_secrets_manager = None

def get_secrets_manager() -> SecretsManager:
    """
    Get singleton secrets manager instance
    """
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager