"""
Network Mapper Modules Package

This package contains modular components for the Network Mapper tool:
- vulnerability_scanner: Vulnerability assessment and database
- device_detector: Device type detection and classification
- network_utils: Network scanning utilities (ping, port scan, service detection)
- report_generator: Export and reporting functionality
"""

__version__ = "1.2.0"
__author__ = "Gustavo Valente"

# Import main classes for easy access
from .vulnerability_scanner import VulnerabilityScanner
from .device_detector import DeviceDetector
from .network_utils import NetworkUtils
from .report_generator import ReportGenerator

__all__ = [
    'VulnerabilityScanner',
    'DeviceDetector', 
    'NetworkUtils',
    'ReportGenerator'
]