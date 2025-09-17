"""
Device Detector Module

This module handles device type detection and classification
based on open ports, services, and hostname patterns.
"""

class DeviceDetector:
    """
    Handles device type detection and classification
    """
    
    def __init__(self):
        self.device_indicators = self._load_device_indicators()
    
    def _load_device_indicators(self):
        """Load device type indicators and patterns"""
        return {
            'router': {
                'ports': [80, 443, 23, 22, 161],
                'services': ['http', 'https', 'telnet', 'ssh', 'snmp'],
                'hostnames': ['router', 'gateway', 'gw', 'rt', 'cisco', 'netgear', 'linksys', 'asus']
            },
            'printer': {
                'ports': [631, 9100, 515, 80, 443],
                'services': ['ipp', 'jetdirect', 'lpd', 'http'],
                'hostnames': ['printer', 'print', 'hp', 'canon', 'epson', 'brother', 'lexmark']
            },
            'mobile': {
                'ports': [62078, 5353, 1024, 49152],
                'services': ['airplay', 'mdns', 'bonjour'],
                'hostnames': ['iphone', 'android', 'mobile', 'phone', 'tablet', 'ipad']
            },
            'smart_tv': {
                'ports': [8008, 8009, 7001, 80, 443, 1900],
                'services': ['chromecast', 'upnp', 'dlna', 'http'],
                'hostnames': ['tv', 'samsung', 'lg', 'sony', 'chromecast', 'roku', 'appletv']
            },
            'iot_device': {
                'ports': [80, 443, 1883, 8883, 5683],
                'services': ['http', 'https', 'mqtt', 'coap'],
                'hostnames': ['iot', 'sensor', 'camera', 'doorbell', 'thermostat', 'alexa', 'nest']
            },
            'nas_storage': {
                'ports': [80, 443, 22, 21, 139, 445, 548, 2049],
                'services': ['http', 'https', 'ssh', 'ftp', 'smb', 'afp', 'nfs'],
                'hostnames': ['nas', 'storage', 'synology', 'qnap', 'drobo', 'freenas']
            },
            'gaming_console': {
                'ports': [80, 443, 9293, 1935],
                'services': ['http', 'https', 'xbox', 'playstation'],
                'hostnames': ['xbox', 'playstation', 'ps4', 'ps5', 'nintendo', 'switch']
            },
            'windows_system': {
                'ports': [135, 139, 445, 3389],
                'services': ['rpc', 'netbios', 'smb', 'rdp'],
                'hostnames': ['win', 'windows', 'pc', 'desktop', 'workstation']
            },
            'linux_system': {
                'ports': [22, 80, 443],
                'services': ['ssh', 'http', 'https'],
                'hostnames': ['linux', 'ubuntu', 'debian', 'centos', 'redhat', 'server']
            }
        }
    
    def detect_device_type(self, ip, open_ports, services, hostname):
        """
        Detect device type based on open ports, services, and hostname
        
        Args:
            ip (str): IP address of the device
            open_ports (list): List of open ports
            services (dict): Dictionary of port:service mappings
            hostname (str): Hostname of the device
            
        Returns:
            str: Device type with confidence percentage
        """
        scores = {}
        hostname_lower = hostname.lower() if hostname != 'Unknown' else ''
        
        for device_type, indicators in self.device_indicators.items():
            score = self._calculate_device_score(
                open_ports, services, hostname_lower, indicators
            )
            
            if score > 0:
                scores[device_type] = score
        
        if scores:
            # Return the device type with highest score
            best_match = max(scores, key=scores.get)
            confidence = min(scores[best_match] * 10, 95)  # Cap at 95%
            return f"{best_match.replace('_', ' ').title()} ({confidence}%)"
        
        # Fallback based on common patterns
        return self._fallback_detection(open_ports)
    
    def _calculate_device_score(self, open_ports, services, hostname_lower, indicators):
        """
        Calculate device type score based on indicators
        
        Args:
            open_ports (list): List of open ports
            services (dict): Dictionary of port:service mappings
            hostname_lower (str): Lowercase hostname
            indicators (dict): Device type indicators
            
        Returns:
            int: Device type score
        """
        score = 0
        
        # Check hostname indicators (highest weight)
        for keyword in indicators['hostnames']:
            if keyword in hostname_lower:
                score += 3
        
        # Check port indicators (medium weight)
        matching_ports = set(open_ports) & set(indicators['ports'])
        score += len(matching_ports) * 2
        
        # Check service indicators (medium weight)
        for service in services.values():
            service_lower = service.lower()
            for indicator in indicators['services']:
                if indicator in service_lower:
                    score += 2
        
        return score
    
    def _fallback_detection(self, open_ports):
        """
        Fallback device detection based on common port patterns
        
        Args:
            open_ports (list): List of open ports
            
        Returns:
            str: Device type with confidence
        """
        if 22 in open_ports and 80 in open_ports:
            return "Server/Computer (60%)"
        elif 3389 in open_ports:
            return "Windows Computer (70%)"
        elif 22 in open_ports:
            return "Linux/Unix System (65%)"
        elif 135 in open_ports or 139 in open_ports or 445 in open_ports:
            return "Windows System (60%)"
        else:
            return "Unknown Device"
    
    def get_device_category(self, device_type_string):
        """
        Extract device category from device type string
        
        Args:
            device_type_string (str): Device type with confidence (e.g., "Router (85%)")
            
        Returns:
            str: Device category
        """
        if "(" in device_type_string:
            return device_type_string.split("(")[0].strip()
        return device_type_string
    
    def get_confidence_level(self, device_type_string):
        """
        Extract confidence level from device type string
        
        Args:
            device_type_string (str): Device type with confidence (e.g., "Router (85%)")
            
        Returns:
            int: Confidence percentage
        """
        if "(" in device_type_string and "%" in device_type_string:
            try:
                confidence_str = device_type_string.split("(")[1].split("%")[0]
                return int(confidence_str)
            except (IndexError, ValueError):
                return 0
        return 0
    
    def is_high_confidence(self, device_type_string, threshold=70):
        """
        Check if device detection has high confidence
        
        Args:
            device_type_string (str): Device type with confidence
            threshold (int): Confidence threshold (default: 70%)
            
        Returns:
            bool: True if confidence is above threshold
        """
        confidence = self.get_confidence_level(device_type_string)
        return confidence >= threshold
    
    def add_custom_device_type(self, device_name, ports, services, hostnames):
        """
        Add a custom device type to the detection system
        
        Args:
            device_name (str): Name of the device type
            ports (list): List of characteristic ports
            services (list): List of characteristic services
            hostnames (list): List of characteristic hostname patterns
        """
        self.device_indicators[device_name.lower().replace(' ', '_')] = {
            'ports': ports,
            'services': services,
            'hostnames': hostnames
        }
    
    def get_supported_device_types(self):
        """
        Get list of supported device types
        
        Returns:
            list: List of supported device type names
        """
        return [device_type.replace('_', ' ').title() 
                for device_type in self.device_indicators.keys()]