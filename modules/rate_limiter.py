#!/usr/bin/env python3
"""
Rate Limiting and Anti-Abuse Module
Implements rate limiting, throttling, and anti-abuse mechanisms to prevent DoS attacks
and ensure responsible network scanning practices.

Author: Gustavo Valente
Version: 2.0
"""

import time
import threading
import logging
from typing import Dict, Any, Optional, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import ipaddress

@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    requests_per_second: float = 10.0
    requests_per_minute: int = 300
    requests_per_hour: int = 5000
    burst_size: int = 20
    cooldown_period: int = 300  # seconds
    max_concurrent_scans: int = 5
    target_specific_limit: int = 100  # per target per hour

class TokenBucket:
    """
    Token bucket algorithm implementation for rate limiting
    """
    
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = capacity
        self.refill_rate = refill_rate
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Try to consume tokens from the bucket
        Returns True if successful, False if rate limited
        """
        with self.lock:
            now = time.time()
            
            # Refill tokens based on time elapsed
            time_passed = now - self.last_refill
            tokens_to_add = time_passed * self.refill_rate
            self.tokens = min(self.capacity, self.tokens + tokens_to_add)
            self.last_refill = now
            
            # Try to consume tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def get_wait_time(self, tokens: int = 1) -> float:
        """
        Get the time to wait before the requested tokens are available
        """
        with self.lock:
            if self.tokens >= tokens:
                return 0.0
            
            tokens_needed = tokens - self.tokens
            return tokens_needed / self.refill_rate

class RateLimiter:
    """
    Comprehensive rate limiting system with multiple algorithms and abuse detection
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self.logger = logging.getLogger(__name__)
        
        # Token buckets for different time windows
        self.global_bucket = TokenBucket(
            capacity=self.config.burst_size,
            refill_rate=self.config.requests_per_second
        )
        
        # Per-target rate limiting
        self.target_buckets: Dict[str, TokenBucket] = {}
        self.target_requests: Dict[str, deque] = defaultdict(deque)
        
        # Request tracking for different time windows
        self.request_history = deque()
        self.minute_requests = deque()
        self.hour_requests = deque()
        
        # Concurrent scan tracking
        self.active_scans: Dict[str, datetime] = {}
        self.scan_lock = threading.Lock()
        
        # Abuse detection
        self.suspicious_activity: Dict[str, Dict[str, Any]] = defaultdict(dict)
        self.blocked_sources: Dict[str, datetime] = {}
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'rate_limited_requests': 0,
            'blocked_requests': 0,
            'suspicious_activity_detected': 0
        }
        
        self.lock = threading.Lock()
    
    def check_rate_limit(self, source_ip: str, target: str, scan_type: str = 'port_scan') -> Tuple[bool, str, float]:
        """
        Check if request should be rate limited
        Returns: (allowed, reason, wait_time)
        """
        now = time.time()
        
        with self.lock:
            self.stats['total_requests'] += 1
            
            # Check if source is blocked
            if self._is_blocked(source_ip):
                self.stats['blocked_requests'] += 1
                return False, "Source IP is temporarily blocked due to suspicious activity", 0
            
            # Check global rate limit
            if not self.global_bucket.consume():
                wait_time = self.global_bucket.get_wait_time()
                self.stats['rate_limited_requests'] += 1
                self.logger.warning(f"Global rate limit exceeded for {source_ip}")
                return False, "Global rate limit exceeded", wait_time
            
            # Check per-target rate limit
            if not self._check_target_rate_limit(target):
                self.stats['rate_limited_requests'] += 1
                return False, f"Rate limit exceeded for target {target}", 60.0
            
            # Check time-window limits
            if not self._check_time_windows():
                self.stats['rate_limited_requests'] += 1
                return False, "Time window rate limit exceeded", 60.0
            
            # Check concurrent scans
            if not self._check_concurrent_scans(source_ip, target):
                self.stats['rate_limited_requests'] += 1
                return False, "Maximum concurrent scans exceeded", 30.0
            
            # Update request tracking
            self._update_request_tracking(source_ip, target, scan_type, now)
            
            # Check for suspicious activity
            self._detect_suspicious_activity(source_ip, target, scan_type)
            
            return True, "Request allowed", 0.0
    
    def start_scan(self, source_ip: str, target: str) -> bool:
        """
        Register the start of a scan
        """
        with self.scan_lock:
            scan_key = f"{source_ip}:{target}"
            
            if len(self.active_scans) >= self.config.max_concurrent_scans:
                # Clean up old scans
                self._cleanup_old_scans()
                
                if len(self.active_scans) >= self.config.max_concurrent_scans:
                    return False
            
            self.active_scans[scan_key] = datetime.now()
            return True
    
    def end_scan(self, source_ip: str, target: str) -> None:
        """
        Register the end of a scan
        """
        with self.scan_lock:
            scan_key = f"{source_ip}:{target}"
            if scan_key in self.active_scans:
                del self.active_scans[scan_key]
    
    def report_abuse(self, source_ip: str, reason: str, severity: str = 'medium') -> None:
        """
        Report abusive behavior
        """
        with self.lock:
            now = datetime.now()
            
            if source_ip not in self.suspicious_activity:
                self.suspicious_activity[source_ip] = {
                    'reports': [],
                    'first_seen': now,
                    'total_score': 0
                }
            
            # Scoring system
            severity_scores = {'low': 1, 'medium': 3, 'high': 5, 'critical': 10}
            score = severity_scores.get(severity, 3)
            
            self.suspicious_activity[source_ip]['reports'].append({
                'timestamp': now,
                'reason': reason,
                'severity': severity,
                'score': score
            })
            
            self.suspicious_activity[source_ip]['total_score'] += score
            
            # Auto-block if score exceeds threshold
            if self.suspicious_activity[source_ip]['total_score'] >= 20:
                self._block_source(source_ip, f"Automatic block due to suspicious activity: {reason}")
            
            self.stats['suspicious_activity_detected'] += 1
            self.logger.warning(f"Abuse reported for {source_ip}: {reason} (severity: {severity})")
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get rate limiting statistics
        """
        with self.lock:
            stats = self.stats.copy()
            stats.update({
                'active_scans': len(self.active_scans),
                'blocked_sources': len(self.blocked_sources),
                'suspicious_sources': len(self.suspicious_activity),
                'global_tokens_available': self.global_bucket.tokens,
                'requests_last_minute': len(self.minute_requests),
                'requests_last_hour': len(self.hour_requests)
            })
            return stats
    
    def _check_target_rate_limit(self, target: str) -> bool:
        """
        Check per-target rate limiting
        """
        if target not in self.target_buckets:
            self.target_buckets[target] = TokenBucket(
                capacity=10,  # Smaller burst for individual targets
                refill_rate=2.0  # 2 requests per second per target
            )
        
        return self.target_buckets[target].consume()
    
    def _check_time_windows(self) -> bool:
        """
        Check minute and hour rate limits
        """
        now = time.time()
        
        # Clean old entries
        while self.minute_requests and now - self.minute_requests[0] > 60:
            self.minute_requests.popleft()
        
        while self.hour_requests and now - self.hour_requests[0] > 3600:
            self.hour_requests.popleft()
        
        # Check limits
        if len(self.minute_requests) >= self.config.requests_per_minute:
            return False
        
        if len(self.hour_requests) >= self.config.requests_per_hour:
            return False
        
        # Add current request
        self.minute_requests.append(now)
        self.hour_requests.append(now)
        
        return True
    
    def _check_concurrent_scans(self, source_ip: str, target: str) -> bool:
        """
        Check concurrent scan limits
        """
        self._cleanup_old_scans()
        
        # Count scans from this source
        source_scans = sum(1 for key in self.active_scans.keys() if key.startswith(f"{source_ip}:"))
        
        return source_scans < 3  # Max 3 concurrent scans per source
    
    def _update_request_tracking(self, source_ip: str, target: str, scan_type: str, timestamp: float) -> None:
        """
        Update request tracking for analysis
        """
        # Track per-target requests
        target_key = target
        if target_key not in self.target_requests:
            self.target_requests[target_key] = deque()
        
        self.target_requests[target_key].append({
            'timestamp': timestamp,
            'source_ip': source_ip,
            'scan_type': scan_type
        })
        
        # Keep only last hour of requests per target
        while (self.target_requests[target_key] and 
               timestamp - self.target_requests[target_key][0]['timestamp'] > 3600):
            self.target_requests[target_key].popleft()
    
    def _detect_suspicious_activity(self, source_ip: str, target: str, scan_type: str) -> None:
        """
        Detect suspicious scanning patterns
        """
        now = time.time()
        
        # Check for rapid scanning of multiple targets
        recent_targets = set()
        for target_key, requests in self.target_requests.items():
            for req in requests:
                if (req['source_ip'] == source_ip and 
                    now - req['timestamp'] < 300):  # Last 5 minutes
                    recent_targets.add(target_key)
        
        if len(recent_targets) > 50:  # Scanning more than 50 targets in 5 minutes
            self.report_abuse(source_ip, "Rapid multi-target scanning", "high")
        
        # Check for unusual scan patterns
        if scan_type in ['aggressive', 'stealth'] and len(recent_targets) > 10:
            self.report_abuse(source_ip, f"Suspicious {scan_type} scanning pattern", "medium")
        
        # Check for targeting sensitive networks
        try:
            target_ip = ipaddress.ip_address(target.split('/')[0])
            if target_ip.is_private and not target_ip.is_loopback:
                # Scanning private networks might be suspicious from external sources
                if not ipaddress.ip_address(source_ip).is_private:
                    self.report_abuse(source_ip, "External source scanning private networks", "medium")
        except ValueError:
            pass  # Not an IP address
    
    def _is_blocked(self, source_ip: str) -> bool:
        """
        Check if source IP is blocked
        """
        if source_ip in self.blocked_sources:
            block_time = self.blocked_sources[source_ip]
            if datetime.now() - block_time < timedelta(seconds=self.config.cooldown_period):
                return True
            else:
                # Unblock after cooldown period
                del self.blocked_sources[source_ip]
        
        return False
    
    def _block_source(self, source_ip: str, reason: str) -> None:
        """
        Block a source IP temporarily
        """
        self.blocked_sources[source_ip] = datetime.now()
        self.logger.warning(f"Blocked source {source_ip}: {reason}")
    
    def _cleanup_old_scans(self) -> None:
        """
        Clean up old scan entries
        """
        now = datetime.now()
        cutoff = now - timedelta(minutes=30)  # Remove scans older than 30 minutes
        
        to_remove = [
            key for key, start_time in self.active_scans.items()
            if start_time < cutoff
        ]
        
        for key in to_remove:
            del self.active_scans[key]
    
    def adaptive_rate_limit(self, system_load: float, network_congestion: float) -> None:
        """
        Adapt rate limits based on system conditions
        """
        # Reduce rate limits if system is under stress
        if system_load > 0.8:  # 80% CPU usage
            self.config.requests_per_second *= 0.5
            self.logger.info("Reduced rate limits due to high system load")
        
        if network_congestion > 0.7:  # 70% network utilization
            self.config.requests_per_second *= 0.7
            self.logger.info("Reduced rate limits due to network congestion")
    
    def whitelist_source(self, source_ip: str, reason: str) -> None:
        """
        Whitelist a source IP (remove from blocked list and suspicious activity)
        """
        with self.lock:
            if source_ip in self.blocked_sources:
                del self.blocked_sources[source_ip]
            
            if source_ip in self.suspicious_activity:
                del self.suspicious_activity[source_ip]
            
            self.logger.info(f"Whitelisted source {source_ip}: {reason}")

# Global rate limiter instance
_rate_limiter = None

def get_rate_limiter() -> RateLimiter:
    """
    Get singleton rate limiter instance
    """
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter