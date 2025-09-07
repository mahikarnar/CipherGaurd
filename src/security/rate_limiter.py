# src/security/rate_limiter.py
"""
Rate limiting implementation to prevent abuse and ensure fair usage.
Uses sliding window approach with in-memory storage and cleanup.
"""

import time
from collections import defaultdict, deque
from functools import wraps
from typing import Dict, Deque, Optional, Tuple, Any
from dataclasses import dataclass
from ..utils.logger import get_logger, log_security_event
from ..utils.config import get_config

logger = get_logger(__name__)


@dataclass
class RateLimitInfo:
    """Information about rate limiting status."""
    allowed: bool
    requests_made: int
    requests_remaining: int
    reset_time: float
    retry_after: Optional[int] = None


class RateLimiter:
    """
    Sliding window rate limiter for API protection.
    Tracks requests per client and enforces limits with automatic cleanup.
    """
    
    def __init__(self, max_requests: int = None, window_seconds: int = None):
        """
        Initialize rate limiter with configuration.
        
        Args:
            max_requests: Maximum requests per window (defaults from config)
            window_seconds: Time window in seconds (defaults from config)
        """
        self.config = get_config()
        
        self.max_requests = max_requests or self.config.rate_limit_requests
        self.window_seconds = window_seconds or self.config.rate_limit_window
        
        # Storage for request timestamps per client
        self.requests: Dict[str, Deque[float]] = defaultdict(deque)
        
        # Track blocked clients and their block times
        self.blocked_clients: Dict[str, float] = {}
        
        # Statistics tracking
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'unique_clients': 0,
            'cleanup_runs': 0
        }
        
        # Automatic cleanup configuration
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
        self.max_clients_before_cleanup = 1000
        
        logger.info(f"RateLimiter initialized: {self.max_requests} requests per {self.window_seconds}s")
    
    def is_allowed(self, client_id: str, request_weight: int = 1) -> RateLimitInfo:
        """
        Check if client is within rate limits.
        
        Args:
            client_id: Unique client identifier (typically IP address)
            request_weight: Weight of this request (default 1, can be higher for expensive operations)
            
        Returns:
            RateLimitInfo: Detailed information about rate limit status
        """
        current_time = time.time()
        
        # Periodic cleanup to prevent memory leaks
        self._maybe_cleanup(current_time)
        
        # Check if client is temporarily blocked (for severe violations)
        if self._is_client_blocked(client_id, current_time):
            self.stats['blocked_requests'] += 1
            
            block_remaining = self.blocked_clients[client_id] - current_time
            log_security_event("rate_limit_blocked", client_id, f"Client blocked, {block_remaining:.1f}s remaining")
            
            return RateLimitInfo(
                allowed=False,
                requests_made=self.max_requests,
                requests_remaining=0,
                reset_time=self.blocked_clients[client_id],
                retry_after=int(block_remaining) + 1
            )
        
        # Get client's request history
        client_requests = self.requests[client_id]
        
        # Remove old requests outside the sliding window
        cutoff_time = current_time - self.window_seconds
        while client_requests and client_requests[0] < cutoff_time:
            client_requests.popleft()
        
        # Calculate current request count with weight
        current_count = len(client_requests)
        projected_count = current_count + request_weight
        
        # Check if request would exceed limit
        if projected_count > self.max_requests:
            self.stats['blocked_requests'] += 1
            
            # Calculate when the oldest request will expire
            oldest_request = client_requests[0] if client_requests else current_time
            reset_time = oldest_request + self.window_seconds
            retry_after = int(reset_time - current_time) + 1
            
            # Check for severe violations (attempting many more requests than limit)
            if projected_count > self.max_requests * 2:
                self._block_client(client_id, current_time)
                log_security_event("rate_limit_severe_violation", client_id, 
                                 f"Attempted {projected_count}/{self.max_requests} requests")
            else:
                log_security_event("rate_limit_exceeded", client_id, 
                                 f"{projected_count}/{self.max_requests} requests in window")
            
            return RateLimitInfo(
                allowed=False,
                requests_made=current_count,
                requests_remaining=0,
                reset_time=reset_time,
                retry_after=retry_after
            )
        
        # Request allowed - record it
        for _ in range(request_weight):
            client_requests.append(current_time)
        
        self.stats['total_requests'] += request_weight
        
        # Track unique clients
        if len(client_requests) == request_weight:  # First request from this client in window
            self.stats['unique_clients'] = len(self.requests)
        
        requests_remaining = max(0, self.max_requests - len(client_requests))
        
        # Log if client is getting close to limit
        if requests_remaining <= 2:
            logger.debug(f"Client {client_id[:8]}... approaching rate limit: {len(client_requests)}/{self.max_requests}")
        
        return RateLimitInfo(
            allowed=True,
            requests_made=len(client_requests),
            requests_remaining=requests_remaining,
            reset_time=current_time + self.window_seconds
        )
    
    def _is_client_blocked(self, client_id: str, current_time: float) -> bool:
        """Check if client is in the blocked list and still blocked."""
        if client_id not in self.blocked_clients:
            return False
        
        block_until = self.blocked_clients[client_id]
        
        if current_time >= block_until:
            # Block has expired, remove from blocked list
            del self.blocked_clients[client_id]
            logger.info(f"Client {client_id[:8]}... unblocked after timeout")
            return False
        
        return True
    
    def _block_client(self, client_id: str, current_time: float):
        """Block a client for severe rate limit violations."""
        block_duration = self.window_seconds * 2  # Block for 2x the window time
        block_until = current_time + block_duration
        
        self.blocked_clients[client_id] = block_until
        logger.warning(f"Client {client_id[:8]}... blocked for {block_duration}s due to severe violation")
    
    def _maybe_cleanup(self, current_time: float):
        """Perform periodic cleanup to prevent memory leaks."""
        should_cleanup = (
            current_time - self.last_cleanup > self.cleanup_interval or
            len(self.requests) > self.max_clients_before_cleanup
        )
        
        if should_cleanup:
            self._cleanup_old_data(current_time)
    
    def _cleanup_old_data(self, current_time: float):
        """Clean up old request data and expired blocks."""
        cutoff_time = current_time - self.window_seconds
        clients_to_remove = []
        
        # Clean up request queues
        for client_id, client_requests in self.requests.items():
            # Remove old requests
            while client_requests and client_requests[0] < cutoff_time:
                client_requests.popleft()
            
            # Remove clients with no recent requests
            if not client_requests:
                clients_to_remove.append(client_id)
        
        # Remove empty client queues
        for client_id in clients_to_remove:
            del self.requests[client_id]
        
        # Clean up expired blocks
        expired_blocks = [
            client_id for client_id, block_until in self.blocked_clients.items()
            if current_time >= block_until
        ]
        
        for client_id in expired_blocks:
            del self.blocked_clients[client_id]
        
        self.last_cleanup = current_time
        self.stats['cleanup_runs'] += 1
        
        if clients_to_remove or expired_blocks:
            logger.debug(f"Cleanup: removed {len(clients_to_remove)} empty clients, "
                        f"{len(expired_blocks)} expired blocks")
    
    def __call__(self, weight: int = 1, client_id_key: str = 'client_id'):
        """
        Decorator for applying rate limiting to functions.
        
        Args:
            weight: Request weight (default 1)
            client_id_key: Key to extract client_id from kwargs
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Extract client ID from kwargs or use default
                client_id = kwargs.get(client_id_key, 'anonymous')
                
                # Check rate limit
                limit_info = self.is_allowed(client_id, weight)
                
                if not limit_info.allowed:
                    return {
                        "error": "Rate limit exceeded",
                        "message": f"Too many requests. You have made {limit_info.requests_made} requests.",
                        "retry_after": limit_info.retry_after,
                        "reset_time": limit_info.reset_time
                    }
                
                # Add rate limit info to kwargs for the function to use if needed
                kwargs['_rate_limit_info'] = limit_info
                
                return func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    def get_client_status(self, client_id: str) -> Dict[str, Any]:
        """
        Get detailed status for a specific client.
        
        Args:
            client_id: Client identifier
            
        Returns:
            Dict: Detailed client status
        """
        current_time = time.time()
        client_requests = self.requests.get(client_id, deque())
        
        # Clean up old requests for accurate count
        cutoff_time = current_time - self.window_seconds
        while client_requests and client_requests[0] < cutoff_time:
            client_requests.popleft()
        
        is_blocked = self._is_client_blocked(client_id, current_time)
        
        status = {
            'client_id': client_id[:8] + '...',  # Partial ID for privacy
            'requests_in_window': len(client_requests),
            'requests_remaining': max(0, self.max_requests - len(client_requests)),
            'window_seconds': self.window_seconds,
            'is_blocked': is_blocked,
            'reset_time': current_time + self.window_seconds
        }
        
        if is_blocked:
            status['blocked_until'] = self.blocked_clients[client_id]
            status['block_remaining'] = max(0, self.blocked_clients[client_id] - current_time)
        
        return status
    
    def get_stats(self) -> Dict[str, Any]:
        """Get overall rate limiter statistics."""
        current_time = time.time()
        
        # Count active clients (with requests in current window)
        cutoff_time = current_time - self.window_seconds
        active_clients = 0
        
        for client_requests in self.requests.values():
            if client_requests and client_requests[-1] > cutoff_time:
                active_clients += 1
        
        return {
            'configuration': {
                'max_requests': self.max_requests,
                'window_seconds': self.window_seconds,
                'cleanup_interval': self.cleanup_interval
            },
            'statistics': {
                'total_requests': self.stats['total_requests'],
                'blocked_requests': self.stats['blocked_requests'],
                'success_rate': (self.stats['total_requests'] / 
                               (self.stats['total_requests'] + self.stats['blocked_requests']) * 100
                               if (self.stats['total_requests'] + self.stats['blocked_requests']) > 0 else 100),
                'active_clients': active_clients,
                'blocked_clients': len(self.blocked_clients),
                'cleanup_runs': self.stats['cleanup_runs']
            },
            'current_state': {
                'tracked_clients': len(self.requests),
                'blocked_clients': len(self.blocked_clients),
                'last_cleanup': self.last_cleanup,
                'memory_usage_estimate': len(self.requests) * 100  # Rough estimate in bytes
            }
        }
    
    def reset_client(self, client_id: str):
        """Reset rate limiting for a specific client (admin function)."""
        if client_id in self.requests:
            del self.requests[client_id]
        if client_id in self.blocked_clients:
            del self.blocked_clients[client_id]
        
        logger.info(f"Rate limit reset for client {client_id[:8]}...")
    
    def reset_all(self):
        """Reset all rate limiting data (admin function)."""
        client_count = len(self.requests)
        blocked_count = len(self.blocked_clients)
        
        self.requests.clear()
        self.blocked_clients.clear()
        
        logger.info(f"Rate limiter reset: cleared {client_count} clients, {blocked_count} blocks")


# Example usage and testing
if __name__ == "__main__":
    from ..utils.logger import setup_logging
    import random
    
    setup_logging("INFO")
    
    # Create rate limiter with low limits for testing
    limiter = RateLimiter(max_requests=5, window_seconds=10)
    
    print("Rate Limiter Testing:")
    print("=" * 50)
    
    # Test normal usage
    test_client = "192.168.1.100"
    
    print(f"\nTesting normal usage (limit: 5 requests per 10s)")
    for i in range(8):  # Try 8 requests (should block after 5)
        limit_info = limiter.is_allowed(test_client)
        
        status = "✅ ALLOWED" if limit_info.allowed else "❌ BLOCKED"
        print(f"Request {i+1}: {status} - {limit_info.requests_made}/{limiter.max_requests} used")
        
        if not limit_info.allowed and limit_info.retry_after:
            print(f"  Retry after: {limit_info.retry_after} seconds")
        
        time.sleep(0.5)  # Small delay between requests
    
    # Test with decorator
    @limiter(weight=2, client_id_key='user_id')
    def expensive_operation(data, user_id=None):
        return f"Processing data for user {user_id}: {data}"
    
    print(f"\nTesting decorator with weight=2:")
    
    test_user = "user_123"
    for i in range(4):  # Each request costs 2, so should block after 2-3 requests
        result = expensive_operation(f"data_{i}", user_id=test_user)
        
        if isinstance(result, dict) and "error" in result:
            print(f"Request {i+1}: ❌ {result['error']}")
        else:
            print(f"Request {i+1}: ✅ {result}")
    
    # Show statistics
    print(f"\nRate Limiter Statistics:")
    stats = limiter.get_stats()
    
    print(f"Configuration: {stats['configuration']}")
    print(f"Total requests: {stats['statistics']['total_requests']}")
    print(f"Blocked requests: {stats['statistics']['blocked_requests']}")
    print(f"Success rate: {stats['statistics']['success_rate']:.1f}%")
    print(f"Active clients: {stats['statistics']['active_clients']}")
    print(f"Blocked clients: {stats['statistics']['blocked_clients']}")