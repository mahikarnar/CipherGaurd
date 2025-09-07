# src/core/breach_checker.py
"""
Have I Been Pwned API integration for checking password breaches.
Uses k-anonymity to protect user privacy - only sends partial hash.
"""

import hashlib
import requests
from typing import Tuple, Optional, Dict, List
import time
from ..utils.logger import get_logger, log_breach_check, log_api_request
from ..utils.config import get_config

logger = get_logger(__name__)


class BreachChecker:
    """
    Checks if passwords have been found in data breaches using HIBP API.
    Implements k-anonymity for privacy protection - never sends full password or hash.
    """
    
    def __init__(self):
        """Initialize breach checker with configuration."""
        self.config = get_config()
        self.api_url = self.config.hibp_api_url
        self.timeout = self.config.hibp_timeout
        self.user_agent = self.config.hibp_user_agent
        
        # Cache for recently checked hashes (to avoid repeat API calls)
        self._cache: Dict[str, Tuple[bool, int, float]] = {}
        self._cache_timeout = 300  # 5 minutes cache
        
        # Rate limiting for API calls
        self._last_request_time = 0
        self._min_request_interval = 0.1  # 100ms between requests (HIBP rate limit)
        
        logger.info(f"BreachChecker initialized with API: {self.api_url}")
    
    def check_breach(self, password: str, client_id: str = "anonymous") -> Tuple[Optional[bool], int]:
        """
        Check if password appears in known breaches using k-anonymity.
        
        This method implements the k-anonymity model:
        1. Hash password with SHA-1
        2. Send only first 5 characters of hash to HIBP
        3. Receive all hashes starting with those 5 characters  
        4. Locally match the remaining 35 characters
        
        Args:
            password: Password to check (never sent to API)
            client_id: Client identifier for logging
            
        Returns:
            Tuple[Optional[bool], int]: (is_breached, breach_count)
            Returns (None, 0) if API is unavailable
        """
        if not password:
            return None, 0
        
        start_time = time.time()
        
        try:
            # Step 1: Generate SHA-1 hash locally
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix = sha1_hash[:5]  # First 5 characters for k-anonymity
            suffix = sha1_hash[5:]  # Remaining 35 characters to match locally
            
            logger.debug(f"Generated hash prefix: {prefix} for client {client_id[:8]}...")
            
            # Check cache first
            cache_key = prefix
            if self._is_cache_valid(cache_key):
                cached_result = self._cache[cache_key]
                is_breached = self._check_suffix_in_cached_data(suffix, cached_result[3])
                breach_count = cached_result[1] if is_breached else 0
                
                logger.debug(f"Cache hit for prefix {prefix}")
                log_breach_check(client_id, is_breached, "cached")
                return is_breached, breach_count
            
            # Step 2: Rate limiting - respect HIBP API limits
            self._enforce_rate_limit()
            
            # Step 3: Query HIBP API with prefix only (k-anonymity)
            response = self._make_api_request(prefix, client_id)
            
            if response is None:
                log_breach_check(client_id, None, "api_error")
                return None, 0
            
            # Step 4: Parse response and match suffix locally
            is_breached, breach_count, response_data = self._parse_response(response.text, suffix)
            
            # Cache the response data for future use
            self._cache[cache_key] = (is_breached, breach_count, time.time(), response_data)
            
            duration_ms = (time.time() - start_time) * 1000
            log_api_request("breach_check", client_id, "success", duration_ms)
            log_breach_check(client_id, is_breached, f"api_success_{response.status_code}")
            
            return is_breached, breach_count
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Unexpected error in breach check for client {client_id[:8]}...: {e}")
            log_api_request("breach_check", client_id, "error", duration_ms)
            log_breach_check(client_id, None, f"error_{str(e)[:50]}")
            return None, 0
    
    def _make_api_request(self, prefix: str, client_id: str) -> Optional[requests.Response]:
        """
        Make API request to HIBP with proper error handling.
        
        Args:
            prefix: 5-character hash prefix
            client_id: Client identifier for logging
            
        Returns:
            Optional[requests.Response]: Response object or None if failed
        """
        try:
            url = f"{self.api_url}{prefix}"
            headers = {
                'User-Agent': self.user_agent,
                'Accept': 'text/plain'
            }
            
            logger.debug(f"Making HIBP API request for prefix: {prefix}")
            
            response = requests.get(
                url,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                logger.debug(f"HIBP API success for prefix {prefix}: {len(response.text)} bytes")
                return response
            elif response.status_code == 404:
                # 404 means no breaches found for this prefix (which is good!)
                logger.debug(f"HIBP API 404 for prefix {prefix}: no breaches found")
                return response
            elif response.status_code == 429:
                logger.warning(f"HIBP API rate limited for client {client_id[:8]}...")
                return None
            else:
                logger.error(f"HIBP API error {response.status_code} for prefix {prefix}")
                return None
                
        except requests.exceptions.Timeout:
            logger.warning(f"HIBP API timeout ({self.timeout}s) for client {client_id[:8]}...")
            return None
        except requests.exceptions.ConnectionError:
            logger.error(f"HIBP API connection error for client {client_id[:8]}...")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"HIBP API request failed for client {client_id[:8]}...: {e}")
            return None
    
    def _parse_response(self, response_text: str, target_suffix: str) -> Tuple[bool, int, Dict[str, int]]:
        """
        Parse HIBP API response to find matching hash.
        
        Args:
            response_text: Raw API response text
            target_suffix: 35-character hash suffix to match
            
        Returns:
            Tuple[bool, int, Dict]: (is_breached, breach_count, all_response_data)
        """
        if not response_text.strip():
            return False, 0, {}
        
        response_data = {}
        hash_lines = response_text.strip().split('\n')
        
        logger.debug(f"Parsing {len(hash_lines)} hash entries from HIBP response")
        
        for line in hash_lines:
            if ':' not in line:
                continue
                
            try:
                hash_suffix, count_str = line.split(':', 1)
                hash_suffix = hash_suffix.strip()
                count = int(count_str.strip())
                
                # Store all response data for caching
                response_data[hash_suffix] = count
                
                # Check if this matches our target
                if hash_suffix == target_suffix:
                    logger.info(f"Password found in {count:,} breaches")
                    return True, count, response_data
                    
            except ValueError as e:
                logger.warning(f"Invalid line in HIBP response: {line} - {e}")
                continue
        
        logger.debug(f"Password not found in {len(response_data)} breach entries")
        return False, 0, response_data
    
    def _check_suffix_in_cached_data(self, suffix: str, cached_data: Dict[str, int]) -> bool:
        """Check if suffix exists in cached response data."""
        return suffix in cached_data
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached data is still valid."""
        if cache_key not in self._cache:
            return False
        
        _, _, timestamp, _ = self._cache[cache_key]
        return time.time() - timestamp < self._cache_timeout
    
    def _enforce_rate_limit(self):
        """Enforce rate limiting to respect HIBP API limits."""
        current_time = time.time()
        time_since_last_request = current_time - self._last_request_time
        
        if time_since_last_request < self._min_request_interval:
            sleep_time = self._min_request_interval - time_since_last_request
            logger.debug(f"Rate limiting: sleeping {sleep_time:.3f}s")
            time.sleep(sleep_time)
        
        self._last_request_time = time.time()
    
    def get_breach_statistics(self) -> Dict[str, any]:
        """
        Get statistics about breach checking.
        
        Returns:
            Dict: Statistics about API usage and cache
        """
        total_cached = len(self._cache)
        valid_cached = sum(1 for key in self._cache if self._is_cache_valid(key))
        
        return {
            'api_url': self.api_url,
            'timeout_seconds': self.timeout,
            'cache_entries': total_cached,
            'valid_cache_entries': valid_cached,
            'cache_timeout_seconds': self._cache_timeout,
            'min_request_interval_ms': self._min_request_interval * 1000,
            'user_agent': self.user_agent
        }
    
    def clear_cache(self):
        """Clear the breach check cache."""
        cache_size = len(self._cache)
        self._cache.clear()
        logger.info(f"Cleared breach check cache ({cache_size} entries)")
    
    def check_multiple_passwords(self, passwords: List[str], client_id: str = "batch") -> Dict[str, Tuple[Optional[bool], int]]:
        """
        Check multiple passwords for breaches efficiently.
        
        Args:
            passwords: List of passwords to check
            client_id: Client identifier for logging
            
        Returns:
            Dict: Map of password -> (is_breached, count)
        """
        results = {}
        
        logger.info(f"Batch checking {len(passwords)} passwords for client {client_id[:8]}...")
        
        for i, password in enumerate(passwords):
            if not password:
                results[password] = (None, 0)
                continue
            
            logger.debug(f"Checking password {i+1}/{len(passwords)}")
            results[password] = self.check_breach(password, f"{client_id}_batch_{i}")
            
            # Small delay between batch requests
            if i < len(passwords) - 1:
                time.sleep(0.05)  # 50ms delay
        
        return results


# Example usage and testing
if __name__ == "__main__":
    from ..utils.logger import setup_logging
    
    setup_logging("DEBUG")
    checker = BreachChecker()
    
    # Test passwords (some known to be breached, others safe)
    test_passwords = [
        "password",           # Definitely breached
        "123456",            # Definitely breached  
        "qwerty",            # Likely breached
        "MyS3cur3P@ssw0rd!", # Probably not breached
        "X9#mK$pL2@vR8qW",   # Very unlikely to be breached
        ""                   # Empty password test
    ]
    
    print("Password Breach Check Results:")
    print("=" * 50)
    
    for pwd in test_passwords:
        if not pwd:
            print("\nEmpty password: Skipped")
            continue
            
        print(f"\nChecking password: {'*' * len(pwd)} (length: {len(pwd)})")
        
        is_breached, count = checker.check_breach(pwd, "test_client")
        
        if is_breached is None:
            print("❓ Unable to check (API unavailable)")
        elif is_breached:
            print(f"🚨 BREACHED! Found in {count:,} breaches")
        else:
            print("✅ Not found in known breaches")
    
    # Show statistics
    print(f"\nBreach Checker Statistics:")
    stats = checker.get_breach_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")