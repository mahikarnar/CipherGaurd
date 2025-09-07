# src/security/validators.py
"""
Input validation and sanitization for CipherGuard.
Prevents injection attacks and ensures data integrity.
"""

import re
import html
from typing import Optional, Dict, Any, List, Union
from dataclasses import dataclass
from ..utils.logger import get_logger, log_security_event
from ..utils.config import get_config

logger = get_logger(__name__)


@dataclass
class ValidationResult:
    """Result of input validation with details."""
    is_valid: bool
    cleaned_value: Any
    errors: List[str]
    warnings: List[str]
    metadata: Dict[str, Any]


class InputValidator:
    """
    Comprehensive input validation and sanitization system.
    Protects against various injection attacks and ensures data quality.
    """
    
    def __init__(self):
        """Initialize validator with configuration and patterns."""
        self.config = get_config()
        
        # Dangerous patterns that could indicate attacks
        self.dangerous_patterns = [
            # SQL Injection patterns
            r"(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into)",
            r"(?i)(\-\-|\;|\||&&)",
            r"(?i)(0x[0-9a-f]+|char\(|ascii\()",
            
            # XSS patterns  
            r"(?i)(<script|<iframe|<object|<embed|<form)",
            r"(?i)(javascript:|vbscript:|data:)",
            r"(?i)(on\w+\s*=)",  # Event handlers
            
            # Command injection
            r"(?i)(\$\(|\`|;\s*(cat|ls|rm|wget|curl))",
            r"(?i)(&&|\|\||;|\n|\r)",
            
            # Path traversal
            r"(\.\.\/|\.\.\\|%2e%2e%2f)",
            
            # Template injection
            r"(\{\{|\}\}|\{%|%\})",
            
            # LDAP injection
            r"(\*|\(|\)|\\|\||&)"
        ]
        
        # Suspicious Unicode patterns
        self.unicode_threats = [
            r"[\u202a-\u202e]",  # Right-to-left override
            r"[\u200b-\u200d]",  # Zero-width characters
            r"[\ufeff]",         # Byte order mark
            r"[\u2028\u2029]"    # Line/paragraph separators
        ]
        
        # Common encoding schemes used in attacks
        self.encoding_patterns = [
            r"%[0-9a-f]{2}",     # URL encoding
            r"&#\d+;",           # HTML decimal encoding
            r"&#x[0-9a-f]+;",    # HTML hex encoding
            r"\\u[0-9a-f]{4}",   # Unicode escape
            r"\\x[0-9a-f]{2}"    # Hex escape
        ]
        
        logger.info("InputValidator initialized with security patterns")
    
    def validate_password(self, password: str, client_id: str = "anonymous") -> ValidationResult:
        """
        Validate password input with security checks.
        
        Args:
            password: Password to validate
            client_id: Client identifier for logging
            
        Returns:
            ValidationResult: Validation results and cleaned password
        """
        errors = []
        warnings = []
        metadata = {}
        
        # Check if password is provided
        if password is None:
            return ValidationResult(
                is_valid=False,
                cleaned_value="",
                errors=["Password is required"],
                warnings=[],
                metadata={"length": 0}
            )
        
        # Convert to string if needed
        if not isinstance(password, str):
            password = str(password)
            warnings.append("Password was converted to string")
        
        # Check length limits
        original_length = len(password)
        metadata["original_length"] = original_length
        
        if original_length == 0:
            errors.append("Password cannot be empty")
        elif original_length > self.config.max_password_length:
            errors.append(f"Password too long (max {self.config.max_password_length} characters)")
            log_security_event("password_too_long", client_id, 
                             f"Length: {original_length}/{self.config.max_password_length}")
        
        # Security pattern checking
        security_issues = self._check_security_patterns(password, client_id)
        if security_issues:
            errors.extend(security_issues)
        
        # Unicode threat detection
        unicode_issues = self._check_unicode_threats(password, client_id)
        if unicode_issues:
            warnings.extend(unicode_issues)
        
        # Encoding detection
        encoding_issues = self._check_encoding_attacks(password, client_id)
        if encoding_issues:
            warnings.extend(encoding_issues)
        
        # Clean the password (minimal cleaning to preserve user intent)
        cleaned_password = self._clean_password(password)
        metadata["cleaned_length"] = len(cleaned_password)
        
        # Check if cleaning changed the password significantly
        if len(cleaned_password) != original_length:
            warnings.append(f"Password was cleaned (length changed: {original_length} → {len(cleaned_password)})")
        
        # Character analysis
        char_analysis = self._analyze_characters(cleaned_password)
        metadata.update(char_analysis)
        
        is_valid = len(errors) == 0
        
        if not is_valid:
            log_security_event("password_validation_failed", client_id, f"Errors: {len(errors)}")
        
        return ValidationResult(
            is_valid=is_valid,
            cleaned_value=cleaned_password,
            errors=errors,
            warnings=warnings,
            metadata=metadata
        )
    
    def validate_client_id(self, client_id: str) -> ValidationResult:
        """
        Validate client identifier (typically IP address).
        
        Args:
            client_id: Client identifier to validate
            
        Returns:
            ValidationResult: Validation results
        """
        errors = []
        warnings = []
        metadata = {}
        
        if not client_id:
            client_id = "anonymous"
            warnings.append("Empty client_id replaced with 'anonymous'")
        
        # Convert to string and limit length
        client_id = str(client_id)[:50]  # Reasonable limit for client IDs
        
        # Remove potentially dangerous characters
        cleaned_id = re.sub(r'[<>"\'\\\x00-\x1f\x7f-\x9f]', '', client_id)
        
        # Check for IP address pattern (common client_id format)
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, cleaned_id):
            metadata["type"] = "ipv4"
        elif ":" in cleaned_id and len(cleaned_id) > 10:
            metadata["type"] = "ipv6_possible"
        else:
            metadata["type"] = "custom"
        
        metadata["original_length"] = len(client_id)
        metadata["cleaned_length"] = len(cleaned_id)
        
        if len(cleaned_id) != len(client_id):
            warnings.append("Client ID was sanitized")
        
        return ValidationResult(
            is_valid=True,  # Client ID is always made valid through cleaning
            cleaned_value=cleaned_id,
            errors=errors,
            warnings=warnings,
            metadata=metadata
        )
    
    def _check_security_patterns(self, input_text: str, client_id: str) -> List[str]:
        """Check for dangerous security patterns."""
        issues = []
        input_lower = input_text.lower()
        
        for pattern in self.dangerous_patterns:
            if re.search(pattern, input_text, re.IGNORECASE):
                issues.append(f"Potentially dangerous pattern detected")
                log_security_event("dangerous_pattern", client_id, f"Pattern matched: {pattern[:20]}...")
                break  # Only report one to avoid spam
        
        # Check for suspicious character sequences
        if len(input_text) > 50 and input_text.count('<') > 5:
            issues.append("Suspicious number of angle brackets")
            log_security_event("suspicious_brackets", client_id, f"Count: {input_text.count('<')}")
        
        if len(input_text) > 50 and input_text.count('%') > 10:
            issues.append("Suspicious number of percent signs")
            log_security_event("suspicious_percent", client_id, f"Count: {input_text.count('%')}")
        
        return issues
    
    def _check_unicode_threats(self, input_text: str, client_id: str) -> List[str]:
        """Check for Unicode-based attacks."""
        warnings = []
        
        for pattern in self.unicode_threats:
            if re.search(pattern, input_text):
                warnings.append("Suspicious Unicode characters detected")
                log_security_event("suspicious_unicode", client_id, "Unicode threat pattern found")
                break
        
        # Check for mixed scripts (potential homograph attack)
        scripts = set()
        for char in input_text:
            if char.isalpha():
                # Simple script detection (not comprehensive but catches obvious cases)
                if ord(char) < 128:
                    scripts.add("latin")
                elif 0x0400 <= ord(char) <= 0x04FF:
                    scripts.add("cyrillic")
                elif 0x0370 <= ord(char) <= 0x03FF:
                    scripts.add("greek")
                elif ord(char) > 0x4E00:
                    scripts.add("cjk")
        
        if len(scripts) > 1:
            warnings.append("Mixed character scripts detected")
            log_security_event("mixed_scripts", client_id, f"Scripts: {list(scripts)}")
        
        return warnings
    
    def _check_encoding_attacks(self, input_text: str, client_id: str) -> List[str]:
        """Check for encoding-based attacks."""
        warnings = []
        
        for pattern in self.encoding_patterns:
            matches = re.findall(pattern, input_text, re.IGNORECASE)
            if len(matches) > 5:  # Threshold for suspicious encoding
                warnings.append("Suspicious encoding patterns detected")
                log_security_event("suspicious_encoding", client_id, f"Pattern: {pattern[:20]}... Count: {len(matches)}")
                break
        
        return warnings
    
    def _clean_password(self, password: str) -> str:
        """
        Minimal cleaning of password while preserving user intent.
        Only removes truly dangerous characters.
        """
        # Remove null bytes and other control characters that could cause issues
        cleaned = password.replace('\x00', '').replace('\r', '').replace('\n', '')
        
        # Remove characters that could cause display issues
        cleaned = ''.join(char for char in cleaned if ord(char) >= 32 or char in '\t')
        
        return cleaned
    
    def _analyze_characters(self, text: str) -> Dict[str, Any]:
        """Analyze character composition for metadata."""
        if not text:
            return {
                "has_ascii": False,
                "has_unicode": False,
                "has_control_chars": False,
                "printable_ratio": 0.0
            }
        
        ascii_chars = sum(1 for c in text if ord(c) < 128)
        unicode_chars = len(text) - ascii_chars
        control_chars = sum(1 for c in text if ord(c) < 32)
        printable_chars = sum(1 for c in text if c.isprintable())
        
        return {
            "has_ascii": ascii_chars > 0,
            "has_unicode": unicode_chars > 0,
            "has_control_chars": control_chars > 0,
            "printable_ratio": printable_chars / len(text) if text else 0.0,
            "ascii_ratio": ascii_chars / len(text) if text else 0.0,
            "unicode_ratio": unicode_chars / len(text) if text else 0.0
        }
    
    def sanitize_for_output(self, text: str, output_type: str = "json") -> str:
        """
        Sanitize text for safe output in different contexts.
        
        Args:
            text: Text to sanitize
            output_type: Output context (json, html, log)
            
        Returns:
            str: Sanitized text safe for the specified context
        """
        if not text:
            return ""
        
        if output_type == "html":
            # HTML escape
            return html.escape(str(text), quote=True)
        
        elif output_type == "log":
            # Log sanitization - remove newlines and control chars
            sanitized = str(text).replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
            # Truncate very long strings for logs
            if len(sanitized) > 200:
                sanitized = sanitized[:197] + "..."
            return sanitized
        
        elif output_type == "json":
            # JSON is generally safe but ensure no control characters
            return ''.join(char for char in str(text) if char.isprintable() or char in ' \t')
        
        else:
            # Default: basic sanitization
            return str(text)
    
    def validate_batch_passwords(self, passwords: List[str], client_id: str = "batch") -> Dict[int, ValidationResult]:
        """
        Validate multiple passwords efficiently.
        
        Args:
            passwords: List of passwords to validate
            client_id: Client identifier
            
        Returns:
            Dict: Index -> ValidationResult mapping
        """
        results = {}
        
        if not passwords:
            return results
        
        if len(passwords) > 100:  # Reasonable batch limit
            log_security_event("large_batch_validation", client_id, f"Size: {len(passwords)}")
        
        for i, password in enumerate(passwords):
            results[i] = self.validate_password(password, f"{client_id}_batch_{i}")
        
        return results
    
    def get_validation_stats(self) -> Dict[str, Any]:
        """Get statistics about validation activities."""
        return {
            "config": {
                "max_password_length": self.config.max_password_length,
                "min_password_length": self.config.min_password_length
            },
            "patterns": {
                "dangerous_patterns": len(self.dangerous_patterns),
                "unicode_threats": len(self.unicode_threats),
                "encoding_patterns": len(self.encoding_patterns)
            }
        }


# Convenience functions for common validation tasks
def validate_password_simple(password: str) -> bool:
    """Simple password validation (returns boolean)."""
    validator = InputValidator()
    result = validator.validate_password(password)
    return result.is_valid

def clean_password(password: str) -> str:
    """Simple password cleaning."""
    validator = InputValidator()
    result = validator.validate_password(password)
    return result.cleaned_value

def sanitize_output(text: str, output_type: str = "json") -> str:
    """Simple output sanitization."""
    validator = InputValidator()
    return validator.sanitize_for_output(text, output_type)


# Example usage and testing
if __name__ == "__main__":
    from ..utils.logger import setup_logging
    
    setup_logging("INFO")
    validator = InputValidator()
    
    # Test passwords with various security issues
    test_cases = [
        ("normal_password123", "Normal password"),
        ("password' OR '1'='1", "SQL injection attempt"),
        ("password<script>alert('xss')</script>", "XSS attempt"),
        ("password`cat /etc/passwd`", "Command injection attempt"),
        ("пароль123", "Unicode password (Cyrillic)"),
        ("password\x00\x01\x02", "Password with control characters"),
        ("p" * 200, "Very long password"),
        ("", "Empty password"),
        (None, "None value"),
        ("password%3Cscript%3E", "URL encoded XSS"),
    ]
    
    print("Password Validation Testing:")
    print("=" * 60)
    
    for password, description in test_cases:
        print(f"\nTest: {description}")
        
        if password is None:
            print(f"Input: None")
        else:
            safe_display = password[:20] + "..." if len(str(password)) > 20 else str(password)
            print(f"Input: '{safe_display}' (length: {len(str(password)) if password else 0})")
        
        result = validator.validate_password(password, "test_client")
        
        status = "✅ VALID" if result.is_valid else "❌ INVALID"
        print(f"Result: {status}")
        
        if result.errors:
            print(f"Errors: {result.errors}")
        
        if result.warnings:
            print(f"Warnings: {result.warnings}")
        
        if result.metadata:
            print(f"Metadata: {result.metadata}")
        
        print(f"Cleaned length: {len(result.cleaned_value)}")
    
    # Test client ID validation
    print(f"\n\nClient ID Validation:")
    print("=" * 30)
    
    test_clients = ["192.168.1.1", "user@domain.com", "<script>alert('xss')</script>", ""]
    
    for client in test_clients:
        result = validator.validate_client_id(client)
        print(f"'{client}' → '{result.cleaned_value}' (Type: {result.metadata.get('type', 'unknown')})")
    
    # Show validation statistics
    print(f"\n\nValidation Statistics:")
    stats = validator.get_validation_stats()
    print(f"Configuration: {stats['config']}")
    print(f"Security patterns loaded: {stats['patterns']}")