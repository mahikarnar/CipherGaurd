# src/core/entropy.py
"""
Shannon entropy calculation for password randomness measurement.
Implements multiple entropy calculation methods for comprehensive analysis.
"""

import math
import re
from collections import Counter
from typing import Dict, Tuple, List
from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger(__name__)


class EntropyCalculator:
    """
    Calculates password entropy using multiple methods.
    Higher entropy indicates more randomness and security.
    """
    
    def __init__(self):
        """Initialize entropy calculator with configuration."""
        self.config = get_config()
        self.charset_sizes = self.config.default_charset_sizes.copy()
        
        # Common keyboard patterns for entropy reduction
        self.keyboard_patterns = [
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm',
            '1234567890', '0987654321',
            'qwerty', 'asdf', 'zxcv'
        ]
        
        # Dictionary words that reduce entropy
        self.common_words = {
            'password', 'admin', 'login', 'user', 'guest', 'root',
            'test', 'demo', 'sample', 'default', 'temp', 'welcome'
        }
        
        logger.debug(f"EntropyCalculator initialized with charset sizes: {self.charset_sizes}")
    
    def calculate(self, password: str) -> float:
        """
        Calculate password entropy using the most conservative method.
        
        Args:
            password: Password to analyze
            
        Returns:
            float: Entropy value in bits
        """
        if not password:
            return 0.0
        
        logger.debug(f"Calculating entropy for password of length {len(password)}")
        
        # Calculate different entropy measures
        charset_entropy = self._calculate_charset_entropy(password)
        frequency_entropy = self._calculate_frequency_entropy(password)
        pattern_adjusted_entropy = self._calculate_pattern_adjusted_entropy(password, charset_entropy)
        
        # Use the most conservative (lowest) entropy value
        final_entropy = min(charset_entropy, frequency_entropy, pattern_adjusted_entropy)
        
        logger.debug(
            f"Entropy calculation results - Charset: {charset_entropy:.2f}, "
            f"Frequency: {frequency_entropy:.2f}, Pattern-adjusted: {pattern_adjusted_entropy:.2f}, "
            f"Final: {final_entropy:.2f}"
        )
        
        return round(final_entropy, 2)
    
    def _calculate_charset_entropy(self, password: str) -> float:
        """
        Calculate entropy based on character set used.
        Formula: length × log₂(charset_size)
        
        Args:
            password: Password to analyze
            
        Returns:
            float: Character set based entropy
        """
        charset_size = self._get_charset_size(password)
        if charset_size == 0:
            return 0.0
        
        entropy = len(password) * math.log2(charset_size)
        logger.debug(f"Charset entropy: {len(password)} × log₂({charset_size}) = {entropy:.2f}")
        
        return entropy
    
    def _calculate_frequency_entropy(self, password: str) -> float:
        """
        Calculate actual entropy based on character frequencies.
        Uses Shannon entropy formula: H = -Σ(p(x) × log₂(p(x)))
        
        Args:
            password: Password to analyze
            
        Returns:
            float: Frequency based entropy
        """
        if not password:
            return 0.0
        
        char_counts = Counter(password)
        length = len(password)
        
        # Calculate Shannon entropy per character
        entropy_per_char = 0.0
        for count in char_counts.values():
            probability = count / length
            if probability > 0:
                entropy_per_char -= probability * math.log2(probability)
        
        # Total entropy is per-character entropy × password length
        total_entropy = entropy_per_char * length
        
        logger.debug(
            f"Frequency entropy: {entropy_per_char:.2f} per char × {length} chars = {total_entropy:.2f}"
        )
        
        return total_entropy
    
    def _calculate_pattern_adjusted_entropy(self, password: str, base_entropy: float) -> float:
        """
        Adjust entropy based on detected patterns.
        Patterns reduce effective entropy.
        
        Args:
            password: Password to analyze
            base_entropy: Base entropy before pattern adjustment
            
        Returns:
            float: Pattern-adjusted entropy
        """
        adjustment_factor = 1.0
        password_lower = password.lower()
        
        # Check for keyboard patterns
        for pattern in self.keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                adjustment_factor *= 0.7  # Reduce entropy by 30%
                logger.debug(f"Keyboard pattern detected: {pattern}")
                break
        
        # Check for dictionary words
        for word in self.common_words:
            if word in password_lower:
                adjustment_factor *= 0.6  # Reduce entropy by 40%
                logger.debug(f"Dictionary word detected: {word}")
                break
        
        # Check for repeated sequences
        if self._has_repeated_sequences(password):
            adjustment_factor *= 0.8  # Reduce entropy by 20%
            logger.debug("Repeated sequences detected")
        
        # Check for date patterns
        if self._has_date_patterns(password):
            adjustment_factor *= 0.7  # Reduce entropy by 30%
            logger.debug("Date pattern detected")
        
        # Check for sequential characters
        if self._has_sequential_chars(password):
            adjustment_factor *= 0.75  # Reduce entropy by 25%
            logger.debug("Sequential characters detected")
        
        adjusted_entropy = base_entropy * adjustment_factor
        
        if adjustment_factor < 1.0:
            logger.debug(f"Entropy adjusted by factor {adjustment_factor:.2f}: {base_entropy:.2f} → {adjusted_entropy:.2f}")
        
        return adjusted_entropy
    
    def _get_charset_size(self, password: str) -> int:
        """Determine the total character set size used."""
        size = 0
        
        if any(c.islower() for c in password):
            size += self.charset_sizes['lowercase']
        if any(c.isupper() for c in password):
            size += self.charset_sizes['uppercase']
        if any(c.isdigit() for c in password):
            size += self.charset_sizes['digits']
        if any(not c.isalnum() for c in password):
            size += self.charset_sizes['symbols']
        
        return size
    
    def _has_repeated_sequences(self, password: str) -> bool:
        """Check for repeated character sequences."""
        # Check for 3+ character repetitions
        if re.search(r'(.{3,})\1', password):
            return True
        
        # Check for alternating patterns (abab, 1212)
        if re.search(r'(..)(\1){2,}', password):
            return True
        
        return False
    
    def _has_date_patterns(self, password: str) -> bool:
        """Check for date-like patterns."""
        date_patterns = [
            r'\d{4}',  # Year (1900-2099)
            r'\d{1,2}[/-]\d{1,2}',  # Month/day patterns
            r'\d{2}/\d{2}/\d{2,4}',  # Full date patterns
            r'(19|20)\d{2}',  # Specific year patterns
        ]
        
        for pattern in date_patterns:
            if re.search(pattern, password):
                return True
        
        return False
    
    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters (abc, 123, etc.)."""
        password_lower = password.lower()
        
        # Check for 3+ sequential letters
        for i in range(len(password_lower) - 2):
            if password_lower[i:i+3].isalpha():
                chars = password_lower[i:i+3]
                if (ord(chars[1]) == ord(chars[0]) + 1 and 
                    ord(chars[2]) == ord(chars[1]) + 1):
                    return True
                # Check reverse sequence
                if (ord(chars[1]) == ord(chars[0]) - 1 and 
                    ord(chars[2]) == ord(chars[1]) - 1):
                    return True
        
        # Check for 3+ sequential numbers
        for i in range(len(password) - 2):
            if password[i:i+3].isdigit():
                nums = password[i:i+3]
                if (int(nums[1]) == int(nums[0]) + 1 and 
                    int(nums[2]) == int(nums[1]) + 1):
                    return True
                # Check reverse sequence
                if (int(nums[1]) == int(nums[0]) - 1 and 
                    int(nums[2]) == int(nums[1]) - 1):
                    return True
        
        return False
    
    def get_entropy_category(self, entropy: float) -> Tuple[str, str]:
        """
        Categorize entropy level with description.
        
        Args:
            entropy: Entropy value in bits
            
        Returns:
            Tuple[str, str]: (category, description)
        """
        if entropy < 20:
            return "Very Low", "Easily crackable with basic tools"
        elif entropy < 35:
            return "Low", "Vulnerable to dictionary and brute force attacks"
        elif entropy < 50:
            return "Moderate", "Decent protection against casual attacks"
        elif entropy < 65:
            return "High", "Strong protection against most attacks"
        else:
            return "Very High", "Excellent protection against advanced attacks"
    
    def get_detailed_analysis(self, password: str) -> Dict[str, any]:
        """
        Get detailed entropy analysis with breakdown.
        
        Args:
            password: Password to analyze
            
        Returns:
            Dict: Detailed analysis results
        """
        if not password:
            return {
                'entropy': 0.0,
                'category': 'None',
                'description': 'No password provided',
                'charset_analysis': {},
                'pattern_penalties': []
            }
        
        # Calculate all entropy types
        charset_entropy = self._calculate_charset_entropy(password)
        frequency_entropy = self._calculate_frequency_entropy(password)
        final_entropy = self.calculate(password)
        
        # Character set analysis
        charset_analysis = {
            'total_size': self._get_charset_size(password),
            'lowercase': any(c.islower() for c in password),
            'uppercase': any(c.isupper() for c in password),
            'digits': any(c.isdigit() for c in password),
            'symbols': any(not c.isalnum() for c in password),
            'unique_chars': len(set(password))
        }
        
        # Pattern analysis
        pattern_penalties = []
        password_lower = password.lower()
        
        for pattern in self.keyboard_patterns:
            if pattern in password_lower or pattern[::-1] in password_lower:
                pattern_penalties.append(f"Keyboard pattern: {pattern}")
        
        for word in self.common_words:
            if word in password_lower:
                pattern_penalties.append(f"Dictionary word: {word}")
        
        if self._has_repeated_sequences(password):
            pattern_penalties.append("Repeated character sequences")
        
        if self._has_date_patterns(password):
            pattern_penalties.append("Date-like patterns")
        
        if self._has_sequential_chars(password):
            pattern_penalties.append("Sequential characters")
        
        category, description = self.get_entropy_category(final_entropy)
        
        return {
            'entropy': final_entropy,
            'charset_entropy': charset_entropy,
            'frequency_entropy': frequency_entropy,
            'category': category,
            'description': description,
            'charset_analysis': charset_analysis,
            'pattern_penalties': pattern_penalties,
            'length': len(password)
        }


# Example usage and testing
if __name__ == "__main__":
    # Test the entropy calculator
    from ..utils.logger import setup_logging
    
    setup_logging("DEBUG")
    calculator = EntropyCalculator()
    
    test_passwords = [
        "password",
        "Password123",
        "P@ssw0rd!",
        "MyS3cur3P@ssw0rd!",
        "correct horse battery staple",
        "Tr0ub4dor&3",
        "X9#mK$pL2@vR8qW",
        "qwerty12345",
        "abc123def456"
    ]
    
    print("Password Entropy Analysis:")
    print("=" * 50)
    
    for pwd in test_passwords:
        analysis = calculator.get_detailed_analysis(pwd)
        print(f"\nPassword: {'*' * len(pwd)} (length: {len(pwd)})")
        print(f"Entropy: {analysis['entropy']:.2f} bits ({analysis['category']})")
        print(f"Character set size: {analysis['charset_analysis']['total_size']}")
        
        if analysis['pattern_penalties']:
            print(f"Pattern issues: {', '.join(analysis['pattern_penalties'])}")
        else:
            print("Pattern issues: None detected")