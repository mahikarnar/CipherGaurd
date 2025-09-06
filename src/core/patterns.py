# src/core/patterns.py
"""
Pattern detection for identifying weak password patterns.
Uses regex, heuristics, and databases to find common weaknesses.
"""

import re
from typing import List, Set, Dict, Tuple
from collections import Counter
from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger(__name__)


class PatternDetector:
    """
    Detects common weak patterns in passwords using various methods.
    Each detected pattern represents a security vulnerability.
    """
    
    def __init__(self):
        """Initialize pattern detector with comprehensive pattern databases."""
        self.config = get_config()
        
        # Dictionary of common weak passwords and words
        self.common_passwords = {
            'password', '123456', 'qwerty', 'abc123', 'admin', 'login',
            'welcome', 'monkey', 'letmein', 'dragon', 'master', 'sunshine',
            'princess', 'football', 'baseball', 'superman', 'michael',
            'shadow', 'flower', 'passw0rd', 'password1', '12345678',
            'iloveyou', 'purple', 'jordan', 'maggie', 'charlie',
            'trustno1', 'summer', 'ashley', 'bailey', 'access'
        }
        
        # Keyboard walking patterns
        self.keyboard_patterns = {
            # QWERTY rows
            'qwertyuiop': 'QWERTY top row',
            'asdfghjkl': 'QWERTY middle row', 
            'zxcvbnm': 'QWERTY bottom row',
            # Common sub-patterns
            'qwerty': 'QWERTY sequence',
            'asdf': 'ASDF sequence',
            'zxcv': 'ZXCV sequence',
            # Number sequences
            '1234567890': 'Number row',
            '0987654321': 'Number row reversed',
            '123456': 'Sequential numbers',
            '654321': 'Sequential numbers reversed',
            # Common key walks
            'qaz': 'Q-A-Z key walk',
            'wsx': 'W-S-X key walk',
            'edc': 'E-D-C key walk',
            '!qaz': 'Shift+Q-A-Z pattern',
            '@wsx': 'Shift+W-S-X pattern'
        }
        
        # Date and year patterns (regex patterns)
        self.date_patterns = {
            r'\b(19|20)\d{2}\b': 'Four-digit year',
            r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b': 'Date format',
            r'\b\d{4}[/-]\d{2}[/-]\d{2}\b': 'ISO date format',
            r'\b\d{2}[/-]\d{2}[/-]\d{4}\b': 'US date format',
            r'\b(0?[1-9]|1[0-2])[/-](0?[1-9]|[12]\d|3[01])\b': 'Month/Day pattern'
        }
        
        # Personal information patterns
        self.personal_patterns = {
            r'\b[A-Z][a-z]+\b': 'Capitalized word (possible name)',
            r'\b\d{3}-?\d{2}-?\d{4}\b': 'SSN-like pattern',
            r'\b\d{10}\b': 'Phone number pattern',
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': 'Email pattern'
        }
        
        # Substitution patterns (leet speak)
        self.substitution_patterns = {
            'a': ['@', '4'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['$', '5'],
            't': ['7'],
            'l': ['1', '!']
        }
        
        logger.debug(f"PatternDetector initialized with {len(self.common_passwords)} common passwords")
    
    def detect_weaknesses(self, password: str) -> List[str]:
        """
        Detect all weakness patterns in the password.
        
        Args:
            password: Password to analyze
            
        Returns:
            List[str]: List of detected weaknesses with descriptions
        """
        if not password:
            return ["Empty password"]
        
        logger.debug(f"Analyzing password patterns for length {len(password)} password")
        
        issues = []
        
        # Check each category of patterns
        issues.extend(self._check_common_passwords(password))
        issues.extend(self._check_keyboard_patterns(password))
        issues.extend(self._check_sequential_patterns(password))
        issues.extend(self._check_repetition_patterns(password))
        issues.extend(self._check_date_patterns(password))
        issues.extend(self._check_personal_patterns(password))
        issues.extend(self._check_character_distribution(password))
        issues.extend(self._check_substitution_patterns(password))
        issues.extend(self._check_length_issues(password))
        
        # Remove duplicates while preserving order
        unique_issues = []
        seen = set()
        for issue in issues:
            if issue not in seen:
                unique_issues.append(issue)
                seen.add(issue)
        
        logger.info(f"Detected {len(unique_issues)} pattern weaknesses")
        return unique_issues
    
    def _check_common_passwords(self, password: str) -> List[str]:
        """Check for common dictionary passwords."""
        issues = []
        password_lower = password.lower()
        
        # Direct matches
        if password_lower in self.common_passwords:
            issues.append(f"Contains common password: '{password_lower}'")
        
        # Substring matches for longer passwords
        for common_pwd in self.common_passwords:
            if len(common_pwd) >= 4 and common_pwd in password_lower:
                issues.append(f"Contains common password fragment: '{common_pwd}'")
                break  # Only report one to avoid spam
        
        return issues
    
    def _check_keyboard_patterns(self, password: str) -> List[str]:
        """Check for keyboard walking patterns."""
        issues = []
        password_lower = password.lower()
        
        for pattern, description in self.keyboard_patterns.items():
            if pattern in password_lower:
                issues.append(f"Keyboard pattern detected: {description}")
            elif pattern[::-1] in password_lower:  # Check reverse
                issues.append(f"Reverse keyboard pattern detected: {description}")
        
        return issues
    
    def _check_sequential_patterns(self, password: str) -> List[str]:
        """Check for sequential characters (abc, 123, etc.)."""
        issues = []
        
        # Check for 3+ sequential letters
        sequential_letters = self._find_sequential_letters(password)
        if sequential_letters:
            issues.append(f"Sequential letters found: {', '.join(sequential_letters)}")
        
        # Check for 3+ sequential numbers
        sequential_numbers = self._find_sequential_numbers(password)
        if sequential_numbers:
            issues.append(f"Sequential numbers found: {', '.join(sequential_numbers)}")
        
        return issues
    
    def _check_repetition_patterns(self, password: str) -> List[str]:
        """Check for excessive character repetition."""
        issues = []
        
        # Check for same character repeated 3+ times
        repeated_chars = re.findall(r'(.)\1{2,}', password)
        if repeated_chars:
            issues.append(f"Repeated characters: {', '.join(set(repeated_chars))}")
        
        # Check for repeated patterns (abab, 1212)
        repeated_patterns = re.findall(r'(.{2,})\1+', password)
        if repeated_patterns:
            issues.append(f"Repeated patterns detected")
        
        # Check if password has too few unique characters
        unique_chars = len(set(password.lower()))
        if len(password) > 6 and unique_chars < len(password) / 3:
            issues.append(f"Too few unique characters ({unique_chars}/{len(password)})")
        
        return issues
    
    def _check_date_patterns(self, password: str) -> List[str]:
        """Check for date patterns that could be guessable."""
        issues = []
        
        for pattern, description in self.date_patterns.items():
            matches = re.findall(pattern, password)
            if matches:
                issues.append(f"Date pattern detected: {description}")
                break  # Only report one date pattern
        
        return issues
    
    def _check_personal_patterns(self, password: str) -> List[str]:
        """Check for personal information patterns."""
        issues = []
        
        for pattern, description in self.personal_patterns.items():
            if re.search(pattern, password):
                issues.append(f"Personal info pattern: {description}")
        
        return issues
    
    def _check_character_distribution(self, password: str) -> List[str]:
        """Check for poor character distribution."""
        issues = []
        
        if len(password) < 8:
            return issues
        
        # Analyze character type distribution
        char_counts = {
            'letters': sum(1 for c in password if c.isalpha()),
            'digits': sum(1 for c in password if c.isdigit()),
            'symbols': sum(1 for c in password if not c.isalnum())
        }
        
        total_chars = len(password)
        
        # Check if one type dominates (>80% of password)
        for char_type, count in char_counts.items():
            if count > 0 and count / total_chars > 0.8:
                issues.append(f"Password is mostly {char_type} ({count}/{total_chars})")
        
        # Check for clustered character types (all numbers at end, etc.)
        if char_counts['digits'] > 2:
            # Find positions of digits
            digit_positions = [i for i, c in enumerate(password) if c.isdigit()]
            if digit_positions:
                first_digit = min(digit_positions)
                last_digit = max(digit_positions)
                
                # If all digits are clustered at the end
                if first_digit > len(password) * 0.7:
                    issues.append("All numbers clustered at end")
                # If all digits are clustered at the beginning
                elif last_digit < len(password) * 0.3:
                    issues.append("All numbers clustered at beginning")
        
        return issues
    
    def _check_substitution_patterns(self, password: str) -> List[str]:
        """Check for simple character substitutions (leet speak)."""
        issues = []
        
        # Create a version with substitutions reversed
        desubstituted = password.lower()
        substitution_count = 0
        
        for original_char, substitutes in self.substitution_patterns.items():
            for substitute in substitutes:
                if substitute in password:
                    desubstituted = desubstituted.replace(substitute.lower(), original_char)
                    substitution_count += 1
        
        # If the desubstituted version contains common passwords
        if substitution_count > 0:
            for common_pwd in self.common_passwords:
                if common_pwd in desubstituted:
                    issues.append(f"Simple substitution of common word: '{common_pwd}' → contains '{substitute}'")
                    break
        
        return issues
    
    def _check_length_issues(self, password: str) -> List[str]:
        """Check for length-related issues."""
        issues = []
        
        length = len(password)
        
        if length < 8:
            issues.append(f"Password too short ({length} characters, minimum 8 recommended)")
        elif length > 128:
            issues.append(f"Password unnecessarily long ({length} characters)")
        
        return issues
    
    def _find_sequential_letters(self, password: str) -> List[str]:
        """Find sequences of 3+ sequential letters."""
        sequences = []
        password_lower = password.lower()
        
        i = 0
        while i < len(password_lower) - 2:
            if password_lower[i:i+3].isalpha():
                # Check for ascending sequence
                seq_len = 3
                while (i + seq_len < len(password_lower) and 
                       password_lower[i + seq_len].isalpha() and
                       ord(password_lower[i + seq_len]) == ord(password_lower[i + seq_len - 1]) + 1):
                    seq_len += 1
                
                if seq_len >= 3:
                    sequences.append(password_lower[i:i+seq_len])
                    i += seq_len
                    continue
                
                # Check for descending sequence
                seq_len = 3
                while (i + seq_len < len(password_lower) and 
                       password_lower[i + seq_len].isalpha() and
                       ord(password_lower[i + seq_len]) == ord(password_lower[i + seq_len - 1]) - 1):
                    seq_len += 1
                
                if seq_len >= 3:
                    sequences.append(password_lower[i:i+seq_len])
                    i += seq_len
                    continue
            
            i += 1
        
        return sequences
    
    def _find_sequential_numbers(self, password: str) -> List[str]:
        """Find sequences of 3+ sequential numbers."""
        sequences = []
        
        i = 0
        while i < len(password) - 2:
            if password[i:i+3].isdigit():
                # Check for ascending sequence
                seq_len = 3
                while (i + seq_len < len(password) and 
                       password[i + seq_len].isdigit() and
                       int(password[i + seq_len]) == int(password[i + seq_len - 1]) + 1):
                    seq_len += 1
                
                if seq_len >= 3:
                    sequences.append(password[i:i+seq_len])
                    i += seq_len
                    continue
                
                # Check for descending sequence
                seq_len = 3
                while (i + seq_len < len(password) and 
                       password[i + seq_len].isdigit() and
                       int(password[i + seq_len]) == int(password[i + seq_len - 1]) - 1):
                    seq_len += 1
                
                if seq_len >= 3:
                    sequences.append(password[i:i+seq_len])
                    i += seq_len
                    continue
            
            i += 1
        
        return sequences
    
    def get_pattern_score(self, password: str) -> Tuple[int, List[str]]:
        """
        Get a pattern strength score (0-100) and list of issues.
        
        Args:
            password: Password to analyze
            
        Returns:
            Tuple[int, List[str]]: (score, list of issues)
        """
        issues = self.detect_weaknesses(password)
        
        # Start with perfect score
        score = 100
        
        # Deduct points for each type of issue
        for issue in issues:
            if "common password" in issue.lower():
                score -= 25  # Heavy penalty
            elif "keyboard pattern" in issue.lower():
                score -= 20
            elif "sequential" in issue.lower():
                score -= 15
            elif "repeated" in issue.lower():
                score -= 15
            elif "date pattern" in issue.lower():
                score -= 10
            elif "clustered" in issue.lower():
                score -= 10
            elif "substitution" in issue.lower():
                score -= 15
            elif "too short" in issue.lower():
                score -= 20
            else:
                score -= 5  # Generic penalty
        
        # Ensure score doesn't go below 0
        score = max(0, score)
        
        return score, issues


# Example usage and testing
if __name__ == "__main__":
    from ..utils.logger import setup_logging
    
    setup_logging("DEBUG")
    detector = PatternDetector()
    
    test_passwords = [
        "password",           # Common password
        "qwerty123",         # Keyboard + sequential
        "Password1",         # Common + substitution
        "abc123def",         # Sequential letters + numbers
        "aaabbbccc",         # Repetition
        "john1985",          # Name + year
        "P@ssw0rd",          # Substitution
        "MyS3cur3P@ss!",     # Mixed but with substitutions
        "correct horse battery staple",  # Passphrase
        "X9#mK$pL2@vR8qW"   # Random strong password
    ]
    
    print("Password Pattern Analysis:")
    print("=" * 60)
    
    for pwd in test_passwords:
        score, issues = detector.get_pattern_score(pwd)
        print(f"\nPassword: {'*' * len(pwd)} (length: {len(pwd)})")
        print(f"Pattern Score: {score}/100")
        
        if issues:
            print("Issues found:")
            for issue in issues:
                print(f"  • {issue}")
        else:
            print("No pattern issues detected")