# src/core/analyzer.py
"""
Main password analyzer class that orchestrates all analysis components.
This is the core business logic separated from UI and infrastructure concerns.
"""

from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import time
from .entropy import EntropyCalculator
from .patterns import PatternDetector
from .breach_checker import BreachChecker
from ..utils.logger import get_logger, log_password_analysis
from ..utils.config import get_config

logger = get_logger(__name__)


@dataclass
class PasswordAnalysisResult:
    """Data class for comprehensive password analysis results."""
    
    # Overall assessment
    overall_strength: str
    score: int
    category: str
    
    # Component analysis
    length_analysis: str
    character_variety: str
    entropy: float
    entropy_category: str
    breach_status: str
    
    # Detailed findings
    security_issues: List[str]
    recommendations: List[str]
    strength_meter: str
    
    # Advanced metrics
    pattern_score: int
    entropy_bits: float
    breach_count: int
    analysis_time_ms: float
    
    # Raw component data (for debugging/advanced users)
    raw_data: Optional[Dict] = None


class PasswordAnalyzer:
    """
    Main password analyzer that coordinates all analysis components.
    Follows single responsibility principle - only orchestrates, doesn't implement.
    """
    
    def __init__(self):
        """Initialize analyzer with all component engines."""
        self.config = get_config()
        
        # Initialize analysis components
        self.entropy_calculator = EntropyCalculator()
        self.pattern_detector = PatternDetector()
        self.breach_checker = BreachChecker()
        
        # Scoring weights for overall assessment
        self.scoring_weights = {
            'length': 0.25,      # 25% weight
            'variety': 0.25,     # 25% weight  
            'entropy': 0.25,     # 25% weight
            'patterns': 0.25     # 25% weight
        }
        
        # Breach penalty (applied after base scoring)
        self.breach_penalty = 30
        
        logger.info("PasswordAnalyzer initialized with all components")
    
    def analyze(self, password: str, client_id: str = "anonymous") -> PasswordAnalysisResult:
        """
        Comprehensive password analysis using all available components.
        
        Args:
            password: The password to analyze
            client_id: Client identifier for logging and rate limiting
            
        Returns:
            PasswordAnalysisResult: Complete analysis results
        """
        start_time = time.time()
        
        if not password:
            return self._empty_result(0.0)
        
        # Validate password length
        if len(password) > self.config.max_password_length:
            logger.warning(f"Password too long ({len(password)} chars) for client {client_id[:8]}...")
            return self._error_result("Password too long", time.time() - start_time)
        
        logger.info(f"Starting comprehensive analysis for client {client_id[:8]}... (length: {len(password)})")
        
        try:
            # Step 1: Basic metrics
            basic_metrics = self._calculate_basic_metrics(password)
            
            # Step 2: Advanced analysis (can be done in parallel in production)
            entropy_result = self._analyze_entropy(password)
            pattern_result = self._analyze_patterns(password)
            breach_result = self._analyze_breaches(password, client_id)
            
            # Step 3: Calculate overall score
            overall_score = self._calculate_overall_score(
                basic_metrics, entropy_result, pattern_result, breach_result
            )
            
            # Step 4: Generate comprehensive result
            analysis_time = (time.time() - start_time) * 1000
            result = self._create_result(
                password, basic_metrics, entropy_result, pattern_result, 
                breach_result, overall_score, analysis_time
            )
            
            # Log successful analysis
            log_password_analysis(client_id, len(password), result.score)
            
            logger.info(f"Analysis complete for client {client_id[:8]}... - Score: {result.score}/100, Time: {analysis_time:.2f}ms")
            
            return result
            
        except Exception as e:
            analysis_time = (time.time() - start_time) * 1000
            logger.error(f"Analysis failed for client {client_id[:8]}...: {e}")
            return self._error_result(f"Analysis error: {str(e)}", analysis_time)
    
    def _calculate_basic_metrics(self, password: str) -> Dict:
        """Calculate basic password metrics."""
        return {
            'length': len(password),
            'has_lower': any(c.islower() for c in password),
            'has_upper': any(c.isupper() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_symbols': any(not c.isalnum() for c in password),
            'unique_chars': len(set(password)),
            'char_variety_count': sum([
                any(c.islower() for c in password),
                any(c.isupper() for c in password),
                any(c.isdigit() for c in password),
                any(not c.isalnum() for c in password)
            ])
        }
    
    def _analyze_entropy(self, password: str) -> Dict:
        """Analyze password entropy with detailed breakdown."""
        try:
            detailed_analysis = self.entropy_calculator.get_detailed_analysis(password)
            return {
                'entropy': detailed_analysis['entropy'],
                'category': detailed_analysis['category'],
                'description': detailed_analysis['description'],
                'charset_entropy': detailed_analysis.get('charset_entropy', 0),
                'frequency_entropy': detailed_analysis.get('frequency_entropy', 0),
                'penalties': detailed_analysis.get('pattern_penalties', [])
            }
        except Exception as e:
            logger.error(f"Entropy analysis failed: {e}")
            return {
                'entropy': 0.0,
                'category': 'Error',
                'description': 'Entropy calculation failed',
                'charset_entropy': 0,
                'frequency_entropy': 0,
                'penalties': []
            }
    
    def _analyze_patterns(self, password: str) -> Dict:
        """Analyze password patterns with detailed breakdown."""
        try:
            pattern_score, issues = self.pattern_detector.get_pattern_score(password)
            return {
                'score': pattern_score,
                'issues': issues,
                'issue_count': len(issues)
            }
        except Exception as e:
            logger.error(f"Pattern analysis failed: {e}")
            return {
                'score': 0,
                'issues': [f"Pattern analysis error: {str(e)}"],
                'issue_count': 1
            }
    
    def _analyze_breaches(self, password: str, client_id: str) -> Dict:
        """Analyze password breach status."""
        try:
            is_breached, breach_count = self.breach_checker.check_breach(password, client_id)
            return {
                'is_breached': is_breached,
                'breach_count': breach_count,
                'status': 'checked',
                'api_available': is_breached is not None
            }
        except Exception as e:
            logger.error(f"Breach analysis failed: {e}")
            return {
                'is_breached': None,
                'breach_count': 0,
                'status': 'error',
                'api_available': False
            }
    
    def _calculate_overall_score(self, basic_metrics: Dict, entropy_result: Dict, 
                                pattern_result: Dict, breach_result: Dict) -> int:
        """
        Calculate overall password score (0-100) using weighted components, with hard penalties for very weak passwords.
        """
        length = basic_metrics['length']
        variety_count = basic_metrics['char_variety_count']
        entropy = entropy_result['entropy']

        # Hard fail for extremely weak passwords
        if length < 4 or variety_count < 2 or entropy < 10:
            return 0

        # Length scoring (0-25 points)
        length_score = self._calculate_length_score(length)
        # Character variety scoring (0-25 points)
        variety_score = self._calculate_variety_score(basic_metrics)
        # Entropy scoring (0-25 points)  
        entropy_score = self._calculate_entropy_score(entropy)
        # Pattern scoring (0-25 points)
        pattern_score = min(25, pattern_result['score'] * 0.25)

        # Combine weighted scores
        base_score = (
            length_score * self.scoring_weights['length'] +
            variety_score * self.scoring_weights['variety'] +
            entropy_score * self.scoring_weights['entropy'] +
            pattern_score * self.scoring_weights['patterns']
        ) / sum(self.scoring_weights.values()) * 100

        # Additional penalty for short passwords
        if length < 8:
            base_score *= 0.5

        # Apply breach penalty
        if breach_result['is_breached']:
            base_score = max(0, base_score - self.breach_penalty)

        # Ensure score is within valid range
        final_score = max(0, min(100, int(base_score)))

        logger.debug(f"Score breakdown - Length: {length_score:.1f}, Variety: {variety_score:.1f}, "
                    f"Entropy: {entropy_score:.1f}, Patterns: {pattern_score:.1f}, "
                    f"Base: {base_score:.1f}, Final: {final_score}")

        return final_score
    
    def _calculate_length_score(self, length: int) -> float:
        """Calculate score based on password length."""
        if length >= 16: return 25.0
        elif length >= 12: return 20.0
        elif length >= 8: return 15.0
        elif length >= 6: return 10.0
        elif length >= 4: return 5.0
        else: return 1.0
    
    def _calculate_variety_score(self, basic_metrics: Dict) -> float:
        """Calculate score based on character variety."""
        variety_count = basic_metrics['char_variety_count']
        if variety_count == 4: return 25.0
        elif variety_count == 3: return 18.0
        elif variety_count == 2: return 12.0
        elif variety_count == 1: return 6.0
        else: return 0.0
    
    def _calculate_entropy_score(self, entropy: float) -> float:
        """Calculate score based on entropy."""
        if entropy >= 70: return 25.0
        elif entropy >= 60: return 20.0
        elif entropy >= 50: return 16.0
        elif entropy >= 40: return 12.0
        elif entropy >= 30: return 8.0
        elif entropy >= 20: return 4.0
        else: return 1.0
    
    def _create_result(self, password: str, basic_metrics: Dict, entropy_result: Dict,
                      pattern_result: Dict, breach_result: Dict, overall_score: int,
                      analysis_time: float) -> PasswordAnalysisResult:
        """Create comprehensive analysis result."""
        
        # Overall strength assessment
        overall_strength, category = self._get_strength_assessment(overall_score)
        
        # Format component results
        length_analysis = self._format_length_analysis(basic_metrics['length'])
        character_variety = self._format_variety_analysis(basic_metrics)
        breach_status = self._format_breach_status(breach_result)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            basic_metrics, entropy_result, pattern_result, breach_result
        )
        
        # Create visual strength meter
        strength_meter = self._create_strength_meter(overall_score, overall_strength.split()[0])
        
        # Combine all security issues
        security_issues = pattern_result['issues'].copy()
        if entropy_result['penalties']:
            security_issues.extend(entropy_result['penalties'])
        
        return PasswordAnalysisResult(
            overall_strength=overall_strength,
            score=overall_score,
            category=category,
            length_analysis=length_analysis,
            character_variety=character_variety,
            entropy=entropy_result['entropy'],
            entropy_category=entropy_result['category'],
            breach_status=breach_status,
            security_issues=security_issues,
            recommendations=recommendations,
            strength_meter=strength_meter,
            pattern_score=pattern_result['score'],
            entropy_bits=entropy_result['entropy'],
            breach_count=breach_result['breach_count'],
            analysis_time_ms=analysis_time,
            raw_data={
                'basic_metrics': basic_metrics,
                'entropy_result': entropy_result,
                'pattern_result': pattern_result,
                'breach_result': breach_result
            }
        )
    
    def _get_strength_assessment(self, score: int) -> Tuple[str, str]:
        """Get overall strength assessment (no emoji)."""
        if score >= 90:
            return "Excellent", "excellent"
        elif score >= 75:
            return "Strong", "strong"
        elif score >= 60:
            return "Good", "good"
        elif score >= 40:
            return "Fair", "fair"
        elif score >= 20:
            return "Weak", "weak"
        else:
            return "Very Weak", "very_weak"
    
    def _format_length_analysis(self, length: int) -> str:
        """Format length analysis with recommendations."""
        if length >= 16:
            return f"{length} characters ✅ (Excellent length)"
        elif length >= 12:
            return f"{length} characters ✅ (Good length)"
        elif length >= 8:
            return f"{length} characters ⚠️ (Acceptable, but longer is better)"
        elif length >= 6:
            return f"{length} characters ❌ (Too short, use 12+ characters)"
        else:
            return f"{length} characters ❌ (Dangerously short)"
    
    def _format_variety_analysis(self, basic_metrics: Dict) -> str:
        """Format character variety analysis."""
        char_types = []
        if basic_metrics['has_lower']: char_types.append("lowercase")
        if basic_metrics['has_upper']: char_types.append("UPPERCASE") 
        if basic_metrics['has_digits']: char_types.append("numbers")
        if basic_metrics['has_symbols']: char_types.append("symbols")
        
        variety_count = len(char_types)
        unique_chars = basic_metrics['unique_chars']
        
        emoji = "✅" if variety_count >= 3 else "⚠️" if variety_count >= 2 else "❌"
        
        return f"{variety_count}/4 types: {', '.join(char_types)} {emoji} ({unique_chars} unique chars)"
    
    def _format_breach_status(self, breach_result: Dict) -> str:
        """Format breach status with appropriate warnings."""
        if not breach_result['api_available']:
            return "❓ Could not check breaches (API unavailable)"
        elif breach_result['is_breached']:
            count = breach_result['breach_count']
            return f"🚨 BREACHED! Found in {count:,} data breaches - Change immediately!"
        else:
            return "✅ Not found in known data breaches"
    
    def _generate_recommendations(self, basic_metrics: Dict, entropy_result: Dict,
                                 pattern_result: Dict, breach_result: Dict) -> List[str]:
        """Generate specific recommendations for password improvement."""
        recommendations = []
        
        # Length recommendations
        if basic_metrics['length'] < 12:
            recommendations.append("🔢 Use at least 12 characters for better security")
        elif basic_metrics['length'] < 16:
            recommendations.append("🔢 Consider using 16+ characters for excellent security")
        
        # Character variety recommendations
        if not basic_metrics['has_upper']:
            recommendations.append("🔤 Add uppercase letters (A-Z)")
        if not basic_metrics['has_lower']:
            recommendations.append("🔡 Add lowercase letters (a-z)")
        if not basic_metrics['has_digits']:
            recommendations.append("🔢 Add numbers (0-9)")
        if not basic_metrics['has_symbols']:
            recommendations.append("🔣 Add special characters (!@#$%^&*)")
        
        # Entropy recommendations
        if entropy_result['entropy'] < 50:
            recommendations.append("🎲 Increase randomness - avoid predictable patterns")
        
        # Pattern recommendations
        if pattern_result['issue_count'] > 0:
            recommendations.append("🚫 Avoid common patterns, dictionary words, and sequences")
        
        # Breach recommendations
        if breach_result['is_breached']:
            recommendations.append("🚨 CRITICAL: This password is compromised - create a new one immediately!")
        
        # Positive reinforcement
        if not recommendations:
            recommendations.append("🎉 Excellent! This is a very strong password.")
        elif len(recommendations) <= 2:
            recommendations.append("👍 You're on the right track - just a few improvements needed!")
        
        return recommendations
    
    def _create_strength_meter(self, score: int, emoji: str) -> str:
        """Create visual strength meter representation."""
        filled_blocks = min(20, int(score / 5))
        empty_blocks = 20 - filled_blocks
        
        meter_fill = "█" * filled_blocks + "░" * empty_blocks
        return f"{emoji} [{meter_fill}] {score}/100"
    
    def _empty_result(self, analysis_time: float) -> PasswordAnalysisResult:
        """Return result for empty password."""
        return PasswordAnalysisResult(
            overall_strength="❌ No Password",
            score=0,
            category="empty",
            length_analysis="0 characters ❌",
            character_variety="N/A",
            entropy=0.0,
            entropy_category="None",
            breach_status="N/A",
            security_issues=[],
            recommendations=["Enter a password to analyze"],
            strength_meter="❌ [░░░░░░░░░░░░░░░░░░░░] 0/100",
            pattern_score=0,
            entropy_bits=0.0,
            breach_count=0,
            analysis_time_ms=analysis_time
        )
    
    def _error_result(self, error_message: str, analysis_time: float) -> PasswordAnalysisResult:
        """Return result for analysis errors."""
        return PasswordAnalysisResult(
            overall_strength="❌ Analysis Error",
            score=0,
            category="error",
            length_analysis="N/A",
            character_variety="N/A",
            entropy=0.0,
            entropy_category="Error",
            breach_status="N/A",
            security_issues=[error_message],
            recommendations=["Please try again or contact support"],
            strength_meter="❌ [░░░░░░░░░░░░░░░░░░░░] 0/100",
            pattern_score=0,
            entropy_bits=0.0,
            breach_count=0,
            analysis_time_ms=analysis_time
        )


# Example usage and testing
if __name__ == "__main__":
    from ..utils.logger import setup_logging
    
    setup_logging("INFO")
    analyzer = PasswordAnalyzer()
    
    test_passwords = [
        "",                           # Empty
        "password",                   # Very weak
        "Password1",                  # Weak but common
        "MyP@ssw0rd123",             # Fair
        "MyS3cur3P@ssw0rd!",         # Good
        "correct horse battery staple", # Passphrase
        "X9#mK$pL2@vR8qW",           # Strong random
        "Tr0ub4dor&3"                # XKCD reference
    ]
    
    print("CipherGuard Password Analysis Results:")
    print("=" * 60)
    
    for i, pwd in enumerate(test_passwords):
        print(f"\n{i+1}. Password: {'(empty)' if not pwd else '*' * len(pwd)} (length: {len(pwd)})")
        
        result = analyzer.analyze(pwd, f"test_client_{i}")
        
        print(f"   Overall: {result.overall_strength}")
        print(f"   Score: {result.score}/100")
        print(f"   {result.strength_meter}")
        print(f"   Analysis time: {result.analysis_time_ms:.1f}ms")
        
        if result.security_issues:
            print(f"   Issues: {len(result.security_issues)} found")
        
        if result.recommendations:
            print(f"   Top recommendation: {result.recommendations[0]}")