# test_system.py
"""
Quick system test to verify all components work together.
Run this to test your CipherGuard installation.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_imports():
    """Test that all modules can be imported."""
    print("🔍 Testing imports...")
    
    try:
        from src.utils.config import get_config
        from src.utils.logger import setup_logging, get_logger
        from src.core.entropy import EntropyCalculator
        from src.core.patterns import PatternDetector
        from src.core.breach_checker import BreachChecker
        from src.core.analyzer import PasswordAnalyzer
        from src.security.rate_limiter import RateLimiter
        from src.security.validators import InputValidator
        from src.ui.gradio_app import create_password_analyzer_interface
        
        print("✅ All imports successful!")
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False


def test_core_components():
    """Test core analysis components."""
    print("\n🧮 Testing core components...")
    
    try:
        # Setup logging
        from src.utils.logger import setup_logging, get_logger
        setup_logging("INFO")
        logger = get_logger(__name__)
        
        # Test entropy calculator
        from src.core.entropy import EntropyCalculator
        entropy_calc = EntropyCalculator()
        entropy = entropy_calc.calculate("TestPassword123!")
        print(f"✅ Entropy calculation: {entropy:.1f} bits")
        
        # Test pattern detector
        from src.core.patterns import PatternDetector
        pattern_detector = PatternDetector()
        issues = pattern_detector.detect_weaknesses("password123")
        print(f"✅ Pattern detection: {len(issues)} issues found")
        
        # Test analyzer (without breach check to avoid API calls)
        from src.core.analyzer import PasswordAnalyzer
        analyzer = PasswordAnalyzer()
        result = analyzer.analyze("TestPassword123!", "test_client")
        print(f"✅ Full analysis: {result.score}/100 score")
        
        return True
        
    except Exception as e:
        print(f"❌ Core component test failed: {e}")
        return False


def test_security_components():
    """Test security components."""
    print("\n🛡️ Testing security components...")
    
    try:
        # Test rate limiter
        from src.security.rate_limiter import RateLimiter
        limiter = RateLimiter(max_requests=5, window_seconds=10)
        
        for i in range(3):
            result = limiter.is_allowed("test_client")
            if not result.allowed:
                print(f"❌ Rate limiter failed on request {i+1}")
                return False
        
        print("✅ Rate limiter working")
        
        # Test input validator
        from src.security.validators import InputValidator
        validator = InputValidator()
        result = validator.validate_password("TestPassword123!", "test_client")
        
        if not result.is_valid:
            print(f"❌ Validator rejected valid password: {result.errors}")
            return False
        
        print("✅ Input validator working")
        
        return True
        
    except Exception as e:
        print(f"❌ Security component test failed: {e}")
        return False


def test_gradio_interface():
    """Test that Gradio interface can be created."""
    print("\n🎨 Testing Gradio interface...")
    
    try:
        from src.ui.gradio_app import create_password_analyzer_interface
        
        # This just tests creation, not launching
        interface = create_password_analyzer_interface()
        print("✅ Gradio interface created successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Gradio interface test failed: {e}")
        return False


def test_configuration():
    """Test configuration loading."""
    print("\n⚙️ Testing configuration...")
    
    try:
        from src.utils.config import get_config
        
        config = get_config()
        print(f"✅ Configuration loaded:")
        print(f"  • Server: {config.server_host}:{config.server_port}")
        print(f"  • Rate limit: {config.rate_limit_requests}/{config.rate_limit_window}s")
        print(f"  • Max password length: {config.max_password_length}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False


def main():
    """Run all system tests."""
    print("🔐 CipherGuard System Test")
    print("=" * 40)
    
    tests = [
        ("Import Test", test_imports),
        ("Configuration Test", test_configuration),
        ("Core Components", test_core_components),
        ("Security Components", test_security_components),
        ("Gradio Interface", test_gradio_interface),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ {test_name} crashed: {e}")
            failed += 1
    
    print("\n" + "=" * 40)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! CipherGuard is ready to run.")
        print("\n🚀 To start the application:")
        print("   python src/main.py --dev")
        return True
    else:
        print("❌ Some tests failed. Please fix the issues before running.")
        print("\n🔧 Common solutions:")
        print("   • Install dependencies: pip install -r deployment/requirements.txt")
        print("   • Check Python version (3.8+ required)")
        print("   • Verify file permissions")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)