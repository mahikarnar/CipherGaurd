# src/main.py
"""
Main application entry point for CipherGuard.
Orchestrates the UI and core analysis components with proper configuration.
"""

import sys
import os
from pathlib import Path

# Add the project root to Python path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.ui.gradio_app import create_password_analyzer_interface
from src.utils.config import get_config
from src.utils.logger import setup_logging, get_logger

logger = get_logger(__name__)


def validate_environment():
    """
    Validate that all required components are available.
    
    Returns:
        bool: True if environment is valid
    """
    try:
        # Test imports
        from src.core.analyzer import PasswordAnalyzer
        from src.security.rate_limiter import RateLimiter
        from src.security.validators import InputValidator
        
        # Test basic functionality
        analyzer = PasswordAnalyzer()
        test_result = analyzer.analyze("test123", "startup_test")
        
        if test_result.score >= 0:  # Basic sanity check
            logger.info("Environment validation successful")
            return True
        else:
            logger.error("Environment validation failed: Invalid analysis result")
            return False
            
    except ImportError as e:
        logger.error(f"Environment validation failed: Missing import - {e}")
        return False
    except Exception as e:
        logger.error(f"Environment validation failed: {e}")
        return False


def print_startup_banner():
    """Print a nice startup banner with app info."""
    config = get_config()
    
    def box_line(text):
        # text: string to be placed between the box borders, left-aligned
        # box width is 78 chars (76 inside borders)
        return f"║{text:<76}║"

    banner_lines = [
        "╔" + "═"*76 + "╗",
        box_line(""),
        box_line("  CipherGuard - Password Security Analyzer"),
        box_line(""),
        box_line("  Advanced password analysis with entropy calculation"),
        box_line("  Pattern detection and breach checking"),
        box_line("  Privacy-preserving k-anonymity implementation"),
        box_line(""),
        box_line(f"  Server: http://{config.server_host}:{config.server_port}"),
        box_line(f"  Mode: {'Production' if config.is_production() else 'Development'}"),
        box_line(f"  Debug: {'Enabled' if config.debug else 'Disabled'}"),
        box_line(""),
        "╚" + "═"*76 + "╝",
    ]
    banner = "\n".join(banner_lines)
    
    print(banner)


def print_feature_summary():
    """Print summary of enabled features."""
    config = get_config()
    
    features = [
        ("Shannon Entropy Analysis", "Yes"),
        ("Pattern Detection", "Yes"),
        ("Breach Database Check", "Yes"),
        ("Rate Limiting", f"Yes ({config.rate_limit_requests}/min)"),
        ("Input Validation", "Yes"),
        ("Usage Analytics", "Yes" if config.enable_analytics else "No"),
        ("Example Passwords", "Yes" if config.enable_examples else "No"),
        ("Authentication", "Yes" if config.enable_auth else "No"),
        ("HTTPS/SSL", "Yes" if config.ssl_keyfile and config.ssl_certfile else "No"),
    ]
    
    print("\nFeature Status:")
    print("=" * 50)
    for feature, status in features:
        print(f"   {feature}: {status}")
    print()


def main():
    """Main application entry point with proper error handling."""
    
    try:
        # Initialize configuration first
        config = get_config()
        
        # Setup logging with configured level
        setup_logging(
            level=config.log_level,
            log_file=config.get_log_file_path()
        )
        
        logger.info("=" * 60)
        logger.info("CipherGuard Password Security Analyzer starting up...")
        logger.info("=" * 60)
        
        # Print startup information
        print_startup_banner()
        
        # Validate environment
        if not validate_environment():
            logger.error("Environment validation failed. Please check your setup.")
            sys.exit(1)
        
        # Print feature summary
        print_feature_summary()
        
        # Create and configure the Gradio interface
        logger.info("Creating Gradio interface...")
        interface = create_password_analyzer_interface()
        
        # Get launch configuration from config
        launch_kwargs = config.get_gradio_kwargs()
        
        logger.info(f"Launching server on {config.server_host}:{config.server_port}")
        logger.info(f"Configuration: {launch_kwargs}")
        
        # Launch the application
        interface.launch(**launch_kwargs)
        
    except KeyboardInterrupt:
        logger.info("Application stopped by user (Ctrl+C)")
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        logger.error("Stack trace:", exc_info=True)
        
        print(f"\nError: Failed to start CipherGuard")
        print(f"   Reason: {e}")
        print(f"   Check the logs for more details.")
        
        sys.exit(1)


def cli_analyze(password: str, verbose: bool = False) -> None:
    """
    Command-line interface for password analysis.
    
    Args:
        password: Password to analyze
        verbose: Show detailed analysis
    """
    from src.core.analyzer import PasswordAnalyzer
    
    analyzer = PasswordAnalyzer()
    result = analyzer.analyze(password, "cli_user")
    
    print(f"\nCipherGuard Analysis Results:")
    print("=" * 40)
    print(f"Overall Strength: {result.overall_strength}")
    print(f"Security Score: {result.score}/100")
    print(f"Length: {len(password)} characters")
    print(f"Entropy: {result.entropy:.1f} bits")
    print(f"Breach Status: {result.breach_status}")
    
    if result.security_issues:
        print(f"\nIssues Found:")
        for issue in result.security_issues[:5]:  # Show top 5
            print(f"  - {issue}")
    
    if result.recommendations:
        print(f"\nRecommendations:")
        for rec in result.recommendations[:3]:  # Show top 3
            print(f"  - {rec}")
    
    if verbose:
        print(f"\nDetailed Metrics:")
        print(f"  Pattern Score: {result.pattern_score}/100")
        print(f"  Analysis Time: {result.analysis_time_ms:.1f}ms")
        print(f"  Character Variety: {result.character_variety}")
        print(f"  Length Analysis: {result.length_analysis}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CipherGuard Password Security Analyzer")
    
    # Add command line options
    parser.add_argument(
        "--analyze",
        type=str,
        help="Analyze a single password from command line"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed analysis results"
    )
    
    parser.add_argument(
        "--config-check",
        action="store_true", 
        help="Check configuration and exit"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        help="Override server port"
    )
    
    parser.add_argument(
        "--host",
        type=str,
        help="Override server host"
    )
    
    args = parser.parse_args()
    
    # Handle command line analysis
    if args.analyze:
        setup_logging("INFO")
        cli_analyze(args.analyze, args.verbose)
        sys.exit(0)
    
    # Handle configuration check
    if args.config_check:
        setup_logging("INFO")
        config = get_config()
        print("✅ Configuration loaded successfully:")
        print(config)
        sys.exit(0)
    
    # Override configuration if specified
    if args.port:
        os.environ["CIPHERGUARD_PORT"] = str(args.port)
    
    if args.host:
        os.environ["CIPHERGUARD_HOST"] = args.host
    
    # Launch the main application
    main()