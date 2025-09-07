# src/ui/gradio_app.py
"""
Gradio interface configuration and setup.
Separated from business logic for better maintainability.
"""

import gradio as gr
import time
from typing import Dict, Any, Optional, List
from ..core.analyzer import PasswordAnalyzer
from ..security.rate_limiter import RateLimiter
from ..security.validators import InputValidator
from .themes import get_custom_theme, get_custom_css
from .components import create_analysis_interface, create_info_sections
from ..utils.logger import get_logger, log_api_request
from ..utils.config import get_config

logger = get_logger(__name__)


class GradioPasswordApp:
    @staticmethod
    def format_result_html(result: Dict[str, Any]) -> str:
        """Format the analysis result as HTML with bold labels and larger font, breach status in red, and box styling."""
        def clean(val):
            import re
            return re.sub(r"[\U0001F300-\U0001FAFF\u2600-\u27BF\u2190-\u21FF\u2300-\u23FF\u2B50-\u2B55]", "", str(val)).strip()

        html = [
            '<div style="border:2px solid #1976d2; border-radius:12px; background:rgba(25,118,210,0.07); padding:22px 18px 18px 18px; margin:18px 0; font-size:1.15em; line-height:1.7; box-shadow:0 2px 12px rgba(25,118,210,0.08);">'
        ]
        for key, value in result.items():
            if key == "Advanced Metrics" and isinstance(value, dict):
                html.append(f"<b>{clean(key)}:</b><br>")
                for k, v in value.items():
                    html.append(f"&nbsp;&nbsp;<b>{clean(k)}:</b> {clean(v)}<br>")
                continue
            if key == "Breach Status" and isinstance(value, str) and value.startswith("BREACHED!"):
                html.append(f"<b>{clean(key)}:</b> <span style='color:#e53935; font-weight:bold;'>{clean(value)}</span><br>")
            else:
                html.append(f"<b>{clean(key)}:</b> {clean(value)}<br>")
        html.append("</div>")
        return "".join(html)
    """
    Main Gradio application class that coordinates UI and business logic.
    """
    
    def __init__(self):
        """Initialize the Gradio app with all components."""
        self.config = get_config()
        
        # Initialize core components
        self.password_analyzer = PasswordAnalyzer()
        self.rate_limiter = RateLimiter()
        self.input_validator = InputValidator()
        
        # App statistics
        self.stats = {
            'total_analyses': 0,
            'successful_analyses': 0,
            'rate_limited': 0,
            'validation_errors': 0,
            'start_time': time.time()
        }
        
        logger.info("GradioPasswordApp initialized")
    
    def analyze_password_with_security(self, password: str, request: gr.Request = None) -> Dict[str, Any]:
        """
        Main analysis function with security layers applied.
        
        Args:
            password: Password to analyze
            request: Gradio request object for client identification
            
        Returns:
            Dict: Analysis results or error message
        """
        start_time = time.time()
        
        # Extract client information
        client_ip = self._get_client_ip(request)
        
        try:
            # Step 1: Input validation
            validation_result = self.input_validator.validate_password(password, client_ip)
            
            if not validation_result.is_valid:
                self.stats['validation_errors'] += 1
                logger.warning(f"Validation failed for client {client_ip[:8]}...: {validation_result.errors}")
                
                return {
                    "Validation Error": "Input validation failed",
                    "Errors": "; ".join(validation_result.errors),
                    "Warnings": "; ".join(validation_result.warnings) if validation_result.warnings else "None",
                    "Suggestions": "Please check your input and try again"
                }
            
            # Use cleaned password for analysis
            clean_password = validation_result.cleaned_value
            
            # Step 2: Rate limiting
            rate_limit_info = self.rate_limiter.is_allowed(client_ip)
            
            if not rate_limit_info.allowed:
                self.stats['rate_limited'] += 1
                logger.warning(f"Rate limit exceeded for client {client_ip[:8]}...")
                
                return {
                    "Rate Limited": "Too many requests",
                    "Requests Made": f"{rate_limit_info.requests_made}/{self.rate_limiter.max_requests}",
                    "Window": f"{self.rate_limiter.window_seconds} seconds",
                    "Retry After": f"{rate_limit_info.retry_after} seconds" if rate_limit_info.retry_after else "Soon",
                    "Message": "Please wait a moment before analyzing another password"
                }
            
            # Step 3: Password analysis
            analysis_result = self.password_analyzer.analyze(clean_password, client_ip)
            
            # Step 4: Format results for UI
            formatted_result = self._format_analysis_result(analysis_result, validation_result)
            
            # Update statistics
            self.stats['total_analyses'] += 1
            self.stats['successful_analyses'] += 1
            
            # Log successful request
            duration_ms = (time.time() - start_time) * 1000
            log_api_request("password_analysis", client_ip, "success", duration_ms)
            
            return self.format_result_html(formatted_result)
            
        except Exception as e:
            # Handle unexpected errors gracefully
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Analysis error for client {client_ip[:8]}...: {e}")
            log_api_request("password_analysis", client_ip, "error", duration_ms)
            
            self.stats['total_analyses'] += 1
            
            return {
                "System Error": "An unexpected error occurred",
                "Error ID": str(hash(str(e)))[:8],  # Short error ID for support
                "Message": "Please try again. If the problem persists, contact support.",
                "Suggestion": "Try with a different password or check your internet connection"
            }
    
    def _get_client_ip(self, request: gr.Request) -> str:
        """Extract client IP from Gradio request."""
        if request and hasattr(request, 'client') and request.client:
            return request.client.host
        return "127.0.0.1"  # Fallback for local development
    
    def _format_analysis_result(self, analysis_result, validation_result) -> Dict[str, Any]:
        """
        Format analysis results for Gradio JSON output.
        
        Args:
            analysis_result: PasswordAnalysisResult from analyzer
            validation_result: ValidationResult from validator
            
        Returns:
            Dict: Formatted results for UI display
        """
        # Main analysis results
        formatted = {
            "Overall Strength": analysis_result.overall_strength,
            "Security Score": f"{analysis_result.score}/100",
            "Length Analysis": analysis_result.length_analysis,
            "Character Variety": analysis_result.character_variety,
            "Entropy Level": f"{analysis_result.entropy:.1f} bits ({analysis_result.entropy_category})",
            "Breach Status": analysis_result.breach_status,
            "Strength Meter": analysis_result.strength_meter
        }
        
        # Security issues and recommendations
        if analysis_result.security_issues:
            formatted["Security Issues"] = "; ".join(analysis_result.security_issues)
        else:
            formatted["Security Issues"] = "No significant issues detected"

        if analysis_result.recommendations:
            # Show top 3 recommendations to avoid overwhelming the user
            top_recommendations = analysis_result.recommendations[:3]
            formatted["Recommendations"] = "; ".join(top_recommendations)
            
            if len(analysis_result.recommendations) > 3:
                formatted["Additional Tips"] = f"+{len(analysis_result.recommendations) - 3} more suggestions available"

        # Advanced metrics (for power users)
        if self.config.debug:
            formatted["Advanced Metrics"] = {
                "Pattern Score": f"{analysis_result.pattern_score}/100",
                "Analysis Time": f"{analysis_result.analysis_time_ms:.1f}ms",
                "Breach Count": analysis_result.breach_count if analysis_result.breach_count > 0 else "None"
            }

        # Validation info (if there were warnings)
        if validation_result.warnings:
            formatted["Input Notes"] = "; ".join(validation_result.warnings)

        return formatted
    
    def get_app_statistics(self) -> Dict[str, Any]:
        """Get application usage statistics."""
        uptime_hours = (time.time() - self.stats['start_time']) / 3600
        
        rate_limiter_stats = self.rate_limiter.get_stats()
        
        return {
            "Application Stats": {
                "Uptime": f"{uptime_hours:.1f} hours",
                "Total Analyses": self.stats['total_analyses'],
                "Successful": self.stats['successful_analyses'],
                "Rate Limited": self.stats['rate_limited'],
                "Validation Errors": self.stats['validation_errors'],
                "Success Rate": f"{(self.stats['successful_analyses'] / max(1, self.stats['total_analyses']) * 100):.1f}%"
            },
            "Rate Limiter": rate_limiter_stats['statistics'],
            "Security": {
                "Active Clients": rate_limiter_stats['current_state']['tracked_clients'],
                "Blocked Clients": rate_limiter_stats['current_state']['blocked_clients']
            }
        }


def create_password_analyzer_interface() -> gr.Blocks:
    """
    Create the main Gradio interface for password analysis.
    
    Returns:
        gr.Blocks: Configured Gradio interface
    """
    
    # Initialize the app
    app = GradioPasswordApp()
    config = get_config()
    
    # Create the interface
    with gr.Blocks(
        title=config.app_title,
        theme=get_custom_theme(),
        css=get_custom_css(),
        analytics_enabled=config.enable_analytics
    ) as interface:
        # Header section
        gr.Markdown(
            """
            <div style='text-align:center; margin-bottom: 0.5em;'>
                <span style='font-size:2.5em; font-weight:700; letter-spacing:1px;'>Cipher Guard</span><br>
                <span style='font-size:1.35em; color:#2196f3; font-weight:500;'>Advanced Password Security Analyser</span>
            </div>
            """,
            elem_id="cipherguard-header"
        )

        # Main interface components
        password_input, analyze_button, results_output = create_analysis_interface()

        # Example passwords section (if enabled in config)
        if config.enable_examples:
            with gr.Row():
                gr.Examples(
                    examples=[
                        ["password123"],           # Weak - common word + numbers
                        ["qwerty12345"],          # Weak - keyboard pattern
                        ["Password1!"],           # Fair - basic requirements met
                        ["MyS3cur3P@ssw0rd!"],    # Good - length + variety + no breaches
                        ["correct horse battery staple"],  # Good - passphrase approach
                        ["Tr0ub4dor&3"],          # Strong - XKCD reference, good entropy
                        ["X9#mK$pL2@vR8qW"],      # Very strong - high entropy, random
                        [""],                     # Empty - validation test
                    ],
                    inputs=password_input,
                    label="Try these example passwords:"
                )
        # Features section (moved below examples)
        gr.Markdown(
            """
            <div style='margin-bottom: 1.2em;'>
                <b style='color:#bbdefb; font-size:1.45em;'>Features:</b><br>
                <ul style='text-align:left; display:inline-block; margin:0 auto; font-size:1.05em;'>
                    <li>Shannon Entropy Calculation: Mathematical measure of password randomness</li>
                    <li>Pattern Weakness Detection: Identifies common vulnerable patterns</li>
                    <li>Breach Database Check: Secure k-anonymity check against 600M+ breached passwords</li>
                    <li>Real-time Analysis: Instant feedback with detailed recommendations</li>
                    <li>Enterprise Security: Rate limiting, input validation, and secure processing</li>
                </ul>
            </div>
            """
        )

        # Information sections
        info_sections = create_info_sections()

        with gr.Accordion("How CipherGuard Works", open=False):
            gr.Markdown("""
            ### Analysis Components:

            **Entropy Calculation**
            - Uses Shannon entropy formula: `H = -Σ(p(x) × log₂(p(x)))`
            - Measures actual randomness vs theoretical maximum
            - Accounts for character set size and distribution
            - Applies penalties for predictable patterns
            
            **Pattern Detection**
            - Dictionary words and common passwords
            - Keyboard walking patterns (qwerty, 123456)
            - Sequential characters and repetition
            - Date patterns and personal information
            - Substitution patterns (P@ssw0rd → Password)
            
            **Breach Detection**
            - Checks against 600+ million compromised passwords
            - Uses k-anonymity for privacy protection
            - Only sends first 5 characters of password hash
            - Your password never leaves your device in full
            
            **Scoring Algorithm**
            - **Length (25%)**: 12+ characters recommended
            - **Variety (25%)**: Mix of uppercase, lowercase, numbers, symbols
            - **Entropy (25%)**: Mathematical randomness measure
            - **Patterns (25%)**: Absence of predictable patterns
            - **Breach Penalty**: -30 points if password found in breaches
            """)

        with gr.Accordion("Security & Privacy", open=False):
            gr.Markdown("""
            ### Your Privacy is Protected:

            **Zero Storage Policy**
            - Passwords are never saved to disk or logs
            - Analysis happens in memory and data is immediately cleared
            - No tracking or retention of password data
            
            **k-Anonymity Breach Checking**
            - Only partial hash sent to Have I Been Pwned API
            - Your full password hash never transmitted
            - Impossible for external service to reconstruct password
            
            **Security Measures**
            - Rate limiting prevents abuse (20 requests per minute)
            - Input validation blocks injection attempts
            - HTTPS encryption for all communications
            - Memory cleared after each analysis
            
            ### Fair Usage:
            - **Rate Limit**: 20 password analyses per minute per IP
            - **Length Limit**: Maximum 128 characters per password
            - **Batch Processing**: Contact us for enterprise needs
            """)

        with gr.Accordion("Password Best Practices", open=False):
            gr.Markdown("""
            ### Creating Strong Passwords:

            **Do This:**
            - Use 12+ characters (16+ is even better)
            - Mix uppercase, lowercase, numbers, and symbols
            - Use unique passwords for every account
            - Consider passphrases: "correct horse battery staple"
            - Use a password manager for convenience
            
            **Avoid This:**
            - Dictionary words or common phrases
            - Personal information (names, dates, addresses)
            - Keyboard patterns (qwerty, 123456, asdf)
            - Simple substitutions (P@ssw0rd, Passw0rd1)
            - Recycling passwords across multiple sites
            
            **Maintenance:**
            - Change passwords if they appear in breaches
            - Update critical passwords periodically
            - Enable two-factor authentication where possible
            - Monitor accounts for unauthorized access
            """)


        # Event handlers
        analyze_button.click(
            fn=app.analyze_password_with_security,
            inputs=[password_input],
            outputs=[results_output],
            api_name="analyze_password"  # Creates /api/analyze_password endpoint
        )

        password_input.submit(
            fn=app.analyze_password_with_security,
            inputs=[password_input],
            outputs=[results_output]
        )

        # Footer with attribution and links
        gr.Markdown("""
    <div style="text-align: center; opacity: 0.7; font-size: 0.9em;">
        
    **CipherGuard** - Built with care using Python, Gradio, and security best practices  
        
    **Data Sources**: Breach data powered by [Have I Been Pwned](https://haveibeenpwned.com)  
    **Research**: Based on NIST password guidelines and entropy analysis  
    **License**: Open source implementation following security standards  
        
    *Your passwords are analyzed locally and never stored. Privacy guaranteed.*
        
    </div>
        """)
    
    logger.info("Gradio interface created successfully")
    return interface


# Example usage and testing
if __name__ == "__main__":
    from ..utils.logger import setup_logging
    
    setup_logging("INFO")
    
    # Create and launch the interface
    interface = create_password_analyzer_interface()
    
    # Launch with development settings
    interface.launch(
        server_port=7860,
        server_name="127.0.0.1",
        share=False,
        debug=True,
        show_error=True
    )