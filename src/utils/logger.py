# src/utils/logger.py
"""
Logging configuration for CipherGuard.
Provides structured logging with different levels for development and production.
"""

import logging
import sys
from typing import Optional
from pathlib import Path


def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Setup application logging configuration.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path. If None, logs to console only.
    """
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Create handlers
    handlers = []
    
    # Console handler (always present)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(simple_formatter)
    console_handler.setLevel(logging.INFO)
    handlers.append(console_handler)
    
    # File handler (if log_file specified or in production)
    if log_file or not sys.stdout.isatty():
        log_path = Path(log_file) if log_file else Path("logs/cipherguard.log")
        log_path.parent.mkdir(exist_ok=True)
        
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(detailed_formatter)
        file_handler.setLevel(logging.DEBUG)
        handlers.append(file_handler)
    
    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        handlers=handlers,
        force=True  # Override any existing configuration
    )
    
    # Suppress verbose third-party logs
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("gradio").setLevel(logging.INFO)
    
    logger = get_logger(__name__)
    logger.info(f"Logging initialized at {level} level")
    if log_file:
        logger.info(f"Logs will be written to: {log_file}")


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Get a configured logger instance.
    
    Args:
        name: Logger name (typically __name__ from calling module)
        
    Returns:
        logging.Logger: Configured logger instance
    """
    return logging.getLogger(name or __name__)


def log_password_analysis(client_id: str, password_length: int, score: int) -> None:
    """
    Log password analysis events (without logging actual passwords).
    
    Args:
        client_id: Client identifier (IP or session)
        password_length: Length of analyzed password
        score: Analysis score (0-100)
    """
    logger = get_logger("cipherguard.analysis")
    logger.info(
        f"Password analyzed - Client: {client_id[:8]}..., "
        f"Length: {password_length}, Score: {score}"
    )


def log_security_event(event_type: str, client_id: str, details: str = "") -> None:
    """
    Log security-related events.
    
    Args:
        event_type: Type of security event (rate_limit, breach_check, etc.)
        client_id: Client identifier
        details: Additional event details
    """
    logger = get_logger("cipherguard.security")
    logger.warning(
        f"Security Event - Type: {event_type}, "
        f"Client: {client_id[:8]}..., Details: {details}"
    )


def log_api_request(endpoint: str, client_id: str, status: str, duration_ms: float) -> None:
    """
    Log API request details for monitoring.
    
    Args:
        endpoint: API endpoint called
        client_id: Client identifier
        status: Request status (success, error, rate_limited)
        duration_ms: Request duration in milliseconds
    """
    logger = get_logger("cipherguard.api")
    logger.info(
        f"API Request - Endpoint: {endpoint}, "
        f"Client: {client_id[:8]}..., Status: {status}, "
        f"Duration: {duration_ms:.2f}ms"
    )


def log_breach_check(client_id: str, is_breached: bool, api_status: str) -> None:
    """
    Log breach check events.
    
    Args:
        client_id: Client identifier
        is_breached: Whether password was found in breaches
        api_status: HIBP API response status
    """
    logger = get_logger("cipherguard.breach")
    
    if is_breached:
        logger.warning(
            f"Breach detected - Client: {client_id[:8]}..., "
            f"API Status: {api_status}"
        )
    else:
        logger.info(
            f"No breach found - Client: {client_id[:8]}..., "
            f"API Status: {api_status}"
        )


# Example usage and testing
if __name__ == "__main__":
    # Test the logging configuration
    setup_logging("DEBUG")
    
    logger = get_logger(__name__)
    
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    
    # Test specialized logging functions
    log_password_analysis("192.168.1.100", 12, 85)
    log_security_event("rate_limit", "192.168.1.100", "20 requests in 60 seconds")
    log_api_request("/analyze", "192.168.1.100", "success", 45.67)
    log_breach_check("192.168.1.100", False, "200_OK")