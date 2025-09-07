# src/utils/config.py
"""
Configuration management for CipherGuard.
Handles environment variables, default settings, and app configuration.
"""

import os
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from pathlib import Path


@dataclass
class Config:
    """
    Application configuration with environment variable support.
    All settings can be overridden via environment variables.
    """
    
    # Server Configuration
    server_host: str = "127.0.0.1"
    server_port: int = 7860
    max_threads: int = 40
    share: bool = False
    debug: bool = False
    
    # Rate Limiting Configuration
    rate_limit_requests: int = 20
    rate_limit_window: int = 60
    
    # HIBP API Configuration
    hibp_api_url: str = "https://api.pwnedpasswords.com/range/"
    hibp_timeout: int = 5
    hibp_user_agent: str = "CipherGuard-Password-Analyzer/1.0"
    
    # Security Settings
    enable_auth: bool = False
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    
    # SSL/TLS Configuration
    ssl_keyfile: Optional[str] = None
    ssl_certfile: Optional[str] = None
    
    # Logging Configuration
    log_level: str = "INFO"
    log_file: Optional[str] = None
    enable_file_logging: bool = True
    
    # Analysis Settings
    min_password_length: int = 1
    max_password_length: int = 128
    default_charset_sizes: Dict[str, int] = field(default_factory=lambda: {
        'lowercase': 26,
        'uppercase': 26,
        'digits': 10,
        'symbols': 32
    })
    
    # UI Settings
    app_title: str = "CipherGuard - Password Security Analyzer"
    app_description: str = "Advanced password analysis with entropy calculation and breach detection"
    enable_examples: bool = True
    enable_analytics: bool = False
    
    def __post_init__(self):
        """Load configuration from environment variables after initialization."""
        self._load_from_environment()
        self._validate_config()
    
    def _load_from_environment(self):
        """Load configuration values from environment variables."""
        
        # Server settings
        self.server_host = os.getenv("CIPHERGUARD_HOST", self.server_host)
        self.server_port = int(os.getenv("CIPHERGUARD_PORT", self.server_port))
        self.max_threads = int(os.getenv("CIPHERGUARD_MAX_THREADS", self.max_threads))
        self.share = self._get_bool_env("CIPHERGUARD_SHARE", self.share)
        self.debug = self._get_bool_env("CIPHERGUARD_DEBUG", self.debug)
        
        # Rate limiting
        self.rate_limit_requests = int(os.getenv("RATE_LIMIT_REQUESTS", self.rate_limit_requests))
        self.rate_limit_window = int(os.getenv("RATE_LIMIT_WINDOW", self.rate_limit_window))
        
        # HIBP API
        self.hibp_api_url = os.getenv("HIBP_API_URL", self.hibp_api_url)
        self.hibp_timeout = int(os.getenv("HIBP_TIMEOUT", self.hibp_timeout))
        self.hibp_user_agent = os.getenv("HIBP_USER_AGENT", self.hibp_user_agent)
        
        # Security
        self.enable_auth = self._get_bool_env("ENABLE_AUTH", self.enable_auth)
        self.auth_username = os.getenv("AUTH_USERNAME", self.auth_username)
        self.auth_password = os.getenv("AUTH_PASSWORD", self.auth_password)
        
        # SSL/TLS
        self.ssl_keyfile = os.getenv("SSL_KEYFILE", self.ssl_keyfile)
        self.ssl_certfile = os.getenv("SSL_CERTFILE", self.ssl_certfile)
        
        # Logging
        self.log_level = os.getenv("LOG_LEVEL", self.log_level).upper()
        self.log_file = os.getenv("LOG_FILE", self.log_file)
        self.enable_file_logging = self._get_bool_env("ENABLE_FILE_LOGGING", self.enable_file_logging)
        
        # Analysis
        self.min_password_length = int(os.getenv("MIN_PASSWORD_LENGTH", self.min_password_length))
        self.max_password_length = int(os.getenv("MAX_PASSWORD_LENGTH", self.max_password_length))
        
        # UI
        self.app_title = os.getenv("APP_TITLE", self.app_title)
        self.app_description = os.getenv("APP_DESCRIPTION", self.app_description)
        self.enable_examples = self._get_bool_env("ENABLE_EXAMPLES", self.enable_examples)
        self.enable_analytics = self._get_bool_env("ENABLE_ANALYTICS", self.enable_analytics)
    
    def _get_bool_env(self, key: str, default: bool) -> bool:
        """Get boolean value from environment variable."""
        value = os.getenv(key, str(default)).lower()
        return value in ('true', '1', 'yes', 'on')
    
    def _validate_config(self):
        """Validate configuration values."""
        
        # Validate port range
        if not (1 <= self.server_port <= 65535):
            raise ValueError(f"Invalid server port: {self.server_port}")
        
        # Validate rate limiting
        if self.rate_limit_requests <= 0:
            raise ValueError(f"Rate limit requests must be positive: {self.rate_limit_requests}")
        
        if self.rate_limit_window <= 0:
            raise ValueError(f"Rate limit window must be positive: {self.rate_limit_window}")
        
        # Validate password length limits
        if self.min_password_length < 0:
            raise ValueError(f"Minimum password length cannot be negative: {self.min_password_length}")
        
        if self.max_password_length <= self.min_password_length:
            raise ValueError(f"Maximum password length must be greater than minimum")
        
        # Validate log level
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.log_level not in valid_levels:
            raise ValueError(f"Invalid log level: {self.log_level}. Must be one of {valid_levels}")
        
        # Validate SSL files if provided
        if self.ssl_keyfile and not Path(self.ssl_keyfile).exists():
            raise FileNotFoundError(f"SSL key file not found: {self.ssl_keyfile}")
        
        if self.ssl_certfile and not Path(self.ssl_certfile).exists():
            raise FileNotFoundError(f"SSL certificate file not found: {self.ssl_certfile}")
        
        # Validate authentication
        if self.enable_auth and (not self.auth_username or not self.auth_password):
            raise ValueError("Authentication enabled but username/password not provided")
    
    def get_gradio_kwargs(self) -> Dict[str, Any]:
        """Get keyword arguments for Gradio launch configuration."""
        kwargs = {
            'server_name': self.server_host,
            'server_port': self.server_port,
            'share': self.share,
            'debug': self.debug,
            'show_error': True,
            'max_threads': self.max_threads,
        }
        
        # Add authentication if enabled
        if self.enable_auth:
            kwargs['auth'] = (self.auth_username, self.auth_password)
        
        # Add SSL configuration if provided
        if self.ssl_keyfile and self.ssl_certfile:
            kwargs['ssl_keyfile'] = self.ssl_keyfile
            kwargs['ssl_certfile'] = self.ssl_certfile
        
        return kwargs
    
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return os.getenv("ENVIRONMENT", "development").lower() == "production"
    
    def get_log_file_path(self) -> Optional[str]:
        """Get the log file path based on configuration."""
        if not self.enable_file_logging:
            return None
        
        if self.log_file:
            return self.log_file
        
        # Default log file location
        if self.is_production():
            return "logs/cipherguard.log"
        else:
            return None  # Console only in development
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary (excluding sensitive data)."""
        config_dict = {}
        
        for key, value in self.__dict__.items():
            # Skip sensitive information
            if 'password' in key.lower() or 'auth' in key.lower():
                config_dict[key] = "***REDACTED***" if value else None
            elif 'ssl' in key.lower() and value:
                config_dict[key] = "***FILE_PATH***"
            else:
                config_dict[key] = value
        
        return config_dict
    
    def __str__(self) -> str:
        """String representation of configuration."""
        config_dict = self.to_dict()
        lines = [f"{key}: {value}" for key, value in config_dict.items()]
        return "CipherGuard Configuration:\n" + "\n".join(f"  {line}" for line in lines)


# Global configuration instance
_config_instance: Optional[Config] = None


def get_config() -> Config:
    """
    Get the global configuration instance (singleton pattern).
    
    Returns:
        Config: Global configuration instance
    """
    global _config_instance
    
    if _config_instance is None:
        _config_instance = Config()
    
    return _config_instance


def reload_config() -> Config:
    """
    Reload configuration from environment variables.
    
    Returns:
        Config: New configuration instance
    """
    global _config_instance
    _config_instance = Config()
    return _config_instance


# Example usage and testing
if __name__ == "__main__":
    # Test configuration loading
    config = get_config()
    
    print(config)
    print(f"\nProduction mode: {config.is_production()}")
    print(f"Log file path: {config.get_log_file_path()}")
    
    # Test environment variable override
    os.environ["CIPHERGUARD_PORT"] = "8080"
    os.environ["LOG_LEVEL"] = "DEBUG"
    
    # Reload with new environment variables
    new_config = reload_config()
    print(f"\nAfter environment override:")
    print(f"Port: {new_config.server_port}")
    print(f"Log level: {new_config.log_level}")
    
    # Test Gradio configuration
    gradio_kwargs = config.get_gradio_kwargs()
    print(f"\nGradio kwargs: {gradio_kwargs}")