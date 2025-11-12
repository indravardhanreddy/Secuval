"""
SecureAPIs Python Bindings

High-performance security middleware for Python applications.
"""

import os
import json
import ctypes
from ctypes import c_char_p, c_int, c_void_p, Structure, POINTER
from typing import Dict, Optional, Any


class SecureAPIsException(Exception):
    """Exception raised by SecureAPIs operations"""
    pass


class SecurityCheckResult(Structure):
    """Result structure for security checks"""
    _fields_ = [
        ("allowed", c_int),
        ("status_code", c_int),
        ("error_message", c_char_p),
        ("headers_json", c_char_p),
    ]


"""
SecureAPIs Python Bindings

High-performance security middleware for Python applications.
"""

import os
import json
import ctypes
from ctypes import c_char_p, c_int, c_void_p, Structure, POINTER
from typing import Dict, Optional, Any, List, Union


class SecureAPIsException(Exception):
    """Exception raised by SecureAPIs operations"""
    pass


class SecurityCheckResult(Structure):
    """Result structure for security checks"""
    _fields_ = [
        ("allowed", c_int),
        ("status_code", c_int),
        ("error_message", c_char_p),
        ("headers_json", c_char_p),
    ]


class SecureAPIsConfig:
    """Configuration for SecureAPIs with support for JSON files and environment variables"""

    def __init__(self):
        # Rate limiting
        self.rate_limit_requests_per_minute = 60
        self.enable_rate_limiting = True

        # Input validation
        self.enable_xss_protection = True
        self.enable_sql_injection_protection = True
        self.enable_input_validation = True
        self.enable_command_injection_protection = True
        self.enable_path_traversal_protection = True
        self.max_request_size_kb = 1024
        self.max_url_length = 2048

        # CSRF protection
        self.enable_csrf_protection = True

        # Authentication
        self.jwt_secret: Optional[str] = None
        self.jwt_issuer: Optional[str] = None
        self.jwt_audience: Optional[str] = None
        self.enable_jwt_validation = False
        self.api_keys: List[str] = []

        # CORS
        self.enable_cors = False
        self.allowed_origins: List[str] = []
        self.allowed_methods: List[str] = []
        self.allowed_headers: List[str] = []

        # Security headers
        self.enable_security_headers = True
        self.enable_hsts = True
        self.enable_csp = False
        self.csp_policy: Optional[str] = None

        # Threat detection
        self.enable_threat_detection = True
        self.blocked_ips: List[str] = []
        self.blocked_user_agents: List[str] = []
        self.max_requests_per_minute = 60

        # Logging & monitoring
        self.enable_logging = True
        self.log_level = "Info"
        self.enable_metrics = True

        # Advanced settings
        self.strict_mode = False
        self.request_timeout_seconds = 30
        self.enable_ip_reputation = False

    @classmethod
    def from_json_file(cls, file_path: str) -> 'SecureAPIsConfig':
        """Load configuration from a JSON file"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Configuration file not found: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        config = cls()
        config._load_from_dict(data)
        return config

    @classmethod
    def from_env(cls) -> 'SecureAPIsConfig':
        """Load configuration from environment variables"""
        config = cls()

        # Rate limiting
        config.rate_limit_requests_per_minute = cls._get_env_int("SECUREAPIS_RATE_LIMIT_REQUESTS", config.rate_limit_requests_per_minute)
        config.enable_rate_limiting = cls._get_env_bool("SECUREAPIS_ENABLE_RATE_LIMITING", config.enable_rate_limiting)

        # Authentication
        config.jwt_secret = cls._get_env_str("SECUREAPIS_JWT_SECRET", config.jwt_secret)
        config.jwt_issuer = cls._get_env_str("SECUREAPIS_JWT_ISSUER", config.jwt_issuer)
        config.jwt_audience = cls._get_env_str("SECUREAPIS_JWT_AUDIENCE", config.jwt_audience)
        config.enable_jwt_validation = cls._get_env_bool("SECUREAPIS_ENABLE_JWT_VALIDATION", config.enable_jwt_validation)
        config.api_keys = cls._get_env_str_list("SECUREAPIS_API_KEYS", config.api_keys)

        # Input validation
        config.enable_input_validation = cls._get_env_bool("SECUREAPIS_ENABLE_INPUT_VALIDATION", config.enable_input_validation)
        config.enable_sql_injection_protection = cls._get_env_bool("SECUREAPIS_ENABLE_SQL_INJECTION_PROTECTION", config.enable_sql_injection_protection)
        config.enable_xss_protection = cls._get_env_bool("SECUREAPIS_ENABLE_XSS_PROTECTION", config.enable_xss_protection)
        config.enable_command_injection_protection = cls._get_env_bool("SECUREAPIS_ENABLE_COMMAND_INJECTION_PROTECTION", config.enable_command_injection_protection)
        config.enable_path_traversal_protection = cls._get_env_bool("SECUREAPIS_ENABLE_PATH_TRAVERSAL_PROTECTION", config.enable_path_traversal_protection)
        config.max_request_size_kb = cls._get_env_int("SECUREAPIS_MAX_REQUEST_SIZE_KB", config.max_request_size_kb)
        config.max_url_length = cls._get_env_int("SECUREAPIS_MAX_URL_LENGTH", config.max_url_length)

        # CORS
        config.enable_cors = cls._get_env_bool("SECUREAPIS_ENABLE_CORS", config.enable_cors)
        config.allowed_origins = cls._get_env_str_list("SECUREAPIS_ALLOWED_ORIGINS", config.allowed_origins)
        config.allowed_methods = cls._get_env_str_list("SECUREAPIS_ALLOWED_METHODS", config.allowed_methods)
        config.allowed_headers = cls._get_env_str_list("SECUREAPIS_ALLOWED_HEADERS", config.allowed_headers)

        # Security headers
        config.enable_security_headers = cls._get_env_bool("SECUREAPIS_ENABLE_SECURITY_HEADERS", config.enable_security_headers)
        config.enable_hsts = cls._get_env_bool("SECUREAPIS_ENABLE_HSTS", config.enable_hsts)
        config.enable_csp = cls._get_env_bool("SECUREAPIS_ENABLE_CSP", config.enable_csp)
        config.csp_policy = cls._get_env_str("SECUREAPIS_CSP_POLICY", config.csp_policy)

        # Threat detection
        config.enable_threat_detection = cls._get_env_bool("SECUREAPIS_ENABLE_THREAT_DETECTION", config.enable_threat_detection)
        config.blocked_ips = cls._get_env_str_list("SECUREAPIS_BLOCKED_IPS", config.blocked_ips)
        config.blocked_user_agents = cls._get_env_str_list("SECUREAPIS_BLOCKED_USER_AGENTS", config.blocked_user_agents)
        config.max_requests_per_minute = cls._get_env_int("SECUREAPIS_MAX_REQUESTS_PER_MINUTE", config.max_requests_per_minute)

        # Logging & monitoring
        config.enable_logging = cls._get_env_bool("SECUREAPIS_ENABLE_LOGGING", config.enable_logging)
        config.log_level = cls._get_env_str("SECUREAPIS_LOG_LEVEL", config.log_level) or config.log_level
        config.enable_metrics = cls._get_env_bool("SECUREAPIS_ENABLE_METRICS", config.enable_metrics)

        # Advanced
        config.strict_mode = cls._get_env_bool("SECUREAPIS_STRICT_MODE", config.strict_mode)
        config.request_timeout_seconds = cls._get_env_int("SECUREAPIS_REQUEST_TIMEOUT_SECONDS", config.request_timeout_seconds)
        config.enable_ip_reputation = cls._get_env_bool("SECUREAPIS_ENABLE_IP_REPUTATION", config.enable_ip_reputation)

        return config

    @classmethod
    def load(cls, json_file_path: Optional[str] = None) -> 'SecureAPIsConfig':
        """Load configuration with fallback: JSON file -> Environment -> Defaults"""
        config = cls()

        # Try JSON file first
        if json_file_path and os.path.exists(json_file_path):
            try:
                config = cls.from_json_file(json_file_path)
            except (FileNotFoundError, json.JSONDecodeError, KeyError):
                config = cls()  # Fall back to defaults

        # Override with environment variables
        env_config = cls.from_env()
        config._merge_from(env_config)

        return config

    def _load_from_dict(self, data: Dict[str, Any]) -> None:
        """Load configuration from a dictionary"""
        # Rate limiting
        if 'rateLimitRequests' in data:
            self.rate_limit_requests_per_minute = data['rateLimitRequests']
        if 'rateLimitWindowSeconds' in data:
            # Convert to requests per minute
            self.rate_limit_requests_per_minute = data['rateLimitRequests'] * (60 // data['rateLimitWindowSeconds'])
        if 'enableRateLimiting' in data:
            self.enable_rate_limiting = data['enableRateLimiting']

        # Authentication
        if 'jwtSecret' in data:
            self.jwt_secret = data['jwtSecret']
        if 'jwtIssuer' in data:
            self.jwt_issuer = data['jwtIssuer']
        if 'jwtAudience' in data:
            self.jwt_audience = data['jwtAudience']
        if 'enableJwtValidation' in data:
            self.enable_jwt_validation = data['enableJwtValidation']
        if 'apiKeys' in data:
            self.api_keys = data['apiKeys']

        # Input validation
        if 'enableInputValidation' in data:
            self.enable_input_validation = data['enableInputValidation']
        if 'enableSqlInjectionDetection' in data:
            self.enable_sql_injection_protection = data['enableSqlInjectionDetection']
        if 'enableXssDetection' in data:
            self.enable_xss_protection = data['enableXssDetection']
        if 'enableCommandInjectionDetection' in data:
            self.enable_command_injection_protection = data['enableCommandInjectionDetection']
        if 'enablePathTraversalDetection' in data:
            self.enable_path_traversal_protection = data['enablePathTraversalDetection']
        if 'maxRequestBodySize' in data:
            self.max_request_size_kb = data['maxRequestBodySize'] // 1024  # Convert bytes to KB
        if 'maxUrlLength' in data:
            self.max_url_length = data['maxUrlLength']

        # CORS
        if 'enableCors' in data:
            self.enable_cors = data['enableCors']
        if 'allowedOrigins' in data:
            self.allowed_origins = data['allowedOrigins']
        if 'allowedMethods' in data:
            self.allowed_methods = data['allowedMethods']
        if 'allowedHeaders' in data:
            self.allowed_headers = data['allowedHeaders']

        # Security headers
        if 'enableSecurityHeaders' in data:
            self.enable_security_headers = data['enableSecurityHeaders']
        if 'enableHsts' in data:
            self.enable_hsts = data['enableHsts']
        if 'enableCsp' in data:
            self.enable_csp = data['enableCsp']
        if 'cspPolicy' in data:
            self.csp_policy = data['cspPolicy']

        # Threat detection
        if 'enableThreatDetection' in data:
            self.enable_threat_detection = data['enableThreatDetection']
        if 'blockedIPs' in data:
            self.blocked_ips = data['blockedIPs']
        if 'blockedUserAgents' in data:
            self.blocked_user_agents = data['blockedUserAgents']
        if 'maxRequestsPerMinute' in data:
            self.max_requests_per_minute = data['maxRequestsPerMinute']

        # Logging & monitoring
        if 'enableLogging' in data:
            self.enable_logging = data['enableLogging']
        if 'logLevel' in data:
            self.log_level = data['logLevel']
        if 'enableMetrics' in data:
            self.enable_metrics = data['enableMetrics']

        # Advanced
        if 'strictMode' in data:
            self.strict_mode = data['strictMode']
        if 'requestTimeoutSeconds' in data:
            self.request_timeout_seconds = data['requestTimeoutSeconds']
        if 'enableIpReputation' in data:
            self.enable_ip_reputation = data['enableIpReputation']

    def _merge_from(self, other: 'SecureAPIsConfig') -> None:
        """Merge configuration from another config instance"""
        # Rate limiting
        if other.enable_rate_limiting != True:
            self.enable_rate_limiting = other.enable_rate_limiting
        if other.rate_limit_requests_per_minute != 60:
            self.rate_limit_requests_per_minute = other.rate_limit_requests_per_minute

        # Authentication
        if other.jwt_secret is not None:
            self.jwt_secret = other.jwt_secret
        if other.jwt_issuer is not None:
            self.jwt_issuer = other.jwt_issuer
        if other.jwt_audience is not None:
            self.jwt_audience = other.jwt_audience
        if other.enable_jwt_validation != False:
            self.enable_jwt_validation = other.enable_jwt_validation
        if other.api_keys:
            self.api_keys = other.api_keys

        # Input validation
        if other.enable_input_validation != True:
            self.enable_input_validation = other.enable_input_validation
        if other.enable_sql_injection_protection != True:
            self.enable_sql_injection_protection = other.enable_sql_injection_protection
        if other.enable_xss_protection != True:
            self.enable_xss_protection = other.enable_xss_protection
        if other.enable_command_injection_protection != True:
            self.enable_command_injection_protection = other.enable_command_injection_protection
        if other.enable_path_traversal_protection != True:
            self.enable_path_traversal_protection = other.enable_path_traversal_protection
        if other.max_request_size_kb != 1024:
            self.max_request_size_kb = other.max_request_size_kb
        if other.max_url_length != 2048:
            self.max_url_length = other.max_url_length

        # CORS
        if other.enable_cors != False:
            self.enable_cors = other.enable_cors
        if other.allowed_origins:
            self.allowed_origins = other.allowed_origins
        if other.allowed_methods:
            self.allowed_methods = other.allowed_methods
        if other.allowed_headers:
            self.allowed_headers = other.allowed_headers

        # Security headers
        if other.enable_security_headers != True:
            self.enable_security_headers = other.enable_security_headers
        if other.enable_hsts != True:
            self.enable_hsts = other.enable_hsts
        if other.enable_csp != False:
            self.enable_csp = other.enable_csp
        if other.csp_policy is not None:
            self.csp_policy = other.csp_policy

        # Threat detection
        if other.enable_threat_detection != True:
            self.enable_threat_detection = other.enable_threat_detection
        if other.blocked_ips:
            self.blocked_ips = other.blocked_ips
        if other.blocked_user_agents:
            self.blocked_user_agents = other.blocked_user_agents
        if other.max_requests_per_minute != 60:
            self.max_requests_per_minute = other.max_requests_per_minute

        # Logging & monitoring
        if other.enable_logging != True:
            self.enable_logging = other.enable_logging
        if other.log_level != "Info":
            self.log_level = other.log_level
        if other.enable_metrics != True:
            self.enable_metrics = other.enable_metrics

        # Advanced
        if other.strict_mode != False:
            self.strict_mode = other.strict_mode
        if other.request_timeout_seconds != 30:
            self.request_timeout_seconds = other.request_timeout_seconds
        if other.enable_ip_reputation != False:
            self.enable_ip_reputation = other.enable_ip_reputation

    @staticmethod
    def _get_env_int(key: str, default: int) -> int:
        """Get integer value from environment variable"""
        value = os.getenv(key)
        if value is not None:
            try:
                return int(value)
            except ValueError:
                pass
        return default

    @staticmethod
    def _get_env_bool(key: str, default: bool) -> bool:
        """Get boolean value from environment variable"""
        value = os.getenv(key)
        if value is not None:
            return value.lower() in ('true', '1', 'yes', 'on')
        return default

    @staticmethod
    def _get_env_str(key: str, default: Optional[str]) -> Optional[str]:
        """Get string value from environment variable"""
        return os.getenv(key, default)

    @staticmethod
    def _get_env_str_list(key: str, default: List[str]) -> List[str]:
        """Get list of strings from environment variable"""
        value = os.getenv(key)
        if value:
            return [item.strip() for item in value.split(',') if item.strip()]
        return default

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary matching Rust SecurityConfig"""
        return {
            "rate_limit": {
                "enabled": self.enable_rate_limiting,
                "requests_per_window": self.rate_limit_requests_per_minute,
                "window_duration": {"secs": 60, "nanos": 0},
                "burst_size": 10,
                "per_ip": True,
                "per_user": False,
                "adaptive": False,
            },
            "validation": {
                "enabled": self.enable_input_validation,
                "sql_injection_check": self.enable_sql_injection_protection,
                "xss_check": self.enable_xss_protection,
                "command_injection_check": self.enable_command_injection_protection,
                "path_traversal_check": self.enable_path_traversal_protection,
                "sanitize_input": True,
                "max_payload_size": self.max_request_size_kb * 1024,
                "max_header_size": 8192,
            },
            "auth": {
                "enabled": self.enable_jwt_validation,
                "require_auth": self.enable_jwt_validation,
                "jwt_secret": self.jwt_secret,
                "jwt_issuer": self.jwt_issuer,
                "jwt_audience": self.jwt_audience,
                "api_keys": self.api_keys,
                "token_expiry": {"secs": 3600, "nanos": 0},
                "refresh_enabled": False,
                "mfa_enabled": False,
            },
            "monitoring": {
                "enabled": self.enable_logging,
                "log_requests": False,
                "log_responses": False,
                "log_security_events": True,
                "metrics_enabled": self.enable_metrics,
                "trace_sampling_rate": 0.0,
            },
            "threat_detection": {
                "enabled": self.enable_threat_detection,
                "anomaly_detection": False,
                "bot_detection": True,
                "known_patterns": True,
                "block_suspicious": True,
                "blocked_ips": self.blocked_ips,
                "blocked_user_agents": self.blocked_user_agents,
                "max_requests_per_minute": self.max_requests_per_minute,
            },
            "https": {
                "enabled": False,
                "require_https": False,
                "hsts_max_age": 31536000,
                "hsts_include_subdomains": True,
                "hsts_enabled": self.enable_hsts,
            },
            "cors": {
                "enabled": self.enable_cors,
                "allow_origins": self.allowed_origins,
                "allow_all_origins": len(self.allowed_origins) == 0 or "*" in self.allowed_origins,
                "allow_methods": self.allowed_methods if self.allowed_methods else ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
                "allow_headers": self.allowed_headers if self.allowed_headers else ["Content-Type", "Authorization"],
                "allow_credentials": False,
                "max_age": 86400,
            },
            "csrf": {
                "enabled": self.enable_csrf_protection,
                "token_length": 32,
                "header_name": "X-CSRF-Token",
                "param_name": "_csrf",
            },
            "content_type": {
                "enabled": True,
                "allowed_types": [
                    "application/json",
                    "application/x-www-form-urlencoded",
                    "multipart/form-data",
                    "text/plain",
                ],
                "strict_mode": self.strict_mode,
            },
        }


class SecurityResult:
    """Result of a security check operation"""

    def __init__(self, allowed: bool, status_code: int,
                 error_message: Optional[str], headers_json: Optional[str]):
        self.allowed = allowed
        self.blocked = not allowed  # Add blocked property for compatibility
        self.status_code = status_code
        self.error_message = error_message
        self.reason = error_message  # Alias for backward compatibility
        self.headers_json = headers_json


class SecureAPIs:
    """Main SecureAPIs class"""

    def __init__(self, config: SecureAPIsConfig):
        # Load the native library
        lib_path = self._find_library()
        if lib_path:
            self._lib = ctypes.CDLL(lib_path)
        else:
            raise RuntimeError("Could not find SecureAPIs native library")

        # Configure function signatures
        self._lib.secureapis_create_config.argtypes = [c_char_p]
        self._lib.secureapis_create_config.restype = c_void_p

        self._lib.secureapis_free_security_layer.argtypes = [c_void_p]
        self._lib.secureapis_free_security_layer.restype = None

        self._lib.secureapis_check_request.argtypes = [
            c_void_p, c_char_p, c_char_p, c_char_p, c_char_p, c_char_p
        ]
        self._lib.secureapis_check_request.restype = c_void_p  # Returns SecurityCheckResult*

        self._lib.secureapis_free_result.argtypes = [c_void_p]
        self._lib.secureapis_free_result.restype = None

        self._lib.secureapis_free_string.argtypes = [c_char_p]
        self._lib.secureapis_free_string.restype = None

        # Create configuration
        config_json = json.dumps(config.to_dict()).encode('utf-8')
        self._config = self._lib.secureapis_create_config(config_json)

        if not self._config:
            raise SecureAPIsException("Failed to create SecureAPIs configuration")

    def __del__(self):
        """Cleanup resources"""
        if hasattr(self, '_config') and self._config:
            self._lib.secureapis_free_security_layer(self._config)

    def check_request(self, method: str, path: str, headers: Dict[str, str],
                     body: str = "", ip_address: str = "127.0.0.1") -> SecurityResult:
        """Check if a request is allowed by security rules"""

        # Convert headers to JSON
        headers_json = json.dumps(headers).encode('utf-8')

        # Call native function
        result_ptr = self._lib.secureapis_check_request(
            self._config,
            method.encode('utf-8'),
            path.encode('utf-8'),
            headers_json,
            body.encode('utf-8'),
            ip_address.encode('utf-8')
        )

        if not result_ptr:
            raise SecureAPIsException("Security check failed")

        # Convert result to Python object
        result = ctypes.cast(result_ptr, POINTER(SecurityCheckResult)).contents

        # Extract values
        allowed = bool(result.allowed)
        status_code = result.status_code
        error_message = None
        headers_json_out = None

        if result.error_message:
            error_message = ctypes.c_char_p(result.error_message).value.decode('utf-8')

        if result.headers_json:
            headers_json_out = ctypes.c_char_p(result.headers_json).value.decode('utf-8')

        # Free the result
        self._lib.secureapis_free_result(result_ptr)

        return SecurityResult(allowed, status_code, error_message, headers_json_out)

    def _find_library(self) -> Optional[str]:
        """Find the native library file"""
        package_dir = os.path.dirname(__file__)

        # Try different library names based on platform
        if os.name == 'nt':  # Windows
            lib_names = ['secureapis.dll']
        elif os.uname().sysname == 'Darwin':  # macOS
            lib_names = ['libsecureapis.dylib']
        else:  # Linux/Unix
            lib_names = ['libsecureapis.so']

        for lib_name in lib_names:
            lib_path = os.path.join(package_dir, lib_name)
            if os.path.exists(lib_path):
                return lib_path

        return None