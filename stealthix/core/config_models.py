"""
Pydantic configuration models for type-safe configuration validation.

This module provides Pydantic BaseModel classes for validating configuration
across the Stealthix codebase, replacing raw dict-based configuration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings


class HttpConfigModel(BaseModel):
    """HTTP client configuration."""

    timeout: float = Field(default=10.0, ge=0.1, le=300, description="Request timeout in seconds")
    verify_tls: bool = Field(default=True, description="Verify SSL/TLS certificates")
    proxy: str | None = Field(default=None, description="HTTP proxy URL")
    headers: dict[str, str] = Field(default_factory=dict, description="Default HTTP headers")
    cookies: dict[str, str] = Field(default_factory=dict, description="Default cookies")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    max_redirects: int = Field(default=5, ge=0, le=20, description="Maximum redirect count")


class AuthConfigModel(BaseModel):
    """Authentication configuration."""

    auth_type: str | None = Field(
        default=None, description="Authentication type (bearer, basic, digest, form, ntlm, script)"
    )
    auth_user: str | None = Field(default=None, description="Username for authentication")
    auth_pass: str | None = Field(default=None, description="Password for authentication")
    auth_token: str | None = Field(default=None, description="Bearer token")
    auth_header: str | None = Field(default=None, description="Custom auth header name")
    auth_header_value: str | None = Field(default=None, description="Custom auth header value")
    auth_script: str | None = Field(default=None, description="Path to custom auth script")
    csrf_url: str | None = Field(default=None, description="CSRF token URL")
    csrf_token_param: str | None = Field(default=None, description="CSRF token parameter name")
    scheme: str = Field(default="Bearer", description="Auth scheme (Bearer, Basic, etc.)")


class CrawlConfigModel(BaseModel):
    """Crawler configuration."""

    crawl_enabled: bool = Field(default=False, description="Enable web crawling")
    crawl_depth: int = Field(default=2, ge=0, le=10, description="Maximum crawl depth")
    crawl_max_pages: int = Field(default=50, ge=1, le=1000, description="Maximum pages to crawl")
    crawl_scope: str = Field(default="host", description="Crawl scope (host, domain, subdomain)")
    parse_robots: bool = Field(default=True, description="Parse robots.txt")
    parse_sitemap: bool = Field(default=True, description="Parse sitemap.xml")


class ApiConfigModel(BaseModel):
    """API/WebSocket configuration."""

    api_schema: str | None = Field(default=None, description="Path to API schema (OpenAPI/Postman)")
    api_schema_format: str = Field(
        default="auto", description="Schema format (auto, openapi, postman)"
    )
    api_header_param: str | None = Field(default=None, description="API header parameter")
    ws_url: str | None = Field(default=None, description="WebSocket URL")
    ws_timeout: float = Field(default=10.0, ge=0.1, le=300, description="WebSocket timeout")


class SessionConfigModel(BaseModel):
    """Main session configuration model."""

    # Target configuration
    base_url: str = Field(default="", description="Target base URL")
    method: str = Field(default="GET", description="HTTP method")
    body_format: str = Field(
        default="form", description="Request body format (form, json, xml, multipart)"
    )
    data: dict[str, Any] | None = Field(default=None, description="Request body data")

    # Scan configuration
    risk: int = Field(default=1, ge=1, le=3, description="Risk level (1=low, 2=medium, 3=high)")
    level: int = Field(default=1, ge=1, le=5, description="Detection level (1=quick, 5=thorough)")
    threads: int = Field(default=5, ge=1, le=50, description="Number of threads")

    # HTTP configuration
    timeout: float = Field(default=10.0, ge=0.1, le=300, description="Request timeout")
    verify_tls: bool = Field(default=True, description="Verify SSL/TLS certificates")
    proxy: str | None = Field(default=None, description="HTTP proxy URL")
    headers: dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    cookies: dict[str, str] = Field(default_factory=dict, description="Cookies")

    # Authentication
    auth_type: str | None = Field(default=None, description="Authentication type")
    auth_user: str | None = Field(default=None, description="Username")
    auth_pass: str | None = Field(default=None, description="Password")
    auth_token: str | None = Field(default=None, description="Bearer token")
    auth_header: str | None = Field(default=None, description="Custom auth header")
    auth_header_value: str | None = Field(default=None, description="Custom auth header value")
    auth_script: str | None = Field(default=None, description="Auth script path")
    csrf_url: str | None = Field(default=None, description="CSRF token URL")
    csrf_token_param: str | None = Field(default=None, description="CSRF parameter name")
    scheme: str = Field(default="Bearer", description="Auth scheme")
    auth_config: dict[str, Any] | None = Field(default=None, description="Auth configuration dict")

    # Crawler
    crawl_enabled: bool = Field(default=False, description="Enable crawling")
    crawl_depth: int = Field(default=2, ge=0, le=10, description="Crawl depth")
    crawl_max_pages: int = Field(default=50, ge=1, le=1000, description="Max pages")
    crawl_scope: str = Field(default="host", description="Crawl scope")
    parse_robots: bool = Field(default=True, description="Parse robots.txt")
    parse_sitemap: bool = Field(default=True, description="Parse sitemap")

    # API/WebSocket
    api_schema: str | None = Field(default=None, description="API schema path")
    api_schema_format: str = Field(default="auto", description="Schema format")
    api_header_param: str | None = Field(default=None, description="API header param")
    ws_url: str | None = Field(default=None, description="WebSocket URL")
    ws_timeout: float = Field(default=10.0, ge=0.1, le=300, description="WebSocket timeout")

    # Detection
    dbms: str | None = Field(default=None, description="Target DBMS")
    custom_payloads: dict[str, list[str]] | None = Field(
        default=None, description="Custom payloads"
    )
    target_params: list[str] | None = Field(default=None, description="Target parameters")
    technique: str | None = Field(default=None, description="Detection technique")

    # Connection pooling
    pool_connections: int | None = Field(default=None, ge=1, description="Pool connections")
    pool_maxsize: int | None = Field(default=None, ge=1, description="Pool max size")

    # API/WebSocket additional fields
    api_base_url: str | None = Field(default=None, description="API base URL")
    api_header_params: list[str] | None = Field(default=None, description="API header parameters")
    ws_messages: list[str] | None = Field(default=None, description="WebSocket messages")
    ws_headers: dict[str, str] | None = Field(default=None, description="WebSocket headers")
    ws_subprotocols: list[str] | None = Field(default=None, description="WebSocket subprotocols")

    # Evasion/Tamper
    tamper_pipeline: list[str] | None = Field(default=None, description="Tamper scripts pipeline")
    tamper_auto: bool = Field(default=True, description="Auto tamper")
    tamper_retry_budget: int = Field(default=3, ge=1, description="Tamper retry budget")

    # Batch mode
    batch: bool = Field(default=False, description="Batch mode")

    # Output
    output_dir: str | None = Field(default=None, description="Output directory")

    @model_validator(mode="before")
    @classmethod
    def _remap_url_alias(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "url" in data and "base_url" not in data:
                data["base_url"] = data.pop("url")
        return data

    @property
    def url(self) -> str:
        return self.base_url

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v: str) -> str:
        """Validate base URL format."""
        if not v:
            return v  # Allow empty for WebSocket-only configs
        if not (
            v.startswith("http://")
            or v.startswith("https://")
            or v.startswith("ws://")
            or v.startswith("wss://")
        ):
            raise ValueError("base_url must start with http://, https://, ws://, or wss://")
        return v

    @field_validator("method")
    @classmethod
    def validate_method(cls, v: str) -> str:
        """Validate HTTP method."""
        valid_methods = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
        if v.upper() not in valid_methods:
            raise ValueError(f"Invalid method: {v}. Must be one of {valid_methods}")
        return v.upper()

    @field_validator("body_format")
    @classmethod
    def validate_body_format(cls, v: str) -> str:
        """Validate body format."""
        valid_formats = {"form", "json", "xml", "multipart"}
        if v.lower() not in valid_formats:
            raise ValueError(f"Invalid body_format: {v}. Must be one of {valid_formats}")
        return v.lower()

    @model_validator(mode="after")
    def validate_auth_config(self) -> SessionConfigModel:
        """Validate authentication configuration consistency."""
        # Only validate if all required fields are present (lenient for backward compatibility)
        if self.auth_type == "bearer" and self.auth_token is not None and not self.auth_token:
            raise ValueError("auth_token required when auth_type is bearer")
        if (
            self.auth_type in {"basic", "digest", "form", "ntlm"}
            and self.auth_user is not None
            and self.auth_pass is not None
            and not (self.auth_user and self.auth_pass)
        ):
            raise ValueError(f"auth_user and auth_pass required when auth_type is {self.auth_type}")
        if self.auth_type == "script" and self.auth_script is not None and not self.auth_script:
            raise ValueError("auth_script required when auth_type is script")
        return self

    @model_validator(mode="after")
    def validate_crawl_config(self) -> SessionConfigModel:
        """Validate crawler configuration."""
        if self.crawl_enabled and not self.base_url:
            raise ValueError("base_url required when crawl_enabled is True")
        return self

    model_config = ConfigDict(
        extra="ignore",  # Ignore extra fields for backward compatibility
        validate_assignment=True,
    )

    def to_dict(self) -> dict[str, Any]:
        """Backward compatibility method - use model_dump() instead."""
        return self.model_dump()

    def to_dict_redacted(self) -> dict[str, Any]:
        """Return a dict with sensitive fields redacted for logging/display."""
        result = self.model_dump()
        redacted = "***REDACTED***"
        result["auth_token"] = "***REDACTED***" if self.auth_token else None
        result["auth_pass"] = redacted if self.auth_pass else None
        result["auth_header_value"] = redacted if self.auth_header_value else None
        result["auth_config"] = self._redact_auth_config()
        result["headers"] = self._redact_mapping(self.headers)
        result["cookies"] = {str(key): redacted for key in self.cookies}
        return result

    def _redact_auth_config(self) -> dict[str, Any] | None:
        """Redact sensitive fields from auth_config."""
        if not self.auth_config:
            return None
        return self._redact_mapping(self.auth_config)

    @staticmethod
    def _redact_mapping(payload: dict[str, Any] | None) -> dict[str, Any]:
        if not payload:
            return {}
        sensitive_fragments = {
            "authorization",
            "cookie",
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "key",
            "session",
        }
        redacted: dict[str, Any] = {}
        for key, value in payload.items():
            key_text = str(key).lower()
            if value and any(fragment in key_text for fragment in sensitive_fragments):
                redacted[str(key)] = "***REDACTED***"
            elif isinstance(value, dict):
                redacted[str(key)] = SessionConfigModel._redact_mapping(value)
            else:
                redacted[str(key)] = value
        return redacted

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> SessionConfigModel:
        """Backward compatibility method - use cls(**payload) instead."""
        return cls(**payload)

    def worker_count(self) -> int:
        """Get worker count for parallel processing."""
        return max(1, int(self.threads or 1))

    def effective_pool_connections(self) -> int:
        """Get effective pool connections."""
        configured = (
            self.pool_connections if self.pool_connections is not None else self.worker_count()
        )
        return max(1, int(configured))

    def effective_pool_maxsize(self) -> int:
        """Get effective pool max size."""
        configured = self.pool_maxsize if self.pool_maxsize is not None else self.worker_count() * 2
        return max(self.effective_pool_connections(), int(configured))

    def __getitem__(self, key: str) -> Any:
        """Support dict-like access for backward compatibility."""
        return getattr(self, key)


class EnvConfig(BaseSettings):
    """Environment-based configuration."""

    stealthix_log_level: str = Field(default="INFO", alias="STEALTHIX_LOG_LEVEL")
    stealthix_log_format: str = Field(default="rich", alias="STEALTHIX_LOG_FORMAT")
    stealthix_log_file: str | None = Field(default=None, alias="STEALTHIX_LOG_FILE")
    stealthix_rate_limit_rps: float = Field(default=10.0, alias="STEALTHIX_RATE_LIMIT_RPS")
    stealthix_rate_limit_burst: int = Field(default=5, alias="STEALTHIX_RATE_LIMIT_BURST")

    model_config = ConfigDict(
        extra="ignore",
    )
