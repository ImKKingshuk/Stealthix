"""
Basic tests for reconnaissance module.
"""

import pytest

from stealthix.recon.models import DiscoveredEndpoint, ReconConfig, TechnologyMatch


def test_recon_config_defaults():
    """Test ReconConfig default values."""
    config = ReconConfig()
    assert config.enabled is True
    assert config.tech_enabled is True
    assert config.endpoints_enabled is True
    assert config.max_endpoints == 100
    assert config.depth == 2
    assert config.use_head_requests is True


def test_recon_config_validation():
    """Test ReconConfig validates negative values."""
    config = ReconConfig(max_endpoints=-10, depth=-5, timeout=-1.0)
    assert config.max_endpoints == 100  # Reset to default
    assert config.depth == 2  # Reset to default
    assert config.timeout is None  # Reset to None


def test_technology_match_to_dict():
    """Test TechnologyMatch serialization."""
    match = TechnologyMatch(
        category="web_server",
        name="nginx",
        version="1.21.6",
        confidence=0.95,
        evidence=[{"type": "header", "key": "Server", "value": "nginx/1.21.6"}],
    )
    data = match.to_dict()
    assert data["category"] == "web_server"
    assert data["name"] == "nginx"
    assert data["version"] == "1.21.6"
    assert data["confidence"] == 0.95
    assert len(data["evidence"]) == 1


def test_discovered_endpoint_to_dict():
    """Test DiscoveredEndpoint serialization."""
    endpoint = DiscoveredEndpoint(
        url="https://example.com/admin",
        status_code=401,
        response_size=1234,
        response_time=0.123,
        category="admin",
        confidence=0.9,
        evidence={"method": "HEAD", "requires_auth": True},
    )
    data = endpoint.to_dict()
    assert data["url"] == "https://example.com/admin"
    assert data["status_code"] == 401
    assert data["response_size"] == 1234
    assert data["category"] == "admin"
    assert data["confidence"] == 0.9
