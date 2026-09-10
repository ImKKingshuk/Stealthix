"""Unit tests for advanced WAF evasion modules."""

from __future__ import annotations

import pytest

from stealthix.core.session import ScanSession, SessionConfig
from stealthix.evasion import behavioral, ml_bypass, polymorphic, protocol


class TestMLBypass:
    """Tests for ML bypass module."""

    def test_ml_waf_detector_initialization(self) -> None:
        """Test MLWAFDetector initialization."""
        detector = ml_bypass.MLWAFDetector()
        assert detector._ml_signature_patterns
        assert detector._ml_header_patterns

    def test_extract_features(self) -> None:
        """Test feature extraction from WAF response."""
        detector = ml_bypass.MLWAFDetector()
        response = {
            "status_code": 403,
            "response_time": 150.0,
            "content_length": 500,
            "headers": {"x-waf": "blocked"},
            "text": "Access denied by WAF",
        }
        features = detector.extract_features(response)
        assert features.status_code == 403
        assert features.response_time_ms == 150.0
        assert features.content_length == 500

    def test_extract_blocked_indicators(self) -> None:
        """Test extraction of blocked indicators."""
        detector = ml_bypass.MLWAFDetector()
        indicators = detector._extract_blocked_indicators(
            403, "Access denied by WAF", {"x-waf": "blocked"}
        )
        assert "status_403" in indicators
        assert any("body_" in ind for ind in indicators)

    def test_adversarial_heuristic_initialization(self) -> None:
        """Test AdversarialHeuristic initialization."""
        heuristic = ml_bypass.AdversarialHeuristic()
        assert heuristic._char_frequency
        assert heuristic._common_substitutions

    def test_generate_adversarial_payload(self) -> None:
        """Test adversarial payload generation."""
        heuristic = ml_bypass.AdversarialHeuristic()
        payload = "SELECT * FROM users"
        result = heuristic.generate_adversarial_payload(payload, mutation_strength=0.5)
        assert result != payload  # Should be mutated

    def test_pattern_analyzer_initialization(self) -> None:
        """Test PatternAnalyzer initialization."""
        analyzer = ml_bypass.PatternAnalyzer()
        assert analyzer._response_history == []
        assert analyzer._pattern_cache == {}

    def test_analyze_response(self) -> None:
        """Test response pattern analysis."""
        analyzer = ml_bypass.PatternAnalyzer()
        response = {
            "status_code": 200,
            "response_time": 100.0,
            "text": "Success",
        }
        analysis = analyzer.analyze_response(response)
        assert "blocked" in analysis
        assert "timing_variance" in analysis

    def test_bypass_generator_initialization(self) -> None:
        """Test BypassGenerator initialization."""
        generator = ml_bypass.BypassGenerator()
        assert generator._adversarial_heuristic
        assert generator._pattern_analyzer

    def test_generate_bypass(self) -> None:
        """Test bypass payload generation."""
        generator = ml_bypass.BypassGenerator()
        payload = "SELECT * FROM users"
        bypasses = generator.generate_bypass(None, payload)
        assert isinstance(bypasses, list)
        assert len(bypasses) > 0


class TestPolymorphic:
    """Tests for polymorphic encoding module."""

    def test_encoding_chain_initialization(self) -> None:
        """Test EncodingChain initialization."""
        chain = polymorphic.EncodingChain(operations=("space2comment", "randomcase"))
        assert chain.operations == ("space2comment", "randomcase")
        assert chain.success_count == 0
        assert chain.failure_count == 0

    def test_encoding_chain_success_rate(self) -> None:
        """Test EncodingChain success rate calculation."""
        chain = polymorphic.EncodingChain(operations=("space2comment",))
        chain.record_success()
        chain.record_success()
        chain.record_failure()
        assert chain.success_rate == 2 / 3

    def test_polymorphic_encoder_initialization(self) -> None:
        """Test PolymorphicEncoder initialization."""
        encoder = polymorphic.PolymorphicEncoder()
        assert encoder._chains == {}
        assert encoder._mutation_strategies

    def test_generate_chain(self) -> None:
        """Test encoding chain generation."""
        encoder = polymorphic.PolymorphicEncoder()
        chain = encoder.generate_chain(length=3)
        assert isinstance(chain, polymorphic.EncodingChain)
        assert len(chain.operations) == 3

    def test_mutate_chain(self) -> None:
        """Test chain mutation."""
        encoder = polymorphic.PolymorphicEncoder()
        chain = encoder.generate_chain(length=2)
        mutated = encoder.mutate_chain(chain)
        assert isinstance(mutated, polymorphic.EncodingChain)

    def test_apply_chain(self) -> None:
        """Test applying encoding chain to payload."""
        encoder = polymorphic.PolymorphicEncoder()
        chain = encoder.generate_chain(length=1)
        payload = "SELECT * FROM users"
        result = encoder.apply_chain(chain, payload)
        assert isinstance(result, str)

    def test_get_best_chain(self) -> None:
        """Test getting best chain."""
        encoder = polymorphic.PolymorphicEncoder()
        chain1 = encoder.generate_chain(length=2)
        chain1.record_success()
        chain1.record_success()
        chain1.record_failure()

        chain2 = encoder.generate_chain(length=2)
        chain2.record_success()
        chain2.record_failure()

        best = encoder.get_best_chain()
        assert best.success_rate >= 0.5

    def test_mutation_strategy_random(self) -> None:
        """Test random mutation strategy."""
        chain = polymorphic.EncodingChain(operations=("space2comment", "randomcase"))
        mutated = polymorphic.MutationStrategy.random_mutation(
            chain, ["space2comment", "randomcase", "uppercase"]
        )
        assert isinstance(mutated, polymorphic.EncodingChain)

    def test_chain_optimizer_initialization(self) -> None:
        """Test ChainOptimizer initialization."""
        optimizer = polymorphic.ChainOptimizer()
        assert optimizer._chain_performance == {}
        assert optimizer._ab_test_results == {}

    def test_record_chain_performance(self) -> None:
        """Test recording chain performance."""
        optimizer = polymorphic.ChainOptimizer()
        chain = polymorphic.EncodingChain(operations=("space2comment",))
        optimizer.record_chain_performance(chain, success=True, response_time=100.0)
        assert optimizer._chain_performance

    def test_generate_polymorphic_payload(self) -> None:
        """Test polymorphic payload generation."""
        payload = "SELECT * FROM users"
        result = polymorphic.generate_polymorphic_payload(payload, chain_length=2)
        assert isinstance(result, str)


class TestBehavioral:
    """Tests for behavioral evasion module."""

    def test_timing_profile_initialization(self) -> None:
        """Test TimingProfile initialization."""
        profile = behavioral.TimingProfile()
        assert profile.min_interval_ms == 100.0
        assert profile.max_interval_ms == 5000.0

    def test_timing_analyzer_initialization(self) -> None:
        """Test TimingAnalyzer initialization."""
        analyzer = behavioral.TimingAnalyzer()
        assert analyzer._profile
        assert analyzer._request_count == 0

    def test_analyze_baseline(self) -> None:
        """Test baseline timing analysis."""
        analyzer = behavioral.TimingAnalyzer()
        intervals = [100.0, 200.0, 300.0, 400.0]
        profile = analyzer.analyze_baseline(intervals)
        assert profile.min_interval_ms == 100.0
        assert profile.max_interval_ms == 400.0

    def test_get_next_interval(self) -> None:
        """Test getting next request interval."""
        analyzer = behavioral.TimingAnalyzer()
        interval = analyzer.get_next_interval()
        assert interval > 0
        assert interval < 10  # Should be reasonable

    def test_header_normalizer_initialization(self) -> None:
        """Test HeaderNormalizer initialization."""
        normalizer = behavioral.HeaderNormalizer()
        assert normalizer._user_agents
        assert normalizer._accept_languages

    def test_get_user_agent(self) -> None:
        """Test getting User-Agent string."""
        normalizer = behavioral.HeaderNormalizer()
        ua = normalizer.get_user_agent()
        assert isinstance(ua, str)
        assert "Mozilla" in ua

    def test_normalize_headers(self) -> None:
        """Test header normalization."""
        normalizer = behavioral.HeaderNormalizer()
        headers = {}
        normalized = normalizer.normalize_headers(headers)
        assert "user-agent" in normalized
        assert "accept-language" in normalized

    def test_is_suspicious_user_agent(self) -> None:
        """Test suspicious User-Agent detection."""
        normalizer = behavioral.HeaderNormalizer()
        assert normalizer._is_suspicious_user_agent("python-requests/2.0")
        assert not normalizer._is_suspicious_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

    def test_session_simulator_initialization(self) -> None:
        """Test SessionSimulator initialization."""
        simulator = behavioral.SessionSimulator()
        assert simulator._session_cookies == {}
        assert simulator._navigation_history == []

    def test_start_session(self) -> None:
        """Test starting a session."""
        simulator = behavioral.SessionSimulator()
        simulator.start_session("http://example.com/")
        assert simulator._navigation_history == ["http://example.com/"]

    def test_navigate_to(self) -> None:
        """Test navigation to URL."""
        simulator = behavioral.SessionSimulator()
        simulator.start_session("http://example.com/")
        # First navigation sets referer for subsequent navigations
        simulator.navigate_to("http://example.com/page1")
        headers = simulator.navigate_to("http://example.com/page2")
        assert "referer" in headers

    def test_behavioral_profile_initialization(self) -> None:
        """Test BehavioralProfile initialization."""
        profile = behavioral.BehavioralProfile()
        assert profile._baseline_requests == []
        assert profile._timing_analyzer
        assert profile._header_normalizer

    def test_generate_realistic_request(self) -> None:
        """Test generating realistic request."""
        profile = behavioral.BehavioralProfile()
        request = profile.generate_realistic_request("http://example.com/")
        assert request["url"] == "http://example.com/"
        assert "headers" in request

    def test_apply_timing_evasion(self) -> None:
        """Test applying timing evasion."""
        interval = behavioral.apply_timing_evasion(100.0, 5000.0)
        assert interval > 0

    def test_normalize_request_headers(self) -> None:
        """Test normalizing request headers."""
        headers = {}
        normalized = behavioral.normalize_request_headers(headers)
        assert "user-agent" in normalized


class TestProtocol:
    """Tests for protocol evasion module."""

    def test_smuggling_technique_initialization(self) -> None:
        """Test SmugglingTechnique initialization."""
        technique = protocol.SmugglingTechnique("CL.TE", "Description")
        assert technique.name == "CL.TE"
        assert technique.description == "Description"

    def test_request_smuggler_initialization(self) -> None:
        """Test RequestSmuggler initialization."""
        smuggler = protocol.RequestSmuggler()
        assert smuggler._techniques

    def test_apply_cl_te_smuggling(self) -> None:
        """Test CL.TE smuggling application."""
        smuggler = protocol.RequestSmuggler()
        request = "GET / HTTP/1.1"
        payload = "test"
        result = smuggler.apply_cl_te_smuggling(request, payload)
        assert "Content-Length" in result
        assert "Transfer-Encoding" in result

    def test_apply_te_cl_smuggling(self) -> None:
        """Test TE.CL smuggling application."""
        smuggler = protocol.RequestSmuggler()
        request = "GET / HTTP/1.1"
        payload = "test"
        result = smuggler.apply_te_cl_smuggling(request, payload)
        assert "Content-Length" in result

    def test_apply_te_te_smuggling(self) -> None:
        """Test TE.TE smuggling application."""
        smuggler = protocol.RequestSmuggler()
        request = "GET / HTTP/1.1"
        payload = "test"
        result = smuggler.apply_te_te_smuggling(request, payload)
        assert "Transfer-Encoding" in result

    def test_obfuscate_header(self) -> None:
        """Test header obfuscation."""
        smuggler = protocol.RequestSmuggler()
        obfuscated = smuggler.obfuscate_header("User-Agent", "Mozilla")
        assert "User-Agent" in obfuscated

    def test_request_fragmenter_initialization(self) -> None:
        """Test RequestFragmenter initialization."""
        fragmenter = protocol.RequestFragmenter()
        assert fragmenter._fragmentation_methods

    def test_fragment_chunked(self) -> None:
        """Test chunked fragmentation."""
        fragmenter = protocol.RequestFragmenter()
        request = "GET / HTTP/1.1"
        body = "test payload"
        fragments = fragmenter.fragment_chunked(request, body, chunk_size=2)
        assert isinstance(fragments, list)
        assert len(fragments) > 0

    def test_fragment_multipart(self) -> None:
        """Test multipart fragmentation."""
        fragmenter = protocol.RequestFragmenter()
        request = "GET / HTTP/1.1"
        body = "test payload"
        fragments = fragmenter.fragment_multipart(request, body, part_count=2)
        assert isinstance(fragments, list)
        assert len(fragments) == 2

    def test_fragment_headers(self) -> None:
        """Test header fragmentation."""
        fragmenter = protocol.RequestFragmenter()
        request = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test"
        fragments = fragmenter.fragment_headers(request)
        assert isinstance(fragments, list)

    def test_protocol_mutator_initialization(self) -> None:
        """Test ProtocolMutator initialization."""
        mutator = protocol.ProtocolMutator()
        assert mutator._http_methods
        assert mutator._http_versions

    def test_mutate_method(self) -> None:
        """Test HTTP method mutation."""
        mutator = protocol.ProtocolMutator()
        request = "GET / HTTP/1.1"
        mutated = mutator.mutate_method(request, "POST")
        assert "POST" in mutated

    def test_mutate_version(self) -> None:
        """Test HTTP version mutation."""
        mutator = protocol.ProtocolMutator()
        request = "GET / HTTP/1.1"
        mutated = mutator.mutate_version(request, "HTTP/2")
        assert "HTTP/2" in mutated

    def test_mutate_header_order(self) -> None:
        """Test header order mutation."""
        mutator = protocol.ProtocolMutator()
        request = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n"
        mutated = mutator.mutate_header_order(request)
        assert isinstance(mutated, str)

    def test_mutate_header_casing(self) -> None:
        """Test header casing mutation."""
        mutator = protocol.ProtocolMutator()
        request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        mutated = mutator.mutate_header_casing(request)
        assert isinstance(mutated, str)

    def test_smuggling_detector_initialization(self) -> None:
        """Test SmugglingDetector initialization."""
        detector = protocol.SmugglingDetector()
        assert detector._smuggler
        assert detector._fragmenter

    def test_smuggling_detector_uses_probe_callback(self) -> None:
        """Test smuggling detector probe integration."""
        detector = protocol.SmugglingDetector()
        session = ScanSession(config=SessionConfig(target="http://example.com"))
        seen: list[dict[str, str]] = []

        def probe(event):
            seen.append(event)
            return {"effective": event["technique"] == "te_cl"}

        session.runtime["smuggling_probe"] = probe

        assert detector.test_smuggling_technique(session, "GET / HTTP/1.1", "test", "te_cl")
        assert seen[0]["technique"] == "te_cl"

    def test_apply_request_smuggling(self) -> None:
        """Test applying request smuggling."""
        request = "GET / HTTP/1.1"
        payload = "test"
        result = protocol.apply_request_smuggling(request, payload)
        assert isinstance(result, str)

    def test_fragment_request(self) -> None:
        """Test request fragmentation."""
        request = "GET / HTTP/1.1"
        body = "test payload"
        fragments = protocol.fragment_request(request, body, method="chunked")
        assert isinstance(fragments, list)

    def test_mutate_http_protocol(self) -> None:
        """Test HTTP protocol mutation."""
        request = "GET / HTTP/1.1"
        mutated = protocol.mutate_http_protocol(request)
        assert isinstance(mutated, str)


class TestAdaptiveIntegration:
    """Tests for adaptive.py integration with new modules."""

    def test_detect_ml_waf(self) -> None:
        """Test ML WAF detection integration."""
        from stealthix.core.session import SessionConfig

        session = ScanSession(config=SessionConfig(target="http://example.com"))
        response = {
            "status_code": 403,
            "response_time": 150.0,
            "content_length": 500,
            "headers": {},
            "text": "Access denied",
        }
        from stealthix.evasion.adaptive import detect_ml_waf

        is_ml, confidence = detect_ml_waf(session, response)
        assert isinstance(is_ml, bool)
        assert isinstance(confidence, float)

    def test_apply_polymorphic_encoding(self) -> None:
        """Test polymorphic encoding integration."""
        from stealthix.core.session import SessionConfig

        session = ScanSession(config=SessionConfig(target="http://example.com"))
        payload = "SELECT * FROM users"
        from stealthix.evasion.adaptive import apply_polymorphic_encoding

        result = apply_polymorphic_encoding(session, payload)
        assert isinstance(result, str)

    def test_apply_behavioral_evasion(self) -> None:
        """Test behavioral evasion integration."""
        from stealthix.core.session import SessionConfig

        session = ScanSession(config=SessionConfig(target="http://example.com"))
        headers = {}
        from stealthix.evasion.adaptive import apply_behavioral_evasion

        result = apply_behavioral_evasion(session, headers)
        assert isinstance(result, dict)
        assert "user-agent" in result

    def test_apply_protocol_evasion(self) -> None:
        """Test protocol evasion integration."""
        from stealthix.core.session import SessionConfig

        session = ScanSession(config=SessionConfig(target="http://example.com"))
        request = "GET / HTTP/1.1"
        payload = "test"
        from stealthix.evasion.adaptive import apply_protocol_evasion

        result = apply_protocol_evasion(session, request, payload)
        assert isinstance(result, str)

    def test_smart_encoding_optimizer(self) -> None:
        """Test smart encoding optimizer integration."""
        from stealthix.core.session import SessionConfig

        session = ScanSession(config=SessionConfig(target="http://example.com"))
        pipeline = ["space2comment", "randomcase"]
        from stealthix.evasion.adaptive import smart_encoding_optimizer

        result = smart_encoding_optimizer(session, pipeline, 0.6)
        assert isinstance(result, list)

    def test_adaptive_escalation_with_feedback(self) -> None:
        """Test adaptive escalation with feedback."""
        from stealthix.core.session import SessionConfig

        session = ScanSession(config=SessionConfig(target="http://example.com"))
        payload = "SELECT * FROM users"
        from stealthix.evasion.adaptive import adaptive_escalation_with_feedback

        result = adaptive_escalation_with_feedback(session, payload, blocked=True)
        assert isinstance(result, str)

    def test_automated_bypass_discovery(self) -> None:
        """Test automated bypass discovery."""
        from stealthix.core.session import SessionConfig

        session = ScanSession(config=SessionConfig(target="http://example.com"))
        payload = "SELECT * FROM users"
        from stealthix.evasion.adaptive import automated_bypass_discovery

        result = automated_bypass_discovery(session, payload, max_attempts=5)
        assert isinstance(result, list)
