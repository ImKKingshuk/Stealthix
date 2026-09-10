"""Unit tests for advanced blind inference features."""

from __future__ import annotations

import pytest

from stealthix.extraction.bitwise_inference import (
    BitwiseInference,
    calculate_optimal_bit_chunk_size,
    estimate_request_reduction,
)
from stealthix.extraction.statistical_inference import (
    StatisticalPredictor,
    build_predictor_from_samples,
    get_optimized_search_order,
)


class TestStatisticalPredictor:
    """Test statistical frequency analysis for blind inference."""

    def test_predictor_initialization(self) -> None:
        """Test predictor initializes with context."""
        predictor = StatisticalPredictor(context="hello world")
        assert predictor.context == "hello world"
        assert predictor.char_frequency is not None

    def test_predictor_without_context(self) -> None:
        """Test predictor initializes without context using default frequency."""
        predictor = StatisticalPredictor()
        assert predictor.context == ""
        assert predictor.char_frequency is not None

    def test_predict_next_char(self) -> None:
        """Test predicting next character based on frequency."""
        predictor = StatisticalPredictor(context="hello")
        chars = predictor.predict_next_char()
        assert isinstance(chars, list)
        assert len(chars) > 0

    def test_predict_next_char_with_char_set(self) -> None:
        """Test predicting next character with character set constraint."""
        predictor = StatisticalPredictor(context="hello123")
        chars = predictor.predict_next_char(char_set="abc123")
        assert isinstance(chars, list)
        assert all(c in "abc123" for c in chars)

    def test_predict_string_completion(self) -> None:
        """Test predicting string completions."""
        predictor = StatisticalPredictor(context="hello world")
        completions = predictor.predict_string_completion("hel")
        assert isinstance(completions, list)

    def test_get_char_set_by_type(self) -> None:
        """Test getting character set by data type."""
        predictor = StatisticalPredictor()
        assert predictor.get_char_set_by_type("hex") == predictor.COMMON_HEX
        assert predictor.get_char_set_by_type("digits") == predictor.COMMON_DIGITS
        assert predictor.get_char_set_by_type("base64") == predictor.COMMON_BASE64

    def test_rank_chars_by_probability(self) -> None:
        """Test ranking characters by probability."""
        predictor = StatisticalPredictor(context="hello")
        ranked = predictor.rank_chars_by_probability(["h", "e", "l", "o"])
        assert isinstance(ranked, list)
        assert len(ranked) == 4

    def test_estimate_length_range(self) -> None:
        """Test estimating length range from sample data."""
        predictor = StatisticalPredictor()
        samples = ["hello", "world", "test"]
        min_len, max_len = predictor.estimate_length_range(samples)
        assert min_len >= 1
        assert max_len <= 128

    def test_build_predictor_from_samples(self) -> None:
        """Test building predictor from sample data."""
        samples = ["hello", "world", "test"]
        predictor = build_predictor_from_samples(samples)
        assert predictor is not None
        assert predictor.context == "hello world test"

    def test_get_optimized_search_order(self) -> None:
        """Test getting optimized search order for binary search."""
        order = get_optimized_search_order("hello")
        assert isinstance(order, list)
        assert len(order) > 0
        assert all(isinstance(code, int) for code in order)


class TestBitwiseInference:
    """Test bitwise inference for numeric data extraction."""

    def test_bitwise_inference_initialization(self) -> None:
        """Test bitwise inference initializes with oracle and dialect."""
        oracle = MockOracle()
        dialect = MockDialect()
        bitwise = BitwiseInference(oracle, dialect)
        assert bitwise.oracle is not None
        assert bitwise.dialect is not None

    def test_infer_bits(self) -> None:
        """Test extracting multiple bits per request."""
        oracle = MockBitwiseOracle(value=10)
        dialect = MockDialect()
        bitwise = BitwiseInference(oracle, dialect)
        result = bitwise.infer_bits("value", 4, 0)
        assert result >= 0
        assert result <= 15

    def test_infer_bits_invalid_num_bits(self) -> None:
        """Test that invalid num_bits raises ValueError."""
        oracle = MockBitwiseOracle()
        dialect = MockDialect()
        bitwise = BitwiseInference(oracle, dialect)
        with pytest.raises(ValueError):
            bitwise.infer_bits("value", 3, 0)

    def test_infer_byte(self) -> None:
        """Test extracting a full byte (8 bits)."""
        oracle = MockBitwiseOracle(value=255)
        dialect = MockDialect()
        bitwise = BitwiseInference(oracle, dialect)
        result = bitwise.infer_byte("value", 0)
        assert result >= 0
        assert result <= 255

    def test_infer_number_bitwise(self) -> None:
        """Test extracting multi-byte number."""
        oracle = MockBitwiseOracle(value=1024)
        dialect = MockDialect()
        bitwise = BitwiseInference(oracle, dialect)
        result = bitwise.infer_number_bitwise("value", max_bytes=2)
        assert result >= 0

    def test_infer_boolean_array(self) -> None:
        """Test extracting multiple boolean values as bits."""
        oracle = MockBitwiseOracle(value=0b1011)
        dialect = MockDialect()
        bitwise = BitwiseInference(oracle, dialect)
        booleans = bitwise.infer_boolean_array("value", 4)
        assert isinstance(booleans, list)
        assert len(booleans) == 4

    def test_infer_with_nibble_optimization(self) -> None:
        """Test number inference using nibble optimization."""
        oracle = MockBitwiseOracle(value=100)
        dialect = MockDialect()
        bitwise = BitwiseInference(oracle, dialect)
        result = bitwise.infer_with_nibble_optimization("value", max_value=255)
        assert result >= 0
        assert result <= 255

    def test_check_bitwise_support(self) -> None:
        """Test checking bitwise operation support."""
        oracle = MockOracle()
        dialect = MockDialect()
        bitwise = BitwiseInference(oracle, dialect)
        assert bitwise.check_bitwise_support() is True


class TestBitwiseUtilities:
    """Test bitwise inference utility functions."""

    def test_calculate_optimal_bit_chunk_size(self) -> None:
        """Test calculating optimal bit chunk size."""
        # 15 has bit_length 4, so it returns 1 (1-4 bits)
        assert calculate_optimal_bit_chunk_size(15) == 1
        # 255 has bit_length 8, so it returns 2 (5-8 bits)
        assert calculate_optimal_bit_chunk_size(255) == 2
        # 65535 has bit_length 16, so it returns 4 (9-16 bits)
        assert calculate_optimal_bit_chunk_size(65535) == 4
        # 3 has bit_length 2, so it returns 1 (1-4 bits)
        assert calculate_optimal_bit_chunk_size(3) == 1

    def test_estimate_request_reduction(self) -> None:
        """Test estimating request reduction using bitwise inference."""
        # Use a larger max_value to show actual reduction
        bitwise_requests, reduction = estimate_request_reduction(16, 65535, use_bitwise=True)
        assert bitwise_requests == 4  # 2 bytes * 2 requests per byte (4-bit chunks)
        assert reduction > 0

    def test_estimate_request_reduction_no_bitwise(self) -> None:
        """Test that bitwise disabled shows no reduction."""
        standard, reduction = estimate_request_reduction(8, 255, use_bitwise=False)
        assert standard == 8
        assert reduction == 0.0


class MockOracle:
    """Mock oracle for testing."""

    def __init__(self, value: int = 0) -> None:
        self.value = value

    def check(self, predicate: str) -> bool:
        """Mock check that returns True for predicates less than value."""
        try:
            # Extract number from predicate like "(value)>5"
            if ">" in predicate:
                num = int(predicate.split(">")[-1].rstrip(")"))
                return self.value > num
            return False
        except (ValueError, IndexError):
            return False


class MockBitwiseOracle:
    """Mock oracle that simulates bitwise operations for testing."""

    def __init__(self, value: int = 0) -> None:
        self.value = value

    def check(self, predicate: str) -> bool:
        """Mock check that simulates bitwise operations."""
        try:
            # Simulate ((value >> offset) & mask) > num
            if ">>" in predicate and "&" in predicate:
                # Extract offset, mask, and comparison value
                parts = predicate.split(")")
                value_part = parts[0].strip("(")
                offset = int(value_part.split(">>")[1])
                mask = int(parts[1].split("&")[1])
                num = int(parts[2].split(">")[1])

                extracted = (self.value >> offset) & mask
                return extracted > num
            return False
        except (ValueError, IndexError):
            return False


class MockDialect:
    """Mock dialect for testing."""

    def __init__(self) -> None:
        self.name = "mock"

    def ascii_expr(self, expr: str, pos: int) -> str:
        return f"ASCII(SUBSTRING({expr},{pos},1))"

    def length_expr(self, expr: str) -> str:
        return f"LENGTH({expr})"

    def hex_expr(self, expr: str) -> str:
        return f"HEX({expr})"

    def boolean_wrapper(self, predicate: str) -> str:
        return f"1 AND ({predicate})"

    def time_wrapper(self, predicate: str, delay: float) -> str:
        return f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--"
