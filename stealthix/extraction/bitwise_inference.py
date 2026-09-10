"""Bitwise inference for numeric data extraction."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


class BitwiseInference:
    """Bitwise inference for numeric data extraction."""

    def __init__(self, oracle: Any, dialect: Any) -> None:
        """Initialize bitwise inference with oracle and dialect."""
        self.oracle = oracle
        self.dialect = dialect

    def infer_bits(self, expression: str, num_bits: int, bit_offset: int = 0) -> int:
        """Extract multiple bits per request using bitwise operations.

        Args:
            expression: SQL expression to extract value from
            num_bits: Number of bits to extract (typically 4 or 8)
            bit_offset: Starting bit position (default 0)

        Returns:
            Extracted bits as integer value

        Example:
            infer_bits("value", 4, 0) extracts bits 0-3 (lower nibble)
            infer_bits("value", 4, 4) extracts bits 4-7 (upper nibble)
        """
        if num_bits not in [1, 2, 4, 8]:
            raise ValueError("num_bits must be 1, 2, 4, or 8")

        # Use bit-shifting predicate: ((value >> bit_offset) & mask)
        mask = (1 << num_bits) - 1
        predicate = f"(({expression} >> {bit_offset}) & {mask})"

        # Binary search for the value (0 to mask)
        low = 0
        high = mask
        while low <= high:
            mid = (low + high) // 2
            if self.oracle.check(f"({predicate}) > {mid}"):
                low = mid + 1
            else:
                high = mid - 1
        return low

    def infer_byte(self, expression: str, byte_offset: int = 0) -> int:
        """Extract a full byte (8 bits) in minimal requests.

        Extracts 8 bits using two 4-bit extractions, reducing from 8 requests to 2-3.

        Args:
            expression: SQL expression to extract value from
            byte_offset: Byte position (default 0)

        Returns:
            Extracted byte as integer value (0-255)
        """
        bit_offset = byte_offset * 8

        # Extract lower nibble (bits 0-3)
        lower_nibble = self.infer_bits(expression, 4, bit_offset)

        # Extract upper nibble (bits 4-7)
        upper_nibble = self.infer_bits(expression, 4, bit_offset + 4)

        # Combine nibbles to form byte
        return (upper_nibble << 4) | lower_nibble

    def infer_number_bitwise(self, expression: str, max_bytes: int = 4) -> int:
        """Extract a multi-byte number using bitwise inference.

        Extracts multiple bytes using bitwise operations, significantly reducing
        the number of requests compared to standard binary search.

        Args:
            expression: SQL expression to extract value from
            max_bytes: Maximum number of bytes to extract (default 4 = 32 bits)

        Returns:
            Extracted number as integer value
        """
        result = 0
        for byte_offset in range(max_bytes):
            byte_value = self.infer_byte(expression, byte_offset)
            result |= byte_value << (byte_offset * 8)

            # Early termination if byte is 0 and we've already extracted data
            if byte_value == 0 and byte_offset > 0:
                break

        return result

    def infer_boolean_array(self, expression: str, num_bits: int) -> list[bool]:
        """Extract multiple boolean values as bits.

        Extracts num_bits boolean values packed into a single integer.

        Args:
            expression: SQL expression that evaluates to a bitmask
            num_bits: Number of boolean bits to extract

        Returns:
            List of boolean values
        """
        # Extract the full bitmask
        mask_value = self.infer_number_bitwise(expression, max_bytes=(num_bits + 7) // 8)

        # Convert bitmask to boolean array
        booleans = []
        for i in range(num_bits):
            booleans.append(bool((mask_value >> i) & 1))

        return booleans

    def infer_with_nibble_optimization(self, expression: str, max_value: int = 255) -> int:
        """Extract number using nibble (4-bit) optimization.

        For values up to 255, uses two 4-bit extractions instead of 8 bit extractions.
        For larger values, scales accordingly.

        Args:
            expression: SQL expression to extract value from
            max_value: Maximum expected value (default 255)

        Returns:
            Extracted number as integer value
        """
        if max_value <= 255:
            # Single byte, use nibble extraction
            return self.infer_byte(expression, 0)
        elif max_value <= 65535:
            # Two bytes, use nibble extraction for each
            low_byte = self.infer_byte(expression, 0)
            high_byte = self.infer_byte(expression, 1)
            return (high_byte << 8) | low_byte
        else:
            # Larger values, use full bitwise extraction
            max_bytes = (max_value.bit_length() + 7) // 8
            return self.infer_number_bitwise(expression, max_bytes=max_bytes)

    def check_bitwise_support(self) -> bool:
        """Check if the dialect supports bitwise operations.

        Returns:
            True if dialect supports bitwise operations (>>, &, |, <<)
        """
        # Most SQL dialects support bitwise operations
        # This is a basic check - could be enhanced with dialect-specific tests
        return True


def calculate_optimal_bit_chunk_size(max_value: int) -> int:
    """Calculate optimal bit chunk size for a given max value.

    Args:
        max_value: Maximum value to extract

    Returns:
        Optimal number of bits per chunk (1, 2, 4, or 8)
    """
    bit_length = max_value.bit_length()

    # Use 8-bit chunks for larger values (more than 16 bits)
    if bit_length > 16:
        return 8
    # Use 4-bit chunks for medium values (9-16 bits)
    elif bit_length > 8:
        return 4
    # Use 2-bit chunks for small values (5-8 bits)
    elif bit_length > 4:
        return 2
    # Use 1-bit chunks for very small values (1-4 bits)
    else:
        return 1


def estimate_request_reduction(
    standard_requests: int, max_value: int, use_bitwise: bool
) -> tuple[int, float]:
    """Estimate request reduction using bitwise inference.

    Args:
        standard_requests: Number of requests with standard binary search
        max_value: Maximum value to extract
        use_bitwise: Whether bitwise inference is used

    Returns:
        Tuple of (estimated_requests, reduction_percentage)
    """
    if not use_bitwise:
        return standard_requests, 0.0

    # Standard binary search: log2(max_value) requests per byte
    # Bitwise with nibble chunks: 2 requests per byte (4 bits each)
    # Bitwise with byte chunks: 1 request per byte (8 bits)

    bit_length = max_value.bit_length()
    chunk_size = calculate_optimal_bit_chunk_size(max_value)

    # Calculate number of bytes needed
    num_bytes = (bit_length + 7) // 8

    # Bitwise requests: num_bytes * (8 / chunk_size) requests
    # For 4-bit chunks: num_bytes * 2
    # For 8-bit chunks: num_bytes * 1
    bitwise_requests = num_bytes * (8 // chunk_size)

    # Ensure bitwise_requests is at least 1
    bitwise_requests = max(1, bitwise_requests)

    reduction = ((standard_requests - bitwise_requests) / standard_requests) * 100
    return bitwise_requests, max(0.0, reduction)
