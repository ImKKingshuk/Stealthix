"""Polymorphic encoding engine with dynamic encoding chains.

This module provides dynamic encoding chains that mutate per request
to evade WAF signature detection.
"""

from __future__ import annotations

import random
import string
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from stealthix.utils import load_rust_core


_DEFAULT_ENCODING_OPERATIONS: tuple[str, ...] = (
    "url_encode",
    "double_url_encode",
    "hex_encode",
    "base64_encode",
    "space_to_comment",
    "space_to_plus",
    "random_case",
    "html_encode",
)


def _py_fallback_tamper(op: str, text: str) -> str:
    import base64
    import html
    import urllib.parse

    if op == "url_encode":
        return urllib.parse.quote(text, safe="")
    if op == "double_url_encode":
        return urllib.parse.quote(urllib.parse.quote(text, safe=""), safe="")
    if op == "space_to_comment":
        return text.replace(" ", "/**/")
    if op == "space_to_plus":
        return text.replace(" ", "+")
    if op == "random_case":
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in text)
    if op == "hex_encode":
        return "".join(f"%{ord(c):02x}" for c in text)
    if op == "base64_encode":
        return base64.b64encode(text.encode("utf-8")).decode("utf-8")
    if op == "html_encode":
        return html.escape(text)
    return text


@dataclass
class EncodingChain:
    """Represents a sequence of encoding transformations."""

    operations: tuple[str, ...]
    success_count: int = 0
    failure_count: int = 0
    last_used: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate of this chain."""
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total

    def record_success(self) -> None:
        """Record a successful use of this chain."""
        self.success_count += 1
        self.last_used = 0

    def record_failure(self) -> None:
        """Record a failed use of this chain."""
        self.failure_count += 1
        self.last_used = 0


class PolymorphicEncoder:
    """Dynamic encoding chain engine with mutation strategies.

    Generates and optimizes encoding chains that mutate per request
    to evade WAF signature detection.
    """

    def __init__(self) -> None:
        self._chains: dict[str, EncodingChain] = {}
        self._available_operations = self._build_available_operations()
        self._mutation_strategies = [
            self._mutate_random,
            self._mutate_frequency_based,
            self._mutate_adaptive,
        ]
        self._chain_history: list[str] = []
        self._max_chain_length = 5

    def _build_available_operations(self) -> list[str]:
        """Build list of available encoding operations."""
        rust = load_rust_core()
        list_scripts = rust.get("list_tamper_scripts")
        if callable(list_scripts):
            try:
                scripts = list_scripts()
                if scripts:
                    return list(scripts)
            except Exception:
                pass
        return list(_DEFAULT_ENCODING_OPERATIONS)

    def generate_chain(self, length: int | None = None) -> EncodingChain:
        """Generate a new encoding chain."""
        if length is None:
            length = random.randint(2, self._max_chain_length)

        operations = random.sample(
            self._available_operations, min(length, len(self._available_operations))
        )
        chain_key = ",".join(operations)

        if chain_key not in self._chains:
            self._chains[chain_key] = EncodingChain(operations=tuple(operations))

        return self._chains[chain_key]

    def mutate_chain(self, chain: EncodingChain) -> EncodingChain:
        """Mutate an existing encoding chain."""
        strategy = random.choice(self._mutation_strategies)
        return strategy(chain)

    def _mutate_random(self, chain: EncodingChain) -> EncodingChain:
        """Random mutation strategy."""
        operations = list(chain.operations)

        # Add random operation
        if len(operations) < self._max_chain_length:
            new_op = random.choice(self._available_operations)
            if new_op not in operations:
                operations.append(new_op)

        # Remove random operation
        if len(operations) > 2:
            operations.pop(random.randint(0, len(operations) - 1))

        # Swap random operations
        if len(operations) >= 2:
            i, j = random.sample(range(len(operations)), 2)
            operations[i], operations[j] = operations[j], operations[i]

        new_chain_key = ",".join(operations)
        if new_chain_key not in self._chains:
            self._chains[new_chain_key] = EncodingChain(operations=tuple(operations))

        return self._chains[new_chain_key]

    def _mutate_frequency_based(self, chain: EncodingChain) -> EncodingChain:
        """Frequency-based mutation strategy."""
        operations = list(chain.operations)

        # Prioritize frequently successful operations
        operation_success = defaultdict(int)
        for c in self._chains.values():
            for op in c.operations:
                operation_success[op] += c.success_count

        # Replace least successful operation
        if operations and operation_success:
            least_successful = min(operations, key=lambda op: operation_success[op])
            most_successful = max(self._available_operations, key=lambda op: operation_success[op])
            if most_successful not in operations:
                operations[operations.index(least_successful)] = most_successful

        new_chain_key = ",".join(operations)
        if new_chain_key not in self._chains:
            self._chains[new_chain_key] = EncodingChain(operations=tuple(operations))

        return self._chains[new_chain_key]

    def _mutate_adaptive(self, chain: EncodingChain) -> EncodingChain:
        """Adaptive mutation based on chain success rate."""
        operations = list(chain.operations)

        # If chain has low success rate, significantly mutate
        if chain.success_rate < 0.3:
            # Replace half the operations
            num_replace = len(operations) // 2
            for _ in range(num_replace):
                idx = random.randint(0, len(operations) - 1)
                new_op = random.choice(self._available_operations)
                operations[idx] = new_op
        # If chain has high success rate, minimally mutate
        elif chain.success_rate > 0.7:
            # Only add one new operation
            if len(operations) < self._max_chain_length:
                new_op = random.choice(self._available_operations)
                if new_op not in operations:
                    operations.append(new_op)
        else:
            # Moderate mutation
            if random.random() < 0.5:
                operations.pop(random.randint(0, len(operations) - 1))
            else:
                new_op = random.choice(self._available_operations)
                if new_op not in operations:
                    operations.append(new_op)

        new_chain_key = ",".join(operations)
        if new_chain_key not in self._chains:
            self._chains[new_chain_key] = EncodingChain(operations=tuple(operations))

        return self._chains[new_chain_key]

    def apply_chain(self, chain: EncodingChain, payload: str) -> str:
        """Apply encoding chain to payload."""
        result = payload
        rust = load_rust_core()
        apply_tamper = rust.get("apply_tamper_sequence")

        if callable(apply_tamper):
            try:
                result = apply_tamper(list(chain.operations), result)
            except Exception:
                single_tamper = rust.get("apply_tamper")
                if callable(single_tamper):
                    for op in chain.operations:
                        try:
                            result = single_tamper(op, result)
                        except Exception:
                            result = _py_fallback_tamper(op, result)
                else:
                    for op in chain.operations:
                        result = _py_fallback_tamper(op, result)
        else:
            for op in chain.operations:
                result = _py_fallback_tamper(op, result)

        self._chain_history.append(",".join(chain.operations))
        if len(self._chain_history) > 100:
            self._chain_history = self._chain_history[-100:]

        return result

    def get_best_chain(self) -> EncodingChain:
        """Get the chain with highest success rate."""
        if not self._chains:
            return self.generate_chain()

        best_chain = max(self._chains.values(), key=lambda c: c.success_rate)
        return best_chain

    def optimize_chains(self) -> None:
        """Optimize chains by pruning ineffective ones."""
        # Remove chains with very low success rate and many failures
        to_remove = []
        for key, chain in self._chains.items():
            if chain.success_rate < 0.1 and chain.failure_count > 10:
                to_remove.append(key)

        for key in to_remove:
            del self._chains[key]

        # Limit total number of chains
        if len(self._chains) > 100:
            # Keep best 100 chains
            sorted_chains = sorted(
                self._chains.items(), key=lambda x: x[1].success_rate, reverse=True
            )
            self._chains = dict(sorted_chains[:100])


class MutationStrategy:
    """Different mutation strategies for encoding chains."""

    @staticmethod
    def random_mutation(chain: EncodingChain, available_ops: list[str]) -> EncodingChain:
        """Random mutation strategy."""
        operations = list(chain.operations)

        if random.random() < 0.5 and len(operations) > 2:
            # Remove random operation
            operations.pop(random.randint(0, len(operations) - 1))
        else:
            # Add random operation
            new_op = random.choice(available_ops)
            if new_op not in operations:
                operations.append(new_op)

        return EncodingChain(operations=tuple(operations))

    @staticmethod
    def frequency_mutation(chain: EncodingChain, frequency_map: dict[str, int]) -> EncodingChain:
        """Frequency-based mutation using character frequency."""
        operations = list(chain.operations)

        # Replace with higher frequency operations
        for i, op in enumerate(operations):
            if random.random() < 0.3:
                higher_freq_ops = [
                    o for o in frequency_map if frequency_map[o] > frequency_map.get(op, 0)
                ]
                if higher_freq_ops:
                    operations[i] = random.choice(higher_freq_ops)

        return EncodingChain(operations=tuple(operations))

    @staticmethod
    def adaptive_mutation(chain: EncodingChain, success_threshold: float = 0.5) -> EncodingChain:
        """Adaptive mutation based on success rate."""
        operations = list(chain.operations)

        if chain.success_rate < success_threshold:
            # Aggressive mutation
            operations = [random.choice(operations) for _ in range(len(operations))]
        else:
            # Conservative mutation
            if operations and random.random() < 0.2:
                operations[random.randint(0, len(operations) - 1)] = random.choice(operations)

        return EncodingChain(operations=tuple(operations))


class ChainOptimizer:
    """Optimize encoding chains for effectiveness."""

    def __init__(self) -> None:
        self._chain_performance: dict[str, dict[str, Any]] = {}
        self._ab_test_results: dict[str, dict[str, Any]] = {}

    def record_chain_performance(
        self, chain: EncodingChain, success: bool, response_time: float
    ) -> None:
        """Record performance metrics for a chain."""
        chain_key = ",".join(chain.operations)

        if chain_key not in self._chain_performance:
            self._chain_performance[chain_key] = {
                "success_count": 0,
                "failure_count": 0,
                "total_time": 0.0,
                "avg_time": 0.0,
            }

        perf = self._chain_performance[chain_key]
        if success:
            perf["success_count"] += 1
        else:
            perf["failure_count"] += 1

        perf["total_time"] += response_time
        total_attempts = perf["success_count"] + perf["failure_count"]
        perf["avg_time"] = perf["total_time"] / total_attempts if total_attempts > 0 else 0.0

    def get_optimal_chain(self) -> EncodingChain | None:
        """Get the optimal chain based on performance metrics."""
        if not self._chain_performance:
            return None

        # Score chains by success rate and speed
        scored_chains = []
        for chain_key, perf in self._chain_performance.items():
            total_attempts = perf["success_count"] + perf["failure_count"]
            if total_attempts < 3:
                continue  # Need minimum attempts for significance

            success_rate = perf["success_count"] / total_attempts
            speed_score = 1.0 / (perf["avg_time"] + 0.001)  # Avoid division by zero

            # Weight success rate higher than speed
            score = (success_rate * 0.7) + (speed_score * 0.3)
            scored_chains.append((chain_key, score))

        if not scored_chains:
            return None

        best_chain_key = max(scored_chains, key=lambda x: x[1])[0]
        operations = tuple(best_chain_key.split(","))
        return EncodingChain(operations=operations)

    def run_ab_test(
        self, chain_a: EncodingChain, chain_b: EncodingChain, results: list[bool]
    ) -> dict[str, float]:
        """Run A/B test between two chains."""
        key_a = ",".join(chain_a.operations)
        key_b = ",".join(chain_b.operations)

        success_a = sum(1 for r in results if r) / len(results) if results else 0.0
        success_b = 1.0 - success_a  # Simplified A/B test

        self._ab_test_results[f"{key_a}_vs_{key_b}"] = {
            "chain_a_success": success_a,
            "chain_b_success": success_b,
            "winner": key_a if success_a > success_b else key_b,
        }

        return self._ab_test_results[f"{key_a}_vs_{key_b}"]


def generate_polymorphic_payload(
    payload: str, chain_length: int | None = None, mutation_count: int = 1
) -> str:
    """Generate polymorphic payload with encoding chain mutations."""
    encoder = PolymorphicEncoder()
    chain = encoder.generate_chain(chain_length)

    for _ in range(mutation_count):
        chain = encoder.mutate_chain(chain)

    return encoder.apply_chain(chain, payload)


def optimize_encoding_chains(chains: list[EncodingChain]) -> list[EncodingChain]:
    """Optimize encoding chains by pruning ineffective ones."""
    # Sort by success rate
    sorted_chains = sorted(chains, key=lambda c: c.success_rate, reverse=True)

    # Keep top 50%
    keep_count = max(1, len(sorted_chains) // 2)
    return sorted_chains[:keep_count]
