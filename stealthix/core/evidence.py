from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, TypeVar, cast

from stealthix.core.models import Finding

SCHEMA_VERSION = "1.0"
DEFAULT_EXCERPT_LIMIT = 512
REDACTED = "[REDACTED]"

_SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "passwd",
    "password",
    "secret",
    "token",
    "api-key",
    "api_key",
    "apikey",
    "session",
    "csrf",
)


def excerpt(value: Any, *, limit: int = DEFAULT_EXCERPT_LIMIT) -> str | None:
    if value is None:
        return None
    text = str(value)
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    return f"{text[: max(limit - 3, 0)]}..."


def is_sensitive_key(key: str) -> bool:
    normalized = key.strip().lower().replace("_", "-")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def redact_value(key: str, value: Any) -> Any:
    if is_sensitive_key(key):
        return REDACTED
    return value


def redact_mapping(values: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(values, dict):
        return {}
    return {str(key): redact_value(str(key), value) for key, value in values.items()}


def body_digest(value: Any) -> str | None:
    if value is None:
        return None
    raw = value if isinstance(value, bytes) else str(value).encode("utf-8", errors="replace")
    return sha256(raw).hexdigest()


def _clean_dict(values: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def _known_extra(values: dict[str, Any], known: set[str]) -> dict[str, Any]:
    return {key: value for key, value in values.items() if key not in known}


T = TypeVar("T")


def _coerce_items[T](value: Any, item_type: type[T]) -> list[T]:
    if not isinstance(value, list):
        return []
    output: list[T] = []
    from_dict = cast(Callable[[dict[str, Any]], T] | None, getattr(item_type, "from_dict", None))
    for item in value:
        if isinstance(item, item_type):
            output.append(item)
        elif isinstance(item, dict) and from_dict is not None:
            output.append(from_dict(item))
    return output


@dataclass
class RequestEvidence:
    method: str | None = None
    url: str | None = None
    headers: dict[str, Any] = field(default_factory=dict)
    body_excerpt: str | None = None
    body_sha256: str | None = None
    timestamp: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, values: dict[str, Any] | None) -> RequestEvidence:
        data = values if isinstance(values, dict) else {}
        raw_body = data.get("body_excerpt", data.get("body"))
        digest = data.get("body_sha256") or data.get("body_digest")
        known = {
            "method",
            "url",
            "headers",
            "body",
            "body_excerpt",
            "body_sha256",
            "body_digest",
            "timestamp",
        }
        return cls(
            method=str(data["method"]) if data.get("method") is not None else None,
            url=str(data["url"]) if data.get("url") is not None else None,
            headers=redact_mapping(
                data.get("headers") if isinstance(data.get("headers"), dict) else {}
            ),
            body_excerpt=excerpt(raw_body),
            body_sha256=str(digest) if digest is not None else body_digest(raw_body),
            timestamp=str(data["timestamp"]) if data.get("timestamp") is not None else None,
            extra=_known_extra(data, known),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            **self.extra,
            "method": self.method,
            "url": self.url,
            "headers": redact_mapping(self.headers),
            "body_excerpt": self.body_excerpt,
            "body_sha256": self.body_sha256 or body_digest(self.body_excerpt),
            "timestamp": self.timestamp,
        }
        return _clean_dict(payload)

    def to_pair_dict(self) -> dict[str, Any]:
        return _clean_dict(
            {
                "method": self.method,
                "url": self.url,
                "headers": redact_mapping(self.headers),
                "body": self.body_excerpt,
            }
        )


@dataclass
class ResponseEvidence:
    status_code: int | None = None
    headers: dict[str, Any] = field(default_factory=dict)
    content_type: str | None = None
    body_excerpt: str | None = None
    body_sha256: str | None = None
    elapsed_ms: float | None = None
    waf_hints: list[str] = field(default_factory=list)
    timestamp: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, values: dict[str, Any] | None) -> ResponseEvidence:
        data = values if isinstance(values, dict) else {}
        raw_body = data.get("body_excerpt", data.get("body"))
        raw_status = data.get("status_code", data.get("status"))
        status = None
        if raw_status is not None:
            try:
                status = int(raw_status)
            except (TypeError, ValueError):
                status = None
        raw_elapsed = data.get("elapsed_ms", data.get("elapsed"))
        elapsed = None
        if raw_elapsed is not None:
            try:
                elapsed = float(raw_elapsed)
            except (TypeError, ValueError):
                elapsed = None
        raw_waf_hints = data.get("waf_hints")
        waf_hints = cast(list[Any], raw_waf_hints) if isinstance(raw_waf_hints, list) else []
        known = {
            "status",
            "status_code",
            "headers",
            "content_type",
            "body",
            "body_excerpt",
            "body_sha256",
            "body_digest",
            "elapsed",
            "elapsed_ms",
            "waf_hints",
            "timestamp",
        }
        return cls(
            status_code=status,
            headers=redact_mapping(
                data.get("headers") if isinstance(data.get("headers"), dict) else {}
            ),
            content_type=str(data["content_type"])
            if data.get("content_type") is not None
            else None,
            body_excerpt=excerpt(raw_body),
            body_sha256=str(data.get("body_sha256") or data.get("body_digest"))
            if data.get("body_sha256") or data.get("body_digest")
            else body_digest(raw_body),
            elapsed_ms=elapsed,
            waf_hints=[str(item) for item in waf_hints if str(item).strip()],
            timestamp=str(data["timestamp"]) if data.get("timestamp") is not None else None,
            extra=_known_extra(data, known),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            **self.extra,
            "status_code": self.status_code,
            "headers": redact_mapping(self.headers),
            "content_type": self.content_type,
            "body_excerpt": self.body_excerpt,
            "body_sha256": self.body_sha256 or body_digest(self.body_excerpt),
            "elapsed_ms": self.elapsed_ms,
            "waf_hints": self.waf_hints,
            "timestamp": self.timestamp,
        }
        return _clean_dict(payload)

    def to_pair_dict(self) -> dict[str, Any]:
        return _clean_dict(
            {
                "status": self.status_code,
                "content_type": self.content_type,
                "headers": redact_mapping(self.headers),
                "body": self.body_excerpt,
                "waf_hints": self.waf_hints,
            }
        )


@dataclass
class PayloadEvidence:
    technique: str | None = None
    parameter: str | None = None
    location: str | None = None
    payload: str | None = None
    payload_excerpt: str | None = None
    encoding: str | None = None
    markers: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, values: dict[str, Any] | None) -> PayloadEvidence:
        data = values if isinstance(values, dict) else {}
        raw_payload = data.get("payload", data.get("payload_excerpt"))
        raw_markers = data.get("markers")
        markers = cast(list[Any], raw_markers) if isinstance(raw_markers, list) else []
        known = {
            "technique",
            "parameter",
            "location",
            "payload",
            "payload_excerpt",
            "encoding",
            "markers",
        }
        return cls(
            technique=str(data["technique"]) if data.get("technique") is not None else None,
            parameter=str(data["parameter"]) if data.get("parameter") is not None else None,
            location=str(data["location"]) if data.get("location") is not None else None,
            payload=excerpt(raw_payload),
            payload_excerpt=excerpt(data.get("payload_excerpt", raw_payload)),
            encoding=str(data["encoding"]) if data.get("encoding") is not None else None,
            markers=[str(item) for item in markers if str(item).strip()],
            extra=_known_extra(data, known),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            **self.extra,
            "technique": self.technique,
            "parameter": self.parameter,
            "location": self.location,
            "payload": self.payload,
            "payload_excerpt": self.payload_excerpt or excerpt(self.payload),
            "encoding": self.encoding,
            "markers": self.markers,
        }
        return _clean_dict(payload)


@dataclass
class TimingEvidence:
    baseline_ms: float | None = None
    observed_ms: float | None = None
    delta_ms: float | None = None
    control_ms: float | None = None
    threshold_ms: float | None = None
    sample_count: int | None = None
    matched: bool | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, values: dict[str, Any] | None) -> TimingEvidence:
        data = values if isinstance(values, dict) else {}

        def as_float(key: str) -> float | None:
            raw = data.get(key)
            if raw is None:
                return None
            try:
                return float(raw)
            except (TypeError, ValueError):
                return None

        raw_sample_count = data.get("sample_count", data.get("samples"))
        sample_count = None
        if raw_sample_count is not None:
            try:
                sample_count = int(raw_sample_count)
            except (TypeError, ValueError):
                sample_count = None
        baseline = as_float("baseline_ms")
        observed = as_float("observed_ms")
        delta = as_float("delta_ms")
        if delta is None and baseline is not None and observed is not None:
            delta = observed - baseline
        known = {
            "baseline_ms",
            "observed_ms",
            "delta_ms",
            "control_ms",
            "threshold_ms",
            "sample_count",
            "samples",
            "matched",
        }
        return cls(
            baseline_ms=baseline,
            observed_ms=observed,
            delta_ms=delta,
            control_ms=as_float("control_ms"),
            threshold_ms=as_float("threshold_ms"),
            sample_count=sample_count,
            matched=data.get("matched") if isinstance(data.get("matched"), bool) else None,
            extra=_known_extra(data, known),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            **self.extra,
            "baseline_ms": self.baseline_ms,
            "observed_ms": self.observed_ms,
            "delta_ms": self.delta_ms,
            "control_ms": self.control_ms,
            "threshold_ms": self.threshold_ms,
            "sample_count": self.sample_count,
            "matched": self.matched,
        }
        return _clean_dict(payload)


@dataclass
class OASTEvidence:
    protocol: str | None = None
    token: str | None = None
    callback_domain: str | None = None
    confirmed: bool = False
    interaction_count: int = 0
    interactions: list[dict[str, Any]] = field(default_factory=list)
    first_seen_at: str | None = None
    last_seen_at: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, values: dict[str, Any] | None) -> OASTEvidence:
        data = values if isinstance(values, dict) else {}
        interactions = (
            [dict(item) for item in data.get("interactions", []) if isinstance(item, dict)]
            if isinstance(data.get("interactions"), list)
            else []
        )
        raw_count = data.get("interaction_count")
        try:
            interaction_count = int(raw_count) if raw_count is not None else len(interactions)
        except (TypeError, ValueError):
            interaction_count = len(interactions)
        known = {
            "protocol",
            "token",
            "callback_domain",
            "confirmed",
            "interaction_count",
            "interactions",
            "first_seen_at",
            "last_seen_at",
        }
        return cls(
            protocol=str(data["protocol"]) if data.get("protocol") is not None else None,
            token=str(data["token"]) if data.get("token") is not None else None,
            callback_domain=str(data["callback_domain"])
            if data.get("callback_domain") is not None
            else None,
            confirmed=bool(data.get("confirmed")),
            interaction_count=interaction_count,
            interactions=interactions,
            first_seen_at=str(data["first_seen_at"])
            if data.get("first_seen_at") is not None
            else None,
            last_seen_at=str(data["last_seen_at"])
            if data.get("last_seen_at") is not None
            else None,
            extra=_known_extra(data, known),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            **self.extra,
            "protocol": self.protocol,
            "token": self.token,
            "callback_domain": self.callback_domain,
            "confirmed": self.confirmed,
            "interaction_count": self.interaction_count,
            "interactions": self.interactions,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
        }
        return _clean_dict(payload)


@dataclass
class BackendFingerprintEvidence:
    dbms: str | None = None
    version: str | None = None
    confidence: str | None = None
    confidence_score: float | None = None
    signals: list[str] = field(default_factory=list)
    raw_error_excerpt: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, values: dict[str, Any] | None) -> BackendFingerprintEvidence:
        data = values if isinstance(values, dict) else {}
        raw_score = data.get("confidence_score")
        confidence_score = None
        if raw_score is not None:
            try:
                confidence_score = float(raw_score)
            except (TypeError, ValueError):
                confidence_score = None
        raw_signals = data.get("signals")
        signals = cast(list[Any], raw_signals) if isinstance(raw_signals, list) else []
        known = {
            "dbms",
            "version",
            "confidence",
            "confidence_score",
            "signals",
            "raw_error_excerpt",
            "raw_error",
        }
        return cls(
            dbms=str(data["dbms"]) if data.get("dbms") is not None else None,
            version=str(data["version"]) if data.get("version") is not None else None,
            confidence=str(data["confidence"]) if data.get("confidence") is not None else None,
            confidence_score=confidence_score,
            signals=[str(item) for item in signals if str(item).strip()],
            raw_error_excerpt=excerpt(data.get("raw_error_excerpt", data.get("raw_error"))),
            extra=_known_extra(data, known),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            **self.extra,
            "dbms": self.dbms,
            "version": self.version,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "signals": self.signals,
            "raw_error_excerpt": self.raw_error_excerpt,
        }
        return _clean_dict(payload)


@dataclass
class FindingEvidenceBundle:
    requests: list[RequestEvidence] = field(default_factory=list)
    responses: list[ResponseEvidence] = field(default_factory=list)
    payloads: list[PayloadEvidence] = field(default_factory=list)
    timings: list[TimingEvidence] = field(default_factory=list)
    oast: list[OASTEvidence] = field(default_factory=list)
    backend_fingerprints: list[BackendFingerprintEvidence] = field(default_factory=list)
    evidence_pairs: list[dict[str, Any]] = field(default_factory=list)
    summary: str | None = None
    schema_version: str = SCHEMA_VERSION
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, values: dict[str, Any] | None) -> FindingEvidenceBundle:
        data = values if isinstance(values, dict) else {}
        raw_pairs = data.get("evidence_pairs")
        pairs = cast(list[Any], raw_pairs) if isinstance(raw_pairs, list) else []
        known = {
            "requests",
            "responses",
            "payloads",
            "timings",
            "oast",
            "backend_fingerprints",
            "evidence_pairs",
            "summary",
            "schema_version",
        }
        return cls(
            requests=_coerce_items(data.get("requests"), RequestEvidence),
            responses=_coerce_items(data.get("responses"), ResponseEvidence),
            payloads=_coerce_items(data.get("payloads"), PayloadEvidence),
            timings=_coerce_items(data.get("timings"), TimingEvidence),
            oast=_coerce_items(data.get("oast"), OASTEvidence),
            backend_fingerprints=_coerce_items(
                data.get("backend_fingerprints"), BackendFingerprintEvidence
            ),
            evidence_pairs=[dict(item) for item in pairs if isinstance(item, dict)],
            summary=str(data["summary"]) if data.get("summary") is not None else None,
            schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
            extra=_known_extra(data, known),
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            **self.extra,
            "schema_version": self.schema_version,
            "requests": [item.to_dict() for item in self.requests],
            "responses": [item.to_dict() for item in self.responses],
            "payloads": [item.to_dict() for item in self.payloads],
            "timings": [item.to_dict() for item in self.timings],
            "oast": [item.to_dict() for item in self.oast],
            "backend_fingerprints": [item.to_dict() for item in self.backend_fingerprints],
            "evidence_pairs": self.to_evidence_pairs(),
            "evidence_count": self.evidence_count,
            "summary": self.summary,
        }
        return _clean_dict(payload)

    @property
    def evidence_count(self) -> int:
        counts = [
            len(self.requests),
            len(self.responses),
            len(self.payloads),
            len(self.timings),
            len(self.oast),
            len(self.backend_fingerprints),
            len(self.evidence_pairs),
        ]
        return max(max(counts), 1)

    def to_evidence_pairs(self) -> list[dict[str, Any]]:
        if self.evidence_pairs:
            return [dict(item) for item in self.evidence_pairs if isinstance(item, dict)]
        pairs: list[dict[str, Any]] = []
        size = max(len(self.requests), len(self.responses))
        for index in range(size):
            pair: dict[str, Any] = {}
            if index < len(self.requests):
                pair["request"] = self.requests[index].to_pair_dict()
            if index < len(self.responses):
                pair["response"] = self.responses[index].to_pair_dict()
            if pair:
                pairs.append(pair)
        return pairs


def attach_evidence(finding: Finding, bundle: FindingEvidenceBundle | dict[str, Any]) -> Finding:
    normalized = (
        bundle
        if isinstance(bundle, FindingEvidenceBundle)
        else FindingEvidenceBundle.from_dict(bundle)
    )
    details = finding.details if isinstance(finding.details, dict) else {}
    finding.details = details
    bundle_dict = normalized.to_dict()
    pairs = normalized.to_evidence_pairs()
    details["evidence_bundle"] = bundle_dict
    if pairs:
        details["evidence_pairs"] = pairs
    elif "evidence_pairs" not in details:
        details["evidence_pairs"] = []
    existing_pairs = details.get("evidence_pairs")
    existing_pair_count = len(existing_pairs) if isinstance(existing_pairs, list) else 0
    details["evidence_count"] = max(
        int(details.get("evidence_count", 0) or 0),
        normalized.evidence_count,
        existing_pair_count,
        1,
    )
    return finding


__all__ = [
    "BackendFingerprintEvidence",
    "FindingEvidenceBundle",
    "OASTEvidence",
    "PayloadEvidence",
    "RequestEvidence",
    "ResponseEvidence",
    "TimingEvidence",
    "attach_evidence",
    "body_digest",
    "excerpt",
    "redact_mapping",
    "redact_value",
]
