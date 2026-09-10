from __future__ import annotations

from stealthix.core.session import ScanSession
from stealthix.core.targeting import discover_injection_points
from stealthix.payloads.nosql_advanced import get_advanced_payloads
from stealthix.utils.payloads import resolve_payloads


def _custom_payloads(cfg: object, key: str) -> list[str] | None:
    custom = getattr(cfg, "custom_payloads", None)
    if not isinstance(custom, dict):
        return None
    payloads = custom.get(key)
    if isinstance(payloads, list):
        return [str(item) for item in payloads if str(item or "").strip()]
    return None


def _estimate_payload_count(session: ScanSession) -> int:
    cfg = session.config
    dbms = (cfg.dbms or "").lower()
    do_sql = dbms in {"", "mysql", "postgresql", "mssql", "oracle", "sqlite", "mariadb", "db2"}
    do_nosql = dbms in {"", "mongodb", "couchdb", "redis", "cassandra", "firebase", "dynamodb"}
    do_newsql = dbms in {"", "cockroachdb", "tidb", "voltdb", "yugabytedb", "spanner"}

    total = 0
    if do_sql:
        total += len(
            resolve_payloads(
                "sqli", custom_payloads=_custom_payloads(cfg, "sqli"), expand=True, risk=cfg.risk
            )
        )
        technique = (cfg.technique or "").upper()
        use_all = not technique
        if use_all or "B" in technique:
            total += 2
        if use_all or "T" in technique:
            total += len(
                resolve_payloads(
                    "time_based",
                    custom_payloads=_custom_payloads(cfg, "time_based"),
                    expand=True,
                    risk=cfg.risk,
                )
            )
        if use_all or "E" in technique:
            total += len(
                resolve_payloads(
                    "error_based",
                    custom_payloads=_custom_payloads(cfg, "error_based"),
                    expand=True,
                    risk=cfg.risk,
                )
            )
        if use_all or "U" in technique:
            total += (min(12, 2 + cfg.level * 3) * 2) + len(
                resolve_payloads(
                    "union_based",
                    custom_payloads=_custom_payloads(cfg, "union_based"),
                    expand=True,
                    risk=cfg.risk,
                )
            )
        if use_all or "S" in technique:
            total += len(
                resolve_payloads(
                    "stacked",
                    custom_payloads=_custom_payloads(cfg, "stacked"),
                    expand=True,
                    risk=cfg.risk,
                )
            )
        if cfg.level >= 5:
            total += 2
        if cfg.level >= 4:
            total += 3
    if do_nosql:
        dbms = (cfg.dbms or "").lower()
        backends = (
            [dbms]
            if dbms in {"mongodb", "couchdb", "redis", "cassandra", "firebase", "dynamodb"}
            else [
                "mongodb",
                "couchdb",
                "redis",
                "cassandra",
                "firebase",
                "dynamodb",
            ]
        )
        for backend in backends:
            if backend == "mongodb":
                total += len(
                    resolve_payloads(
                        "nosqli",
                        custom_payloads=_custom_payloads(cfg, "nosqli"),
                        expand=True,
                        risk=cfg.risk,
                        include_advanced=True,
                        advanced_backend="mongodb",
                    )
                )
            else:
                total += len(
                    resolve_payloads(
                        "nosqli",
                        custom_payloads=_custom_payloads(cfg, "nosqli")
                        or get_advanced_payloads(backend),
                        expand=True,
                        risk=cfg.risk,
                        include_advanced=False,
                    )
                )
    if do_newsql:
        total += len(
            resolve_payloads(
                "newsql",
                custom_payloads=_custom_payloads(cfg, "newsql"),
                expand=True,
                risk=cfg.risk,
            )
        )
    if cfg.level >= 2:
        total += 2
    if cfg.level >= 3:
        total += 4
    return max(1, int(total))


def estimate_total_requests(session: ScanSession) -> int:
    points = discover_injection_points(session)
    return max(1, int((len(points) if points else 1) * _estimate_payload_count(session)))


def summarize_tested_params(session: ScanSession) -> tuple[list[dict[str, object]], str]:
    tested = session.metadata.get("tested_params", [])
    if not isinstance(tested, list):
        tested = []
    parts: list[str] = []
    for item in tested[-6:]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        location = str(item.get("location") or "")
        if name:
            parts.append(f"{name}@{location}" if location else name)
    return tested, ", ".join(parts) if parts else "-"
