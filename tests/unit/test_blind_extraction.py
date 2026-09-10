import re

from stealthix.core.session import ScanSession, SessionConfig
from stealthix.extraction.blind import (
    BlindInferenceEngine,
    dialect_for_dbms,
    enumerate_tables_blind,
)
from stealthix.extraction.databases import enumerate_databases
from stealthix.extraction.nosql_extract import enumerate_databases_nosql
from stealthix.support_matrix import get_support_entry


class _DummyOracle:
    def __init__(self, text: str, count: int) -> None:
        self.text = text
        self.count = count
        self.technique = "boolean"
        self.available = True
        self.request_count = 0
        self.trace = []

    def check(self, predicate: str) -> bool:
        self.request_count += 1
        if match := re.search(r"\(count_demo\)>(\d+)", predicate):
            return self.count > int(match.group(1))
        if match := re.search(r"\(LENGTH\(\(demo\)\)\)>(\d+)", predicate):
            return len(self.text) > int(match.group(1))
        if match := re.search(r"ASCII\(SUBSTRING\(\(demo\),(\d+),1\)\)\)>(\d+)", predicate):
            pos = int(match.group(1)) - 1
            return ord(self.text[pos]) > int(match.group(2))
        raise AssertionError(f"unexpected predicate: {predicate}")


class _PackedBatchOracle:
    def __init__(self, values: dict[str, str], table_rows: list[str] | None = None) -> None:
        self.values = values
        self.table_rows = table_rows or []
        self.technique = "boolean"
        self.available = True
        self.request_count = 0
        self.trace = []

    def check(self, predicate: str) -> bool:
        self.request_count += 1
        threshold = self._threshold(predicate)
        return self._value(predicate) > threshold

    def _threshold(self, predicate: str) -> int:
        match = re.search(r">\s*(\d+)\)?\s*$", predicate)
        if not match:
            raise AssertionError(f"unexpected predicate: {predicate}")
        return int(match.group(1))

    def _value(self, predicate: str) -> int:
        if "COUNT(*) FROM information_schema.tables" in predicate:
            return len(self.table_rows)
        if "SUM(code * weight)" in predicate:
            return self._packed_codes(predicate)
        if "SUM(len * weight)" in predicate:
            return self._packed_lengths(predicate)
        if "LENGTH((" in predicate:
            return len(self._text_for_sql(predicate))
        if "ASCII(SUBSTRING" in predicate:
            position = int(re.search(r",(\d+),1\)", predicate).group(1))
            value = self._text_for_sql(predicate)
            return ord(value[position - 1]) if position <= len(value) else 0
        raise AssertionError(f"unexpected predicate: {predicate}")

    def _text_for_sql(self, sql: str) -> str:
        if "information_schema.tables" in sql:
            match = re.search(r"OFFSET\s+(\d+)", sql)
            index = int(match.group(1)) if match else 0
            return self.table_rows[index] if index < len(self.table_rows) else ""
        for expression, value in self.values.items():
            if expression in sql:
                return value
        return ""

    def _packed_codes(self, sql: str) -> int:
        value = self._text_for_sql(sql)
        packed = 0
        for part in sql.split(" UNION ALL "):
            weight_match = re.search(r"(\d+) AS weight", part)
            position_match = re.search(r",(\d+),1\)\) AS code", part)
            if not weight_match or not position_match:
                continue
            weight = int(weight_match.group(1))
            position = int(position_match.group(1))
            code = ord(value[position - 1]) if position <= len(value) else 0
            packed += code * weight
        return packed

    def _packed_lengths(self, sql: str) -> int:
        packed = 0
        for part in sql.split(" UNION ALL "):
            weight_match = re.search(r"(\d+) AS weight", part)
            if not weight_match:
                continue
            packed += len(self._text_for_sql(part)) * int(weight_match.group(1))
        return packed


class _NoSignalOracle:
    technique = "boolean"
    available = True
    request_count = 0
    trace = []

    def check(self, predicate: str) -> bool:
        self.request_count += 1
        return False


def test_blind_inference_engine_extracts_numbers_and_text() -> None:
    dialect = dialect_for_dbms("mysql")
    assert dialect is not None

    engine = BlindInferenceEngine(_DummyOracle("appdb", 3), dialect, max_workers=3)

    assert engine.infer_number("count_demo", upper_hint=2, max_value=10) == 3
    assert engine.infer_text("demo", max_length=16) == "appdb"


def test_blind_batch_char_codes_and_text_return_expected_characters() -> None:
    dialect = dialect_for_dbms("mysql")
    assert dialect is not None
    engine = BlindInferenceEngine(_PackedBatchOracle({"demo": "batched"}), dialect, max_workers=1)

    codes = engine.batch_char_codes_sql("demo", [1, 2, 3, 4, 5, 6, 7])

    assert codes == {index + 1: ord(char) for index, char in enumerate("batched")}
    assert engine.infer_text_batched("demo", max_length=16) == "batched"


def test_blind_batch_lengths_return_expected_rows() -> None:
    dialect = dialect_for_dbms("mysql")
    assert dialect is not None
    engine = BlindInferenceEngine(
        _PackedBatchOracle({"first_expr": "users", "second_expr": "audit_log"}),
        dialect,
        max_workers=1,
    )

    assert engine.batch_lengths_sql(["first_expr", "second_expr"]) == [5, 9]


def test_blind_batched_inference_handles_no_signal() -> None:
    dialect = dialect_for_dbms("mysql")
    assert dialect is not None
    engine = BlindInferenceEngine(_NoSignalOracle(), dialect, max_workers=1)

    assert engine.batch_char_codes_sql("demo", [1, 2, 3]) == {1: 0, 2: 0, 3: 0}
    assert engine.infer_text_batched("demo", max_length=16) == ""


def test_blind_table_enumeration_uses_batched_text_for_rows(monkeypatch) -> None:
    dialect = dialect_for_dbms("mysql")
    assert dialect is not None
    engine = BlindInferenceEngine(
        _PackedBatchOracle({}, table_rows=["users", "audit"]), dialect, max_workers=1
    )
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="mysql"))

    monkeypatch.setattr(
        "stealthix.extraction.blind.build_blind_engine", lambda *_args, **_kwargs: engine
    )

    result = enumerate_tables_blind(session, technique="boolean")

    assert result["success"] is True
    assert result["tables"] == ["users", "audit"]


def test_enumerate_databases_routes_to_blind_when_union_is_not_preferred(monkeypatch) -> None:
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="mysql"))
    session.metadata["detected_techniques"] = ["boolean"]

    monkeypatch.setattr(
        "stealthix.extraction.databases.enumerate_databases_blind",
        lambda _session, technique: {
            "target": "http://example.com",
            "operation": "databases",
            "payloads": ["blind:boolean"],
            "responses": [],
            "warnings": [],
            "success": True,
            "count": 1,
            "selected_payload": "blind:boolean",
            "technique": technique,
            "databases": ["blinddb"],
        },
    )

    result = enumerate_databases(session)

    assert result["success"] is True
    assert result["technique"] == "boolean"
    assert result["databases"] == ["blinddb"]


def test_couchdb_nosql_database_enumeration_parses_all_dbs(monkeypatch) -> None:
    session = ScanSession(SessionConfig(base_url="http://example.com/app", dbms="couchdb"))

    monkeypatch.setattr(
        "stealthix.extraction.nosql_extract._make_request",
        lambda _session, url, data=None, method=None: ('["users","audit"]', 0.02),
    )

    result = enumerate_databases_nosql(session)

    assert result["success"] is True
    assert sorted(result["databases"]) == ["audit", "users"]


def test_support_matrix_marks_mongodb_extraction_as_supported() -> None:
    entry = get_support_entry("mongodb")
    assert entry is not None
    assert entry["extraction"]["databases"] == "supported"
    assert entry["extraction"]["dump"] == "supported"
