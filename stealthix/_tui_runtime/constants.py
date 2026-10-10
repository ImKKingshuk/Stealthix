def _get_supported_dbms() -> list[str]:
    dbms_list = ["auto"]
    seen = {"auto"}
    try:
        from stealthix.plugins import all_plugins

        for p in all_plugins():
            name = getattr(p, "dbms", None) or getattr(p, "name", None)
            if name and name.lower() not in seen:
                seen.add(name.lower())
                dbms_list.append(name.lower())
    except Exception:
        fallback = [
            "mysql",
            "postgresql",
            "mssql",
            "oracle",
            "sqlite",
            "mariadb",
            "db2",
            "mongodb",
            "couchdb",
            "cassandra",
            "dynamodb",
            "redis",
            "cockroachdb",
            "tidb",
            "yugabytedb",
            "spanner",
        ]
        dbms_list.extend(fallback)
    return dbms_list


SUPPORTED_DBMS = _get_supported_dbms()

SUPPORTED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]
SUPPORTED_REPORT_FORMATS = ["json", "markdown", "html", "pdf", "sarif", "junit", "csv"]
