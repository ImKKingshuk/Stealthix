use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
pub struct Fingerprint;

#[pymethods]
impl Fingerprint {
    #[new]
    fn new() -> Self {
        Self
    }

    fn fingerprint_dbms(&self, response: String) -> PyResult<String> {
        let hay = response.to_lowercase();
        // SQL engines
        if hay.contains("mysql") || hay.contains("com.mysql.jdbc") || hay.contains("mysql_fetch") {
            return Ok("MySQL".to_string());
        }
        if hay.contains("mariadb") {
            return Ok("MariaDB".to_string());
        }
        if hay.contains("postgres") || hay.contains("pg_query") || hay.contains("psycopg") || hay.contains("npgsql") {
            return Ok("PostgreSQL".to_string());
        }
        if hay.contains("oracle") || hay.contains("ora-") || hay.contains("oracle error") {
            return Ok("Oracle".to_string());
        }
        if hay.contains("microsoft sql") || hay.contains("mssql") || hay.contains("sqlsrv") || hay.contains("sql server") {
            return Ok("MSSQL".to_string());
        }
        if hay.contains("sqlite") || hay.contains("sqlite3") {
            return Ok("SQLite".to_string());
        }
        if hay.contains("db2") || hay.contains("ibm db2") || hay.contains("cli01") {
            return Ok("DB2".to_string());
        }
        if hay.contains("clickhouse") {
            return Ok("ClickHouse".to_string());
        }
        if hay.contains("snowflake") {
            return Ok("Snowflake".to_string());
        }
        if hay.contains("bigquery") {
            return Ok("BigQuery".to_string());
        }
        if hay.contains("duckdb") {
            return Ok("DuckDB".to_string());
        }
        if hay.contains("redshift") {
            return Ok("Redshift".to_string());
        }
        if hay.contains("greenplum") {
            return Ok("Greenplum".to_string());
        }
        if hay.contains("vertica") {
            return Ok("Vertica".to_string());
        }
        if hay.contains("firebird") || hay.contains("dynamic sql error") {
            return Ok("Firebird".to_string());
        }
        if hay.contains("sybase") || hay.contains("adaptive server") {
            return Ok("Sybase".to_string());
        }
        if hay.contains("informix") {
            return Ok("Informix".to_string());
        }
        if hay.contains("monetdb") {
            return Ok("MonetDB".to_string());
        }
        if hay.contains("h2") || hay.contains("org.h2.jdbc") {
            return Ok("H2".to_string());
        }
        if hay.contains("hsqldb") || hay.contains("org.hsqldb") {
            return Ok("HSQLDB".to_string());
        }
        if hay.contains("presto") {
            return Ok("Presto".to_string());
        }
        if hay.contains("trino") {
            return Ok("Trino".to_string());
        }
        // NoSQL engines
        if hay.contains("mongodb") || hay.contains("mongo") || hay.contains("bson") {
            return Ok("MongoDB".to_string());
        }
        if hay.contains("couchdb") {
            return Ok("CouchDB".to_string());
        }
        if hay.contains("redis") {
            return Ok("Redis".to_string());
        }
        if hay.contains("cassandra") || hay.contains("cql") {
            return Ok("Cassandra".to_string());
        }
        if hay.contains("dynamodb") {
            return Ok("DynamoDB".to_string());
        }
        if hay.contains("firebase") {
            return Ok("Firebase".to_string());
        }
        if hay.contains("arangodb") {
            return Ok("ArangoDB".to_string());
        }
        if hay.contains("couchbase") {
            return Ok("Couchbase".to_string());
        }
        if hay.contains("neo4j") || hay.contains("cypher") {
            return Ok("Neo4j".to_string());
        }
        if hay.contains("elasticsearch") {
            return Ok("Elasticsearch".to_string());
        }
        if hay.contains("opensearch") {
            return Ok("OpenSearch".to_string());
        }
        if hay.contains("solr") {
            return Ok("Solr".to_string());
        }
        if hay.contains("influxdb") {
            return Ok("InfluxDB".to_string());
        }
        if hay.contains("prometheus") {
            return Ok("Prometheus".to_string());
        }
        if hay.contains("cosmosdb") || hay.contains("cosmos") {
            return Ok("CosmosDB".to_string());
        }
        // NewSQL engines
        if hay.contains("cockroach") || hay.contains("cockroachdb") {
            return Ok("CockroachDB".to_string());
        }
        if hay.contains("tidb") {
            return Ok("TiDB".to_string());
        }
        if hay.contains("yugabyte") || hay.contains("yugabytedb") {
            return Ok("YugabyteDB".to_string());
        }
        if hay.contains("spanner") {
            return Ok("Spanner".to_string());
        }
        if hay.contains("singlestore") || hay.contains("memsql") {
            return Ok("SingleStore".to_string());
        }
        Ok("Unknown".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::Fingerprint;

    #[test]
    fn detects_mysql() {
        let fp = Fingerprint;
        let out = fp.fingerprint_dbms("MySQL error".to_string()).unwrap();
        assert_eq!(out, "MySQL");
    }
}
