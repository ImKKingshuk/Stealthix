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
        if hay.contains("mysql") {
            return Ok("MySQL".to_string());
        }
        if hay.contains("postgres") {
            return Ok("PostgreSQL".to_string());
        }
        if hay.contains("oracle") {
            return Ok("Oracle".to_string());
        }
        if hay.contains("microsoft sql") || hay.contains("mssql") {
            return Ok("MSSQL".to_string());
        }
        if hay.contains("mongodb") {
            return Ok("MongoDB".to_string());
        }
        if hay.contains("couchdb") {
            return Ok("CouchDB".to_string());
        }
        if hay.contains("cockroach") {
            return Ok("CockroachDB".to_string());
        }
        if hay.contains("tidb") {
            return Ok("TiDB".to_string());
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
