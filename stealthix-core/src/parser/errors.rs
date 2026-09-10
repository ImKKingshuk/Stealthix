use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
pub struct ErrorMatcher;

#[pymethods]
impl ErrorMatcher {
    #[new]
    fn new() -> Self {
        Self
    }

    fn match_error(&self, response: String) -> PyResult<Vec<String>> {
        let hay = response.to_lowercase();
        let mut matches = Vec::new();
        for sig in [
            "mysql",
            "sql syntax",
            "postgres",
            "ora-",
            "oracle",
            "microsoft sql",
            "odbc",
            "sqlite",
            "couchdb",
            "mongodb",
            "tidb",
            "cockroach",
        ] {
            if hay.contains(sig) {
                matches.push(sig.to_string());
            }
        }
        Ok(matches)
    }
}

#[cfg(test)]
mod tests {
    use super::ErrorMatcher;

    #[test]
    fn matches_errors() {
        let matcher = ErrorMatcher;
        let out = matcher
            .match_error("MySQL error and postgres".to_string())
            .unwrap();
        assert!(out.contains(&"mysql".to_string()));
        assert!(out.contains(&"postgres".to_string()));
    }
}
