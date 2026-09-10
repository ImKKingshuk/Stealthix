use pyo3::prelude::*;
use regex::Regex;

#[pyclass(skip_from_py_object)]
pub struct Extractor;

#[pymethods]
impl Extractor {
    #[new]
    fn new() -> Self {
        Self
    }

    fn extract(&self, response: String, pattern: String) -> PyResult<Vec<String>> {
        let re = Regex::new(&pattern)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        let mut results = Vec::new();
        for cap in re.captures_iter(&response) {
            if let Some(m) = cap.get(1) {
                results.push(m.as_str().to_string());
            } else if let Some(m) = cap.get(0) {
                results.push(m.as_str().to_string());
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::Extractor;

    #[test]
    fn extracts_matches() {
        let extractor = Extractor;
        let out = extractor
            .extract(
                "user=alice user=bob".to_string(),
                "user=([a-z]+)".to_string(),
            )
            .unwrap();
        assert_eq!(out, vec!["alice".to_string(), "bob".to_string()]);
    }
}
