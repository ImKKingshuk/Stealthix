use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
pub struct PayloadObfuscator;

#[pymethods]
impl PayloadObfuscator {
    #[new]
    fn new() -> Self {
        Self
    }

    fn comment_injection(&self, payload: String) -> PyResult<String> {
        Ok(payload.replace(" ", "/**/"))
    }

    fn whitespace_substitution(&self, payload: String) -> PyResult<String> {
        Ok(payload.replace(" ", "%09"))
    }

    fn keyword_splitting(&self, payload: String) -> PyResult<String> {
        let mut out = payload;
        for kw in ["SELECT", "UNION", "WHERE", "AND", "OR", "FROM"] {
            let replacement = format!("{}{}{}", &kw[0..1], "/**/", &kw[1..]);
            out = out.replace(kw, &replacement);
        }
        Ok(out)
    }

    fn version_specific(&self, payload: String) -> PyResult<String> {
        Ok(payload
            .replace("SELECT", "/*!50000SELECT*/")
            .replace("SeLeCt", "/*!50000SELECT*/")
            .replace("SE/**/LECT", "/*!50000SELECT*/")
            .replace("S/**/ELECT", "/*!50000SELECT*/"))
    }

    fn apply(&self, payload: String) -> PyResult<String> {
        let step1 = self.comment_injection(payload)?;
        let step2 = self.whitespace_substitution(step1)?;
        let step3 = self.keyword_splitting(step2)?;
        self.version_specific(step3)
    }
}

#[cfg(test)]
mod tests {
    use super::PayloadObfuscator;

    #[test]
    fn applies_obfuscation_steps() {
        let obfuscator = PayloadObfuscator;
        let out = obfuscator.apply("SELECT 1 FROM users".to_string()).unwrap();
        assert!(out.contains("/**/"));
        assert!(out.contains("/*!50000SELECT*/"));
    }
}
