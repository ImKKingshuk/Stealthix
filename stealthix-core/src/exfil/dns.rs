use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
pub struct DnsExfil;

#[pymethods]
impl DnsExfil {
    #[new]
    fn new() -> Self {
        Self
    }

    fn encode_subdomain(&self, data: String) -> PyResult<String> {
        let cleaned = data
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect::<String>()
            .to_lowercase();
        let mut chunks = Vec::new();
        let mut start = 0;
        while start < cleaned.len() {
            let end = (start + 50).min(cleaned.len());
            chunks.push(cleaned[start..end].to_string());
            start = end;
        }
        Ok(chunks.join("."))
    }
}

#[cfg(test)]
mod tests {
    use super::DnsExfil;

    #[test]
    fn encodes_subdomain() {
        let exfil = DnsExfil;
        let out = exfil.encode_subdomain("HelloWorld".to_string()).unwrap();
        assert_eq!(out, "helloworld");
    }
}
