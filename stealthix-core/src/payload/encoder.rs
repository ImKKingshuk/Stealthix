use base64::Engine;
use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
pub struct PayloadEncoder;

#[pymethods]
impl PayloadEncoder {
    #[new]
    fn new() -> Self {
        Self
    }

    fn url_encode(&self, payload: String) -> PyResult<String> {
        Ok(urlencoding::encode(&payload).into_owned())
    }

    fn double_url_encode(&self, payload: String) -> PyResult<String> {
        let once = urlencoding::encode(&payload).into_owned();
        Ok(urlencoding::encode(&once).into_owned())
    }

    fn base64_encode(&self, payload: String) -> PyResult<String> {
        Ok(base64::engine::general_purpose::STANDARD.encode(payload))
    }

    fn hex_encode(&self, payload: String) -> PyResult<String> {
        Ok(hex::encode(payload))
    }

    fn unicode_escape(&self, payload: String) -> PyResult<String> {
        let escaped = payload
            .chars()
            .map(|c| format!("\\u{:04x}", c as u32))
            .collect::<Vec<_>>()
            .join("");
        Ok(escaped)
    }

    fn case_shuffle(&self, payload: String) -> PyResult<String> {
        let mut upper = true;
        let mut out = String::with_capacity(payload.len());
        for ch in payload.chars() {
            if ch.is_ascii_alphabetic() {
                if upper {
                    out.push(ch.to_ascii_uppercase());
                } else {
                    out.push(ch.to_ascii_lowercase());
                }
                upper = !upper;
            } else {
                out.push(ch);
            }
        }
        Ok(out)
    }

    fn null_byte_inject(&self, payload: String) -> PyResult<String> {
        Ok(format!("{}%00", payload))
    }
}

#[cfg(test)]
mod tests {
    use super::PayloadEncoder;

    #[test]
    fn encodes_payloads() {
        let encoder = PayloadEncoder;
        assert_eq!(encoder.url_encode("a b".to_string()).unwrap(), "a%20b");
        assert_eq!(
            encoder.double_url_encode("a b".to_string()).unwrap(),
            "a%2520b"
        );
        assert_eq!(encoder.base64_encode("hi".to_string()).unwrap(), "aGk=");
        assert_eq!(encoder.hex_encode("hi".to_string()).unwrap(), "6869");
        assert_eq!(encoder.unicode_escape("A".to_string()).unwrap(), "\\u0041");
        assert_eq!(
            encoder.case_shuffle("select".to_string()).unwrap(),
            "SeLeCt"
        );
        assert_eq!(
            encoder.null_byte_inject("test".to_string()).unwrap(),
            "test%00"
        );
    }
}
