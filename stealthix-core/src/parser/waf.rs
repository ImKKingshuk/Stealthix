use pyo3::prelude::*;
use regex::Regex;

#[pyclass(skip_from_py_object)]
pub struct WafDetector;

#[pymethods]
impl WafDetector {
    #[new]
    fn new() -> Self {
        Self
    }

    fn detect(&self, response: String, headers: Vec<String>) -> PyResult<Vec<String>> {
        let mut detected = Vec::new();
        let hay = response.to_lowercase();
        let rules = vec![
            ("cloudflare", r"cloudflare|cf-ray|cf-cache-status"),
            ("modsecurity", r"modsecurity|mod_security"),
            ("akamai", r"akamai|akamai-ghost"),
            ("imperva", r"imperva|incapsula"),
            (
                "sucuri",
                r"sucuri|x-sucuri|sucuri/cloudproxy|access denied - sucuri website firewall",
            ),
            ("f5", r"big-ip|f5"),
            (
                "awswaf",
                r"aws.?waf|x-amzn-requestid|x-amzn-trace-id|x-amzn-errortype|x-amz-cf-id|x-amz-cf-pop|cloudfront|the request could not be satisfied|request blocked",
            ),
            (
                "fastly",
                r"fastly|x-served-by|x-cache-hits|x-fastly-request-id",
            ),
            ("barracuda", r"barracuda"),
            ("fortinet", r"fortiweb|fortinet"),
            ("radware", r"radware|appwall"),
            ("stackpath", r"stackpath|x-cdn"),
            ("azure", r"azure|x-azure-ref"),
        ];
        for (name, pattern) in rules {
            let re = Regex::new(pattern)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            if re.is_match(&hay) {
                detected.push(name.to_string());
            }
        }
        for header in headers {
            let header_lower = header.to_lowercase();
            if header_lower.contains("cf-ray") || header_lower.contains("cloudflare") {
                detected.push("cloudflare".to_string());
            }
            if header_lower.contains("modsecurity") {
                detected.push("modsecurity".to_string());
            }
            if header_lower.contains("x-amzn-requestid") || header_lower.contains("x-amzn-trace-id")
            {
                detected.push("awswaf".to_string());
            }
            if header_lower.contains("x-amz-cf-id") || header_lower.contains("x-amz-cf-pop") {
                detected.push("awswaf".to_string());
            }
            if header_lower.contains("x-fastly-request-id") || header_lower.contains("fastly") {
                detected.push("fastly".to_string());
            }
            if header_lower.contains("x-sucuri") || header_lower.contains("sucuri") {
                detected.push("sucuri".to_string());
            }
        }
        detected.sort();
        detected.dedup();
        Ok(detected)
    }
}

#[cfg(test)]
mod tests {
    use super::WafDetector;

    #[test]
    fn detects_cloudflare() {
        let detector = WafDetector;
        let out = detector
            .detect("cf-ray".to_string(), vec!["cf-ray: 1".to_string()])
            .unwrap();
        assert!(out.contains(&"cloudflare".to_string()));
    }

    #[test]
    fn detects_aws_waf() {
        let detector = WafDetector;
        let out = detector
            .detect(
                "request blocked".to_string(),
                vec!["x-amzn-trace-id: 1".to_string()],
            )
            .unwrap();
        assert!(out.contains(&"awswaf".to_string()));
    }

    #[test]
    fn detects_sucuri() {
        let detector = WafDetector;
        let out = detector
            .detect(
                "access denied - sucuri website firewall".to_string(),
                vec!["x-sucuri-id: 1".to_string()],
            )
            .unwrap();
        assert!(out.contains(&"sucuri".to_string()));
    }

    #[test]
    fn detects_cloudfront_via_headers() {
        let detector = WafDetector;
        let out = detector
            .detect("blocked".to_string(), vec!["x-amz-cf-id: 1".to_string()])
            .unwrap();
        assert!(out.contains(&"awswaf".to_string()));
    }
}
