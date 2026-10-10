use pyo3::prelude::*;
use regex::Regex;
use std::sync::LazyLock;

static WAF_RULES: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    vec![
        ("cloudflare", Regex::new(r"cloudflare|cf-ray|cf-cache-status").unwrap()),
        ("modsecurity", Regex::new(r"modsecurity|mod_security").unwrap()),
        ("akamai", Regex::new(r"akamai|akamai-ghost").unwrap()),
        ("imperva", Regex::new(r"imperva|incapsula").unwrap()),
        (
            "sucuri",
            Regex::new(r"sucuri|x-sucuri|sucuri/cloudproxy|access denied - sucuri website firewall").unwrap(),
        ),
        ("f5", Regex::new(r"big-ip|f5").unwrap()),
        (
            "awswaf",
            Regex::new(r"aws.?waf|x-amzn-requestid|x-amzn-trace-id|x-amzn-errortype|x-amz-cf-id|x-amz-cf-pop|cloudfront|the request could not be satisfied|request blocked").unwrap(),
        ),
        (
            "fastly",
            Regex::new(r"fastly|x-served-by|x-cache-hits|x-fastly-request-id").unwrap(),
        ),
        ("barracuda", Regex::new(r"barracuda").unwrap()),
        ("fortinet", Regex::new(r"fortiweb|fortinet").unwrap()),
        ("radware", Regex::new(r"radware|appwall").unwrap()),
        ("stackpath", Regex::new(r"stackpath|x-cdn").unwrap()),
        ("azure", Regex::new(r"azure|x-azure-ref").unwrap()),
    ]
});

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
        for (name, re) in WAF_RULES.iter() {
            if re.is_match(&hay) {
                detected.push((*name).to_string());
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
