use pyo3::prelude::*;
use reqwest::cookie::{CookieStore, Jar};
use reqwest::{Client, Method, Response, Url};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;

#[derive(Debug)]
struct HttpResponseEnvelope {
    status_code: u16,
    headers: HashMap<String, String>,
    body: String,
    final_url: String,
}

static RESPONSE_CLS: std::sync::LazyLock<Py<PyAny>> = std::sync::LazyLock::new(|| {
    Python::attach(|py| {
        let code = CString::new(
            r#"
class _StealthixHttpResponse(str):
    def __new__(cls, body, status_code, headers, final_url):
        obj = str.__new__(cls, body)
        obj.body = body
        obj.text = body
        obj.status_code = status_code
        obj.headers = headers
        obj.final_url = final_url
        return obj

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __getitem__(self, key):
        if isinstance(key, str) and key in {"body", "text", "status_code", "headers", "final_url"}:
            return getattr(self, key)
        return super().__getitem__(key)
"#,
        )
        .expect("embedded Python source should not contain null bytes");
        let module = PyModule::from_code(
            py,
            &code,
            &CString::new("response.py").unwrap(),
            &CString::new("response").unwrap(),
        )
        .expect("should create response module");
        module
            .getattr("_StealthixHttpResponse")
            .expect("should get class")
            .unbind()
    })
});

impl HttpResponseEnvelope {
    fn into_py<'py>(self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let cls = RESPONSE_CLS.bind(py);
        cls.call1((self.body, self.status_code, self.headers, self.final_url))
    }
}

fn method_supports_body(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

async fn response_envelope(resp: Response) -> Result<HttpResponseEnvelope, String> {
    let status_code = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let headers = resp
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let body = resp.text().await.map_err(|e| e.to_string())?;

    Ok(HttpResponseEnvelope {
        status_code,
        headers,
        body,
        final_url,
    })
}

#[pyclass(skip_from_py_object)]
pub struct HttpClient {
    client: Client,
    runtime: Runtime,
    jar: Arc<Jar>,
}

#[pymethods]
impl HttpClient {
    #[new]
    fn new(
        proxy: Option<String>,
        timeout: Option<f64>,
        verify_tls: Option<bool>,
    ) -> PyResult<Self> {
        let jar = Arc::new(Jar::default());
        let mut builder = Client::builder()
            .pool_idle_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs_f64(timeout.unwrap_or(20.0)))
            .cookie_provider(jar.clone());
        if let Some(proxy_url) = proxy {
            builder = builder.proxy(
                reqwest::Proxy::all(proxy_url)
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?,
            );
        }
        if let Some(false) = verify_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let client = builder
            .build()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        let runtime =
            Runtime::new().map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self {
            client,
            runtime,
            jar,
        })
    }

    fn request(
        &self,
        method: String,
        url: String,
        headers: HashMap<String, String>,
        cookies: HashMap<String, String>,
        body: String,
    ) -> PyResult<Py<PyAny>> {
        let client = self.client.clone();
        let jar = self.jar.clone();
        let fut = async move {
            let parsed = Url::parse(&url).map_err(|e| e.to_string())?;
            for (k, v) in cookies {
                jar.add_cookie_str(&format!("{}={}", k, v), &parsed);
            }
            let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
            let mut req = client.request(method.clone(), url);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            if method_supports_body(&method) && !body.is_empty() {
                req = req.body(body);
            }
            let resp = req.send().await.map_err(|e| e.to_string())?;
            response_envelope(resp).await
        };
        let response = self
            .runtime
            .block_on(fut)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Python::attach(|py| response.into_py(py).map(|item| item.unbind()))
    }

    fn set_cookies(&self, url: String, cookies: HashMap<String, String>) -> PyResult<()> {
        let jar = self.jar.clone();
        let parsed =
            Url::parse(&url).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        for (k, v) in cookies {
            jar.add_cookie_str(&format!("{}={}", k, v), &parsed);
        }
        Ok(())
    }

    fn cookies_for(&self, url: String) -> PyResult<String> {
        let parsed =
            Url::parse(&url).map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
        if let Some(val) = self.jar.cookies(&parsed) {
            return Ok(val.to_str().unwrap_or("").to_string());
        }
        Ok(String::new())
    }

    fn batch_request(&self, urls: Vec<String>, concurrency: usize) -> PyResult<Vec<Py<PyAny>>> {
        let client = self.client.clone();
        let fut = async move {
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
            let mut handles = Vec::with_capacity(urls.len());
            for url in urls {
                let permit = sem
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|e| e.to_string())?;
                let client = client.clone();
                let req_url = url.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    match client.get(&req_url).send().await {
                        Ok(resp) => response_envelope(resp).await,
                        Err(err) => Ok(HttpResponseEnvelope {
                            status_code: 0,
                            headers: HashMap::new(),
                            body: format!("Error: {err}"),
                            final_url: req_url,
                        }),
                    }
                }));
            }
            let mut results = Vec::new();
            for handle in handles {
                match handle.await {
                    Ok(Ok(envelope)) => results.push(envelope),
                    Ok(Err(err)) => results.push(HttpResponseEnvelope {
                        status_code: 0,
                        headers: HashMap::new(),
                        body: format!("Error: {err}"),
                        final_url: String::new(),
                    }),
                    Err(join_err) => results.push(HttpResponseEnvelope {
                        status_code: 0,
                        headers: HashMap::new(),
                        body: format!("Task error: {join_err}"),
                        final_url: String::new(),
                    }),
                }
            }
            Ok::<_, String>(results)
        };
        let responses = self
            .runtime
            .block_on(fut)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Python::attach(|py| {
            responses
                .into_iter()
                .map(|response| response.into_py(py).map(|item| item.unbind()))
                .collect()
        })
    }

    fn async_request<'py>(
        &self,
        py: Python<'py>,
        method: String,
        url: String,
        headers: HashMap<String, String>,
        cookies: HashMap<String, String>,
        body: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.client.clone();
        let jar = self.jar.clone();
        let fut = async move {
            let parsed = Url::parse(&url)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            for (k, v) in cookies {
                jar.add_cookie_str(&format!("{}={}", k, v), &parsed);
            }
            let method = Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET);
            let mut req = client.request(method.clone(), url);
            for (k, v) in headers {
                req = req.header(k, v);
            }
            if method_supports_body(&method) && !body.is_empty() {
                req = req.body(body);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
            let envelope = response_envelope(resp)
                .await
                .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
            Python::attach(|py| envelope.into_py(py).map(|item| item.unbind()))
        };
        pyo3_async_runtimes::tokio::future_into_py(py, fut)
    }

    fn async_get<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: HashMap<String, String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.async_request(
            py,
            "GET".to_string(),
            url,
            headers,
            HashMap::new(),
            String::new(),
        )
    }

    fn async_post<'py>(
        &self,
        py: Python<'py>,
        url: String,
        headers: HashMap<String, String>,
        body: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.async_request(py, "POST".to_string(), url, headers, HashMap::new(), body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_supports_body_for_all_configured_body_methods() {
        assert!(method_supports_body(&Method::POST));
        assert!(method_supports_body(&Method::PUT));
        assert!(method_supports_body(&Method::PATCH));
        assert!(method_supports_body(&Method::DELETE));
        assert!(!method_supports_body(&Method::GET));
        assert!(!method_supports_body(&Method::HEAD));
    }

    #[test]
    fn response_envelope_exports_body_text_and_metadata() {
        Python::initialize();
        Python::attach(|py| {
            let response = HttpResponseEnvelope {
                status_code: 202,
                headers: HashMap::from([("content-type".to_string(), "text/plain".to_string())]),
                body: "accepted".to_string(),
                final_url: "https://example.test/final".to_string(),
            };

            let response = response
                .into_py(py)
                .expect("response should convert to python")
                .unbind();
            let response = response.bind(py);

            assert_eq!(response.extract::<String>().unwrap(), "accepted");
            assert_eq!(
                response
                    .getattr("status_code")
                    .unwrap()
                    .extract::<u16>()
                    .unwrap(),
                202
            );
            assert_eq!(
                response
                    .getattr("body")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "accepted"
            );
            assert_eq!(
                response
                    .getattr("text")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "accepted"
            );
            assert_eq!(
                response
                    .getattr("final_url")
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "https://example.test/final"
            );
            assert_eq!(
                response
                    .get_item("status_code")
                    .unwrap()
                    .extract::<u16>()
                    .unwrap(),
                202
            );
            let headers = response
                .getattr("headers")
                .unwrap()
                .cast_into::<PyDict>()
                .expect("headers should be a dict");
            assert_eq!(
                headers
                    .get_item("content-type")
                    .unwrap()
                    .unwrap()
                    .extract::<String>()
                    .unwrap(),
                "text/plain"
            );
        });
    }
}
