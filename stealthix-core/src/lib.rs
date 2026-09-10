use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};
use pyo3::IntoPyObjectExt;
use serde_json::{Map, Number, Value};

mod concurrent;
mod exfil;
mod http;
mod parser;
mod payload;

use concurrent::executor::Executor;
use exfil::dns::DnsExfil;
use http::client::HttpClient;
use http::pool::{AdaptivePoolConfig, AdaptivePoolState, PoolConfig, ResponseMetrics};
use http::ratelimit::RateLimiter;
use parser::diff::DiffAnalyzer;
use parser::errors::ErrorMatcher;
use parser::extractor::Extractor;
use parser::fingerprint::Fingerprint;
use parser::timing::TimingAnalyzer;
use parser::waf::WafDetector;
use payload::cloudflare::CloudflareBypass;
use payload::encoder::PayloadEncoder;
use payload::modsec::ModSecurityBypass;
use payload::obfuscator::PayloadObfuscator;

fn json_to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    match value {
        Value::Null => Ok(py.None().into_bound(py)),
        Value::Bool(v) => (*v).into_bound_py_any(py),
        Value::Number(v) => {
            if let Some(i) = v.as_i64() {
                i.into_bound_py_any(py)
            } else if let Some(u) = v.as_u64() {
                u.into_bound_py_any(py)
            } else if let Some(f) = v.as_f64() {
                f.into_bound_py_any(py)
            } else {
                Err(PyTypeError::new_err("unsupported numeric value"))
            }
        }
        Value::String(v) => v.as_str().into_bound_py_any(py),
        Value::Array(values) => {
            let items: Vec<Bound<'_, PyAny>> = values
                .iter()
                .map(|item| json_to_py(py, item))
                .collect::<PyResult<Vec<_>>>()?;
            Ok(PyList::new(py, items)?.into_any())
        }
        Value::Object(values) => {
            let dict = PyDict::new(py);
            for (key, item) in values {
                dict.set_item(key, json_to_py(py, item)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

fn py_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    if value.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(v) = value.extract::<bool>() {
        return Ok(Value::Bool(v));
    }
    if let Ok(v) = value.extract::<i64>() {
        return Ok(Value::Number(Number::from(v)));
    }
    if let Ok(v) = value.extract::<u64>() {
        return Ok(Value::Number(Number::from(v)));
    }
    if let Ok(v) = value.extract::<f64>() {
        return Ok(Number::from_f64(v)
            .map(Value::Number)
            .unwrap_or(Value::Null));
    }
    if let Ok(v) = value.extract::<String>() {
        return Ok(Value::String(v));
    }
    if let Ok(list) = value.cast::<PyList>() {
        let items = list
            .iter()
            .map(|item| py_to_json(&item))
            .collect::<PyResult<Vec<_>>>()?;
        return Ok(Value::Array(items));
    }
    if let Ok(tuple) = value.cast::<PyTuple>() {
        let items = tuple
            .iter()
            .map(|item| py_to_json(&item))
            .collect::<PyResult<Vec<_>>>()?;
        return Ok(Value::Array(items));
    }
    if let Ok(dict) = value.cast::<PyDict>() {
        let mut out = Map::new();
        for (key, item) in dict.iter() {
            out.insert(key.extract::<String>()?, py_to_json(&item)?);
        }
        return Ok(Value::Object(out));
    }
    Ok(Value::String(value.repr()?.to_string()))
}

#[pyfunction]
fn run_tui(callback: Py<PyAny>) -> PyResult<()> {
    stealthix_tui::run_tui(move |action, params| {
        Python::attach(|py| {
            let py_params = json_to_py(py, &params)?;
            let result = callback.call1(py, (action.to_string(), py_params))?;
            py_to_json(result.bind(py))
        })
        .map_err(|err| err.to_string())
    })
    .map_err(|err| PyRuntimeError::new_err(err.to_string()))
}

#[pymodule]
fn stealthix_core(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<HttpClient>()?;
    m.add_class::<PoolConfig>()?;
    m.add_class::<AdaptivePoolConfig>()?;
    m.add_class::<AdaptivePoolState>()?;
    m.add_class::<ResponseMetrics>()?;
    m.add_class::<PayloadEncoder>()?;
    m.add_class::<PayloadObfuscator>()?;
    m.add_class::<CloudflareBypass>()?;
    m.add_class::<ModSecurityBypass>()?;
    m.add_class::<Fingerprint>()?;
    m.add_class::<DnsExfil>()?;
    m.add_class::<TimingAnalyzer>()?;
    m.add_class::<ErrorMatcher>()?;
    m.add_class::<DiffAnalyzer>()?;
    m.add_class::<WafDetector>()?;
    m.add_class::<Extractor>()?;
    m.add_class::<Executor>()?;
    m.add_class::<RateLimiter>()?;
    m.add_function(wrap_pyfunction!(run_tui, m)?)?;

    let tamper_module = PyModule::new(py, "tamper")?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::apply_tamper,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::apply_tamper_sequence,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::list_tamper_scripts,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_reverse,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_inline_comment,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_space2comment,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_space2plus,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_space2tab,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_randomcase,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_between,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_union_all,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_eq2like,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_utf8,
        &tamper_module
    )?)?;
    tamper_module.add_function(wrap_pyfunction!(
        payload::tamper::tamper_charencode,
        &tamper_module
    )?)?;
    m.add_submodule(&tamper_module)?;

    Ok(())
}
