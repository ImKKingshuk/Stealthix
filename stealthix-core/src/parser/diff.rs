use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
pub struct DiffAnalyzer;

#[pymethods]
impl DiffAnalyzer {
    #[new]
    fn new() -> Self {
        Self
    }

    fn length_diff(&self, a: String, b: String) -> PyResult<usize> {
        let la = a.len();
        let lb = b.len();
        if la > lb {
            Ok(la - lb)
        } else {
            Ok(lb - la)
        }
    }

    fn ratio_diff(&self, a: String, b: String) -> PyResult<f64> {
        let la = a.len() as f64;
        let lb = b.len() as f64;
        let denom = if la + lb == 0.0 { 1.0 } else { la + lb };
        Ok(((la - lb).abs()) / denom)
    }
}

#[cfg(test)]
mod tests {
    use super::DiffAnalyzer;

    #[test]
    fn computes_diff() {
        let analyzer = DiffAnalyzer;
        let diff = analyzer
            .length_diff("a".to_string(), "aaaa".to_string())
            .unwrap();
        assert_eq!(diff, 3);
    }
}
