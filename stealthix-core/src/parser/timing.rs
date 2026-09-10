use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
pub struct TimingAnalyzer;

#[pymethods]
impl TimingAnalyzer {
    #[new]
    fn new() -> Self {
        Self
    }

    fn mean(&self, samples: Vec<f64>) -> PyResult<f64> {
        if samples.is_empty() {
            return Ok(0.0);
        }
        let sum: f64 = samples.iter().sum();
        Ok(sum / samples.len() as f64)
    }

    fn stdev(&self, samples: Vec<f64>) -> PyResult<f64> {
        if samples.len() <= 1 {
            return Ok(0.0);
        }
        let mean = self.mean(samples.clone())?;
        let variance =
            samples.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / samples.len() as f64;
        Ok(variance.sqrt())
    }

    fn is_outlier(&self, sample: f64, mean: f64, stdev: f64) -> PyResult<bool> {
        if stdev <= 0.0 {
            return Ok(sample > mean + 1.0);
        }
        Ok(sample > mean + 3.0 * stdev)
    }
}

#[cfg(test)]
mod tests {
    use super::TimingAnalyzer;

    #[test]
    fn detects_outlier() {
        let analyzer = TimingAnalyzer;
        let mean = analyzer.mean(vec![0.5, 0.6, 0.7]).unwrap();
        let stdev = analyzer.stdev(vec![0.5, 0.6, 0.7]).unwrap();
        assert!(!analyzer.is_outlier(0.7, mean, stdev).unwrap());
        assert!(analyzer.is_outlier(5.0, mean, stdev).unwrap());
    }
}
