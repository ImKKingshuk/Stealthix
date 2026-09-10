use pyo3::prelude::*;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

#[pyclass(skip_from_py_object)]
#[derive(Clone, Debug)]
pub struct ResponseMetrics {
    #[pyo3(get)]
    pub p50_ms: u64,
    #[pyo3(get)]
    pub p95_ms: u64,
    #[pyo3(get)]
    pub p99_ms: u64,
    #[pyo3(get)]
    pub error_rate: f64,
    #[pyo3(get)]
    pub sample_count: usize,
}

#[pymethods]
impl ResponseMetrics {
    #[new]
    fn new(p50_ms: u64, p95_ms: u64, p99_ms: u64, error_rate: f64, sample_count: usize) -> Self {
        Self {
            p50_ms,
            p95_ms,
            p99_ms,
            error_rate: error_rate.clamp(0.0, 1.0),
            sample_count,
        }
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone, Debug)]
pub struct PoolConfig {
    #[pyo3(get)]
    pub max_idle: usize,
    #[pyo3(get)]
    pub idle_timeout_secs: u64,
}

#[pymethods]
impl PoolConfig {
    #[new]
    fn new(max_idle: usize, idle_timeout_secs: u64) -> Self {
        Self {
            max_idle: max_idle.max(1),
            idle_timeout_secs,
        }
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone, Debug)]
pub struct AdaptivePoolConfig {
    #[pyo3(get)]
    pub min_size: usize,
    #[pyo3(get)]
    pub max_size: usize,
    #[pyo3(get)]
    pub target_p95_ms: u64,
    #[pyo3(get)]
    pub scale_up_threshold: f64,
    #[pyo3(get)]
    pub scale_down_threshold: f64,
    #[pyo3(get)]
    pub adaptive: bool,
    #[pyo3(get)]
    pub cooldown_secs: u64,
    #[pyo3(get)]
    pub sample_window: usize,
}

#[pymethods]
impl AdaptivePoolConfig {
    #[new]
    #[pyo3(signature = (
        min_size = 1,
        max_size = 32,
        target_p95_ms = 750,
        scale_up_threshold = 1.25,
        scale_down_threshold = 0.55,
        adaptive = true,
        cooldown_secs = 5,
        sample_window = 128
    ))]
    fn new(
        min_size: usize,
        max_size: usize,
        target_p95_ms: u64,
        scale_up_threshold: f64,
        scale_down_threshold: f64,
        adaptive: bool,
        cooldown_secs: u64,
        sample_window: usize,
    ) -> Self {
        let min_size = min_size.max(1);
        let max_size = max_size.max(min_size);
        Self {
            min_size,
            max_size,
            target_p95_ms: target_p95_ms.max(1),
            scale_up_threshold: scale_up_threshold.max(1.0),
            scale_down_threshold: scale_down_threshold.clamp(0.0, 1.0),
            adaptive,
            cooldown_secs,
            sample_window: sample_window.max(8),
        }
    }
}

#[pyclass(skip_from_py_object)]
pub struct AdaptivePoolState {
    config: AdaptivePoolConfig,
    current_size: usize,
    samples: VecDeque<(u64, bool)>,
    last_scaled_at: Option<Instant>,
}

#[pymethods]
impl AdaptivePoolState {
    #[new]
    #[pyo3(signature = (
        min_size = 1,
        max_size = 32,
        target_p95_ms = 750,
        scale_up_threshold = 1.25,
        scale_down_threshold = 0.55,
        adaptive = true,
        cooldown_secs = 5,
        sample_window = 128
    ))]
    fn new(
        min_size: usize,
        max_size: usize,
        target_p95_ms: u64,
        scale_up_threshold: f64,
        scale_down_threshold: f64,
        adaptive: bool,
        cooldown_secs: u64,
        sample_window: usize,
    ) -> Self {
        Self::from_config(AdaptivePoolConfig::new(
            min_size,
            max_size,
            target_p95_ms,
            scale_up_threshold,
            scale_down_threshold,
            adaptive,
            cooldown_secs,
            sample_window,
        ))
    }

    #[getter]
    fn current_size(&self) -> usize {
        self.current_size
    }

    fn record_response(&mut self, elapsed_ms: u64, success: bool) -> ResponseMetrics {
        if self.samples.len() >= self.config.sample_window {
            self.samples.pop_front();
        }
        self.samples.push_back((elapsed_ms, success));
        self.metrics()
    }

    fn metrics(&self) -> ResponseMetrics {
        if self.samples.is_empty() {
            return ResponseMetrics::new(0, 0, 0, 0.0, 0);
        }
        let mut latencies = self
            .samples
            .iter()
            .map(|(latency, _success)| *latency)
            .collect::<Vec<_>>();
        latencies.sort_unstable();
        let sample_count = latencies.len();
        let error_count = self
            .samples
            .iter()
            .filter(|(_latency, success)| !success)
            .count();
        ResponseMetrics::new(
            percentile(&latencies, 0.50),
            percentile(&latencies, 0.95),
            percentile(&latencies, 0.99),
            error_count as f64 / sample_count as f64,
            sample_count,
        )
    }

    fn recommend_size(&mut self) -> usize {
        if !self.config.adaptive || self.samples.len() < 4 {
            return self.current_size;
        }
        if let Some(last_scaled_at) = self.last_scaled_at {
            if last_scaled_at.elapsed() < Duration::from_secs(self.config.cooldown_secs) {
                return self.current_size;
            }
        }

        let metrics = self.metrics();
        let target = self.config.target_p95_ms as f64;
        let p95 = metrics.p95_ms as f64;
        let should_scale_up =
            p95 > target * self.config.scale_up_threshold || metrics.error_rate > 0.10;
        let should_scale_down =
            p95 < target * self.config.scale_down_threshold && metrics.error_rate == 0.0;

        let next_size = if should_scale_up {
            (self.current_size + 1).min(self.config.max_size)
        } else if should_scale_down {
            self.current_size
                .saturating_sub(1)
                .max(self.config.min_size)
        } else {
            self.current_size
        };

        if next_size != self.current_size {
            self.current_size = next_size;
            self.last_scaled_at = Some(Instant::now());
        }
        self.current_size
    }
}

impl AdaptivePoolState {
    fn from_config(config: AdaptivePoolConfig) -> Self {
        Self {
            current_size: config.min_size,
            config,
            samples: VecDeque::new(),
            last_scaled_at: None,
        }
    }
}

fn percentile(sorted_values: &[u64], quantile: f64) -> u64 {
    if sorted_values.is_empty() {
        return 0;
    }
    let index = ((sorted_values.len() - 1) as f64 * quantile)
        .round()
        .clamp(0.0, (sorted_values.len() - 1) as f64) as usize;
    sorted_values[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_response_metrics() {
        let mut state = AdaptivePoolState::from_config(AdaptivePoolConfig::new(
            1, 8, 100, 1.25, 0.5, true, 0, 16,
        ));
        for latency in [10, 20, 30, 40, 50] {
            state.record_response(latency, true);
        }
        let metrics = state.metrics();
        assert_eq!(metrics.sample_count, 5);
        assert_eq!(metrics.p50_ms, 30);
        assert_eq!(metrics.p95_ms, 50);
        assert_eq!(metrics.error_rate, 0.0);
    }

    #[test]
    fn recommends_larger_pool_for_slow_or_erroring_responses() {
        let mut state = AdaptivePoolState::from_config(AdaptivePoolConfig::new(
            1, 4, 100, 1.25, 0.5, true, 0, 16,
        ));
        for _ in 0..4 {
            state.record_response(200, false);
        }
        assert_eq!(state.recommend_size(), 2);
    }
}
