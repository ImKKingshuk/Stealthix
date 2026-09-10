use pyo3::prelude::*;

#[pyclass(skip_from_py_object)]
pub struct RateLimiter {
    base_delay_ms: u64,
    jitter_ms: u64,
    max_delay_ms: u64,
    attempt: u32,
}

#[pymethods]
impl RateLimiter {
    #[new]
    fn new(base_delay_ms: u64, jitter_ms: u64, max_delay_ms: u64) -> Self {
        Self {
            base_delay_ms,
            jitter_ms,
            max_delay_ms,
            attempt: 0,
        }
    }

    fn next_delay_ms(&mut self) -> u64 {
        let backoff = self
            .base_delay_ms
            .saturating_mul(2u64.saturating_pow(self.attempt));
        let jitter = (self.attempt as u64 % 10) * self.jitter_ms;
        self.attempt = self.attempt.saturating_add(1);
        let delay = backoff.saturating_add(jitter);
        delay.min(self.max_delay_ms)
    }

    fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;

    #[test]
    fn increases_delay() {
        let mut rl = RateLimiter::new(10, 1, 100);
        let first = rl.next_delay_ms();
        let second = rl.next_delay_ms();
        assert!(second >= first);
        rl.reset();
        let reset = rl.next_delay_ms();
        assert!(reset <= second);
    }
}
