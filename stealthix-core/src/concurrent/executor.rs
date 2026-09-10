use pyo3::prelude::*;
use tokio::runtime::{Builder, Runtime};

#[pyclass(skip_from_py_object)]
pub struct Executor {
    runtime: Runtime,
    worker_threads: usize,
    queue_limit: usize,
}

#[pymethods]
impl Executor {
    #[new]
    #[pyo3(signature = (worker_threads=None, queue_limit=None))]
    fn new(worker_threads: Option<usize>, queue_limit: Option<usize>) -> PyResult<Self> {
        let resolved_threads = worker_threads
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(4)
            })
            .max(1);
        let runtime = Builder::new_multi_thread()
            .worker_threads(resolved_threads)
            .enable_all()
            .build()
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok(Self {
            runtime,
            worker_threads: resolved_threads,
            queue_limit: queue_limit.unwrap_or(4096).max(1),
        })
    }

    #[getter]
    fn worker_threads(&self) -> usize {
        self.worker_threads
    }

    #[getter]
    fn queue_limit(&self) -> usize {
        self.queue_limit
    }

    #[pyo3(signature = (items, concurrency=None))]
    fn run_cpu_lengths(
        &self,
        items: Vec<String>,
        concurrency: Option<usize>,
    ) -> PyResult<Vec<usize>> {
        if items.len() > self.queue_limit {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "task queue limit exceeded: {} > {}",
                items.len(),
                self.queue_limit
            )));
        }
        let concurrency = concurrency.unwrap_or(self.worker_threads).max(1);
        let fut = async move {
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
            let mut handles = Vec::with_capacity(items.len());
            for item in items {
                let permit = sem
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|e| e.to_string())?;
                handles.push(tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    item.len()
                }));
            }
            let mut results = Vec::new();
            for handle in handles {
                results.push(handle.await.map_err(|e| e.to_string())?);
            }
            Ok::<_, String>(results)
        };
        self.runtime
            .block_on(fut)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)
    }

    #[pyo3(signature = (items, concurrency=None))]
    fn dispatch_lengths(
        &self,
        items: Vec<String>,
        concurrency: Option<usize>,
    ) -> PyResult<Vec<usize>> {
        self.run_cpu_lengths(items, concurrency)
    }
}
