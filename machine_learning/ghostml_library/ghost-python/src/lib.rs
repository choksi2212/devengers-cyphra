//! Python bindings for GhostML - Pure Rust ML library
//! Allows Python scripts to use GhostML without any external ML dependencies

use pyo3::prelude::*;
use pyo3::types::PyModule;
use pyo3::Bound;
use numpy::{PyArray1, PyArray2, PyReadonlyArray1, PyReadonlyArray2};
use ghost_core::metrics::Metrics;
use ghost_preprocessing::*;
use ghost_sampling::*;
use ghost_trees::*;
use ghost_ensemble::*;
use ghost_neural::*;

/// StandardScaler wrapper for Python
#[pyclass]
struct PyStandardScaler {
    scaler: StandardScaler,
}

#[pymethods]
impl PyStandardScaler {
    #[new]
    fn new() -> Self {
        Self { scaler: StandardScaler::new() }
    }
    
    fn fit(&mut self, X: PyReadonlyArray2<f64>) -> PyResult<()> {
        let X_array = X.as_array().to_owned();
        self.scaler.fit(&X_array).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(())
    }
    
    fn transform<'py>(&self, py: Python<'py>, X: PyReadonlyArray2<f64>) -> PyResult<Bound<'py, PyArray2<f64>>> {
        let X_array = X.as_array().to_owned();
        let result = self.scaler.transform(&X_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(PyArray2::from_owned_array_bound(py, result))
    }
    
    fn fit_transform<'py>(&mut self, py: Python<'py>, X: PyReadonlyArray2<f64>) -> PyResult<Bound<'py, PyArray2<f64>>> {
        let X_array = X.as_array().to_owned();
        let result = self.scaler.fit_transform(&X_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(PyArray2::from_owned_array_bound(py, result))
    }
}

/// RobustScaler wrapper for Python
#[pyclass]
struct PyRobustScaler {
    scaler: RobustScaler,
}

#[pymethods]
impl PyRobustScaler {
    #[new]
    fn new() -> Self {
        Self { scaler: RobustScaler::new() }
    }
    
    fn fit(&mut self, X: PyReadonlyArray2<f64>) -> PyResult<()> {
        let X_array = X.as_array().to_owned();
        self.scaler.fit(&X_array).map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(())
    }
    
    fn transform<'py>(&self, py: Python<'py>, X: PyReadonlyArray2<f64>) -> PyResult<Bound<'py, PyArray2<f64>>> {
        let X_array = X.as_array().to_owned();
        let result = self.scaler.transform(&X_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(PyArray2::from_owned_array_bound(py, result))
    }
    
    fn fit_transform<'py>(&mut self, py: Python<'py>, X: PyReadonlyArray2<f64>) -> PyResult<Bound<'py, PyArray2<f64>>> {
        let X_array = X.as_array().to_owned();
        let result = self.scaler.fit_transform(&X_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(PyArray2::from_owned_array_bound(py, result))
    }
}

/// SMOTE wrapper for Python
#[pyclass]
struct PySMOTE {
    k_neighbors: usize,
}

#[pymethods]
impl PySMOTE {
    #[new]
    fn new(k_neighbors: usize) -> Self {
        Self { k_neighbors }
    }
    
    fn fit_resample<'py>(
        &self,
        py: Python<'py>,
        X: PyReadonlyArray2<f64>,
        y: PyReadonlyArray1<f64>,
    ) -> PyResult<(Bound<'py, PyArray2<f64>>, Bound<'py, PyArray1<f64>>)> {
        use ndarray::Array2;
        
        // Ensure arrays are C-contiguous
        let X_array = X.as_array().to_owned();
        let y_array = y.as_array().to_owned();
        
        let smote = SMOTE::new(self.k_neighbors);
        let (X_resampled, y_resampled) = smote.fit_resample(&X_array, &y_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        
        Ok((
            PyArray2::from_owned_array_bound(py, X_resampled),
            PyArray1::from_owned_array_bound(py, y_resampled),
        ))
    }
}

/// GradientBoostingClassifier wrapper for Python
#[pyclass]
struct PyGradientBoosting {
    model: GradientBoostingClassifier,
}

#[pymethods]
impl PyGradientBoosting {
    #[new]
    fn new(n_estimators: usize, learning_rate: f64, max_depth: usize) -> Self {
        let model = GradientBoostingClassifier::new(n_estimators)
            .learning_rate(learning_rate)
            .max_depth(max_depth);
        Self { model }
    }
    
    fn fit(&mut self, X: PyReadonlyArray2<f64>, y: PyReadonlyArray1<f64>) -> PyResult<()> {
        let X_array = X.as_array().to_owned();
        let y_array = y.as_array().to_owned();
        self.model.fit(&X_array, &y_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(())
    }
    
    fn predict<'py>(&self, py: Python<'py>, X: PyReadonlyArray2<f64>) -> PyResult<Bound<'py, PyArray1<f64>>> {
        let X_array = X.as_array().to_owned();
        let result = self.model.predict(&X_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(PyArray1::from_owned_array_bound(py, result))
    }
    
    fn predict_proba<'py>(&self, py: Python<'py>, X: PyReadonlyArray2<f64>) -> PyResult<Bound<'py, PyArray2<f64>>> {
        let X_array = X.as_array().to_owned();
        let result = self.model.predict_proba(&X_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(PyArray2::from_owned_array_bound(py, result))
    }
    
    fn save(&self, path: &str) -> PyResult<()> {
        self.model.save(path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("{:?}", e)))?;
        Ok(())
    }
    
    #[staticmethod]
    fn load(path: &str) -> PyResult<Self> {
        let model = GradientBoostingClassifier::load(path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("{:?}", e)))?;
        Ok(Self { model })
    }
}

/// RandomForestClassifier wrapper for Python
#[pyclass]
struct PyRandomForest {
    model: RandomForestClassifier,
}

#[pymethods]
impl PyRandomForest {
    #[new]
    #[pyo3(signature = (n_estimators, max_depth, min_samples_split=2))]
    fn new(n_estimators: usize, max_depth: usize, min_samples_split: usize) -> Self {
        let model = RandomForestClassifier::new(n_estimators)
            .max_depth(max_depth);
        // Note: RandomForestClassifier doesn't have min_samples_split method yet
        // The trees inside will use their default min_samples_split
        Self { model }
    }
    
    fn fit(&mut self, X: PyReadonlyArray2<f64>, y: PyReadonlyArray1<f64>) -> PyResult<()> {
        let X_array = X.as_array().to_owned();
        let y_array = y.as_array().to_owned();
        self.model.fit(&X_array, &y_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(())
    }
    
    fn predict<'py>(&self, py: Python<'py>, X: PyReadonlyArray2<f64>) -> PyResult<Bound<'py, PyArray1<f64>>> {
        let X_array = X.as_array().to_owned();
        let result = self.model.predict(&X_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(PyArray1::from_owned_array_bound(py, result))
    }
    
    fn predict_proba<'py>(&self, py: Python<'py>, X: PyReadonlyArray2<f64>) -> PyResult<Bound<'py, PyArray2<f64>>> {
        let X_array = X.as_array().to_owned();
        let result = self.model.predict_proba(&X_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(PyArray2::from_owned_array_bound(py, result))
    }
    
    fn save(&self, path: &str) -> PyResult<()> {
        self.model.save(path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("{:?}", e)))?;
        Ok(())
    }
    
    #[staticmethod]
    fn load(path: &str) -> PyResult<Self> {
        let model = RandomForestClassifier::load(path)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyIOError, _>(format!("{:?}", e)))?;
        Ok(Self { model })
    }
}

/// MLPClassifier wrapper for Python
#[pyclass]
struct PyMLP {
    model: MLPClassifier,
}

#[pymethods]
impl PyMLP {
    #[new]
    #[pyo3(signature = (layer_sizes, hidden_activation="relu", epochs=100, batch_size=32))]
    fn new(layer_sizes: Vec<usize>, hidden_activation: &str, epochs: usize, batch_size: usize) -> PyResult<Self> {
        use ghost_core::Activation;
        
        let activation = match hidden_activation {
            "relu" => Activation::ReLU,
            "tanh" => Activation::Tanh,
            "sigmoid" => Activation::Sigmoid,
            "linear" => Activation::Linear,
            _ => return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Unknown activation: {}", hidden_activation)
            )),
        };
        
        let model = MLPClassifier::new(&layer_sizes, activation)
            .epochs(epochs)
            .batch_size(batch_size);
        
        Ok(Self { model })
    }
    
    fn fit(&mut self, X: PyReadonlyArray2<f64>, y: PyReadonlyArray1<f64>) -> PyResult<()> {
        let X_array = X.as_array().to_owned();
        let y_array = y.as_array().to_owned();
        self.model.fit(&X_array, &y_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(())
    }
    
    fn predict<'py>(&mut self, py: Python<'py>, X: PyReadonlyArray2<f64>) -> PyResult<Bound<'py, PyArray1<f64>>> {
        let X_array = X.as_array().to_owned();
        let result = self.model.predict(&X_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(PyArray1::from_owned_array_bound(py, result))
    }
    
    fn predict_proba<'py>(&mut self, py: Python<'py>, X: PyReadonlyArray2<f64>) -> PyResult<Bound<'py, PyArray2<f64>>> {
        let X_array = X.as_array().to_owned();
        let result = self.model.predict_proba(&X_array)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("{:?}", e)))?;
        Ok(PyArray2::from_owned_array_bound(py, result))
    }
}

/// Metrics functions
#[pyfunction]
fn accuracy(y_true: PyReadonlyArray1<f64>, y_pred: PyReadonlyArray1<f64>) -> f64 {
    let y_true_array = y_true.as_array().to_owned();
    let y_pred_array = y_pred.as_array().to_owned();
    Metrics::accuracy(&y_true_array, &y_pred_array)
}

#[pyfunction]
fn f1_score(y_true: PyReadonlyArray1<f64>, y_pred: PyReadonlyArray1<f64>) -> f64 {
    let y_true_array = y_true.as_array().to_owned();
    let y_pred_array = y_pred.as_array().to_owned();
    Metrics::f1_score(&y_true_array, &y_pred_array)
}

#[pyfunction]
fn precision(y_true: PyReadonlyArray1<f64>, y_pred: PyReadonlyArray1<f64>) -> f64 {
    let y_true_array = y_true.as_array().to_owned();
    let y_pred_array = y_pred.as_array().to_owned();
    Metrics::precision(&y_true_array, &y_pred_array)
}

#[pyfunction]
fn recall(y_true: PyReadonlyArray1<f64>, y_pred: PyReadonlyArray1<f64>) -> f64 {
    let y_true_array = y_true.as_array().to_owned();
    let y_pred_array = y_pred.as_array().to_owned();
    Metrics::recall(&y_true_array, &y_pred_array)
}

/// Python module
#[pymodule]
fn ghostml(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyStandardScaler>()?;
    m.add_class::<PyRobustScaler>()?;
    m.add_class::<PySMOTE>()?;
    m.add_class::<PyGradientBoosting>()?;
    m.add_class::<PyRandomForest>()?;
    m.add_class::<PyMLP>()?;
    m.add_function(wrap_pyfunction!(accuracy, m)?)?;
    m.add_function(wrap_pyfunction!(f1_score, m)?)?;
    m.add_function(wrap_pyfunction!(precision, m)?)?;
    m.add_function(wrap_pyfunction!(recall, m)?)?;
    Ok(())
}
