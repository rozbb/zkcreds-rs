//! Defines some placeholder Python functions

use pyo3::prelude::*;

// TODO: Expose Python wrapper functions for `zkcreds` API (maybe also passport module?)

// TODO: Remove
#[pyfunction]
fn hello_world() -> PyResult<()> {
    println!("Hello World!");
    Ok(())
}

/// Python wrapper module for Rust `zkcreds` library
#[pymodule]
// module name must correspond to `lib.name` in `Cargo.toml`
//#[pyo3(name = "zkcreds")]
fn zkcreds(_py: Python, pym: &PyModule) -> PyResult<()> {
    // Generic `zkcreds` API bindings
    pym.add_function(wrap_pyfunction!(hello_world, pym)?)?;

    // `zkcreds` passport application bindings
    // TODO: Where does this belong?
    Ok(())
}
