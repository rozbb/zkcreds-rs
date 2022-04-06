use ark_serialize::{CanonicalSerialize, Write};
use std::fs::{File, OpenOptions};

const SIZE_LOG_FILE: &str = "proof_sizes.csv";

// Make a new CSV file if none exists. If one does, clear its contents.
pub fn new_size_file() {
    let mut f = File::create(SIZE_LOG_FILE).unwrap();
    writeln!(f, "description,proof_size_in_bytes").unwrap();
}

// Record DESC,SIZE in the CSV file
pub fn record_size(desc: impl AsRef<str>, val: &impl CanonicalSerialize) {
    let mut f = OpenOptions::new().append(true).open(SIZE_LOG_FILE).unwrap();
    let size = val.serialized_size();
    writeln!(f, "{},{}", desc.as_ref(), size).unwrap();
}
