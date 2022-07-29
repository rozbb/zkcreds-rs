use criterion::{criterion_group, criterion_main};

//mod com_scaling;
//mod empty;
mod microbenches;
//mod passport;
mod util;

//use empty::bench_empty;
use microbenches::microbenches;
//use passport::bench_passport;
use util::new_size_file as setup; // Gotta set up logging proof sizes to CSV

/*
criterion_group!(
    benches,
    bench_passport,
    bench_empty,
    com_scaling::bench_pred_proof_0::bench_pred_proof_0,
    com_scaling::bench_pred_proof_16::bench_pred_proof_16,
    com_scaling::bench_pred_proof_32::bench_pred_proof_32,
    com_scaling::bench_pred_proof_48::bench_pred_proof_48,
    com_scaling::bench_pred_proof_64::bench_pred_proof_64,
    com_scaling::bench_pred_proof_80::bench_pred_proof_80,
    com_scaling::bench_pred_proof_96::bench_pred_proof_96,
    com_scaling::bench_pred_proof_112::bench_pred_proof_112,
    com_scaling::bench_pred_proof_128::bench_pred_proof_128,
    com_scaling::bench_pred_proof_144::bench_pred_proof_144,
    com_scaling::bench_pred_proof_160::bench_pred_proof_160,
    com_scaling::bench_pred_proof_176::bench_pred_proof_176,
    com_scaling::bench_pred_proof_192::bench_pred_proof_192,
    com_scaling::bench_pred_proof_208::bench_pred_proof_208,
    com_scaling::bench_pred_proof_224::bench_pred_proof_224,
    com_scaling::bench_pred_proof_240::bench_pred_proof_240,
    com_scaling::bench_pred_proof_256::bench_pred_proof_256
);
*/
criterion_main!(setup, /*benches,*/ microbenches);
