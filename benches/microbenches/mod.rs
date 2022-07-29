use criterion::{criterion_group, criterion_main};

//mod linkage_microbench;
pub(crate) mod monolithic_proof;
mod multishow;
//mod multishow_age;
mod pseudonymous_show;
mod revealing_multishow;
mod simple_expiry;
//mod tf_proof;
//mod tree_forest_tradeoff;

//use linkage_microbench::bench_linkage;
use multishow::bench_multishow;
//use multishow_age::bench_multishow_age;
use pseudonymous_show::bench_pseudonymous_show;
use revealing_multishow::bench_revealing_multishow;
use simple_expiry::bench_expiry;
//use tree_forest_tradeoff::bench_tree_forest;

criterion_group!(
    microbenches,
    bench_pseudonymous_show,
    bench_multishow,
    bench_revealing_multishow,
    //bench_linkage,
    //bench_tree_forest,
    //bench_multishow_age,
    bench_expiry,
);
criterion_main!(microbenches);
