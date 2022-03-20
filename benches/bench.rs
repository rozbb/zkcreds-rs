use criterion::{criterion_group, criterion_main};

mod tree_forest_tradeoff;
use tree_forest_tradeoff::bench_tree_forest;

criterion_group!(benches, bench_tree_forest);
criterion_main!(benches);
