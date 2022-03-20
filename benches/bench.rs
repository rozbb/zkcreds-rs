use criterion::{criterion_group, criterion_main};

mod multishow_age;
mod tree_forest_tradeoff;

use multishow_age::bench_multishow_age;
use tree_forest_tradeoff::bench_tree_forest;

criterion_group!(benches, bench_tree_forest, bench_multishow_age);
criterion_main!(benches);
