use criterion::{criterion_group, criterion_main};

mod linkage_microbench;
mod multishow_age;
mod passport;
mod tree_forest_tradeoff;

use linkage_microbench::bench_linkage;
use multishow_age::bench_multishow_age;
use passport::bench_passport;
use tree_forest_tradeoff::bench_tree_forest;

criterion_group!(
    benches,
    bench_linkage,
    bench_tree_forest,
    bench_multishow_age,
    bench_passport
);
criterion_main!(benches);
