//! The combining crate: two libraries' families assembled into three
//! pipelines, with the roots computed at build time.
//!
//! What doesn't compile: a counter without a seed before it (its `LinkIn`
//! is `Seed`, the pipeline starts with `NoLink`):
//!
//! ```compile_fail
//! use combined::circuits::{families::KernelStepCounter, pipelines::seed_count};
//! use noir_zk_core::StepFamily;
//! fn f(pool: &dyn noir_zk_core::Artifacts) {
//!     let _ = seed_count::fold(pool).unwrap().app(KernelStepCounter::select("counter_small", "").unwrap());
//! }
//! ```
//!
//! and a sum right after a seed (`Count` expected, `Seed` given):
//!
//! ```compile_fail
//! use combined::circuits::{families::{KernelStepSeed, KernelStepSum}, pipelines::seed_count_sum};
//! use noir_zk_core::StepFamily;
//! fn f(pool: &dyn noir_zk_core::Artifacts) {
//!     let _ = seed_count_sum::fold(pool).unwrap()
//!         .app(KernelStepSeed::select("seed", "").unwrap()).unwrap()
//!         .app(KernelStepSum::select("sum", "").unwrap());
//! }
//! ```
//!
//! whereas seed then counter then sum does (see `tests/fold.rs`).

#[allow(missing_docs, clippy::all)]
pub mod circuits {
    include!(concat!(env!("OUT_DIR"), "/circuits.rs"));
}

/// The pool every pipeline here folds from: both libraries and the kernels.
pub fn pool<'a>(a: &'a dyn noir_zk_core::Artifacts, b: &'a dyn noir_zk_core::Artifacts) -> noir_zk_core::Merged<'a> {
    noir_zk_core::Merged::new(&[a, b, &noir_zk_backend::kernels::Kernels])
}
