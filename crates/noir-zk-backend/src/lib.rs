//! Proving backend for the eid-circuits circuits.
//!
//! - [`witness`]: ACVM witness solving (ported from psonet's `pso-zk-backend`).
//! - [`chonk`]: barretenberg's Chonk folding over the FFI (`barretenberg-rs`):
//!   accumulate a stack of circuits into one proof, and verify it.
//! - [`fold`]: the eid document proof: the DSC, SOD and envelope steps folded
//!   with the five kernels, whose inputs it builds.
//! - [`srs`]: the BN254 and Grumpkin setups bb needs.

pub mod chonk;
pub mod fold;
pub mod srs;
pub mod witness;
