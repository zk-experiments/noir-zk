//! Proving backend for Noir circuits folded with barretenberg's Chonk.
//!
//! - [`witness`]: ACVM witness solving (ported from psonet's `pso-zk-backend`).
//! - [`chonk`]: Chonk folding over the FFI (`barretenberg-rs`): accumulate a
//!   stack of circuits into one proof, verify it, derive keys.
//! - [`fold`]: typed folding over generated circuit types (`Folding`, `verify`).
//! - [`honk`]: standalone UltraHonk proofs of generated `Honk` circuits.
//! - [`frozen`] and [`store`]: a generated registry as the prover's
//!   [`Artifacts`](noir_zk_core::Artifacts), bytecode fetched and hash-checked.
//! - [`srs`]: the BN254 and Grumpkin setups bb needs.

mod bb;
pub mod chonk;
pub mod fold;
pub mod frozen;
pub mod honk;
pub mod srs;
pub mod store;
pub mod witness;

pub use frozen::Frozen;
#[cfg(feature = "http")]
pub use store::HttpStore;
pub use store::{ArtifactStore, DirStore};
