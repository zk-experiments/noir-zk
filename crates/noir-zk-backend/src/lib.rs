//! Proving backend for Noir circuits folded with barretenberg's Chonk.
//!
//! - [`abi`]: nargo ABIs: field counts and `Prover.toml` encoding.
//! - [`witness`]: ACVM witness solving.
//! - [`chonk`]: Chonk folding over the FFI (`barretenberg-rs`): accumulate a
//!   stack of circuits into one proof, verify it, derive keys.
//! - [`fold`]: typed folding over generated circuit types (`Folding`, `verify`).
//! - [`pipeline`]: folding a declared pipeline with the generic kernels
//!   (`PipelineFold`, `verify`).
//! - [`honk`]: standalone UltraHonk proofs of generated `Honk` circuits.
//! - [`frozen`] and [`store`]: a generated registry as the prover's
//!   [`Artifacts`](noir_zk_core::Artifacts), bytecode fetched and hash-checked.
//! - `pack` (feature `packs`): circuit packs, `.tar.gz` archives of assets.
//! - [`srs`]: the BN254 and Grumpkin setups bb needs.

pub mod abi;
mod bb;
pub mod chonk;
pub mod fold;
pub mod frozen;
pub mod honk;
#[cfg(feature = "packs")]
pub mod pack;
pub mod pipeline;
pub mod srs;
pub mod store;
pub mod witness;

pub use frozen::Frozen;
/// The generic pipeline kernels (`noir-zk-kernels`): their entries, family and artifacts.
pub use noir_zk_kernels as kernels;

/// The barretenberg version linked (`barretenberg-rs`): keys and proofs are
/// only valid for this version.
pub const BB_VERSION: &str = "7.0.0-nightly.20260927";

#[cfg(feature = "http")]
pub use store::HttpStore;
pub use store::{ArtifactStore, BundledStore, DirStore, LayerStore};

#[cfg(test)]
mod tests {
    /// `BB_VERSION` follows the workspace's `barretenberg-rs` pin.
    #[test]
    fn bb_version_matches_the_pin() {
        let manifest = include_str!("../../../Cargo.toml");
        assert!(manifest.contains(&format!(
            "barretenberg-rs = {{ version = \"={}\"",
            super::BB_VERSION
        )));
    }
}
