//! Where a prover gets circuits from: the frozen bytecode (checked against
//! its pinned hash), the ABI, the Chonk verification key and the key's place
//! in the verification key tree the kernels check. `noir-zk-backend`
//! implements it over a generated registry and an artifact store (`Frozen`).

use crate::error::Error;
use crate::zk::Field;

/// A circuit's place in the verification key tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VkPath {
    /// Leaf index.
    pub index: u64,
    /// Siblings from the leaf up.
    pub siblings: Vec<Field>,
}

/// The circuits of one frozen release.
pub trait Artifacts {
    /// Base64 (gzipped) ACIR bytecode as nargo emits it, already checked
    /// against the circuit's pinned hash.
    fn bytecode_b64(&self, name: &str) -> Result<String, Error>;
    /// The circuit's ABI (nargo's JSON).
    fn abi_json(&self, name: &str) -> Result<String, Error>;
    /// The circuit's Chonk verification key.
    fn vk(&self, name: &str) -> Result<Vec<u8>, Error>;
    /// Its path in the verification key tree.
    fn vk_path(&self, name: &str) -> Result<VkPath, Error>;
    /// The key tree root the kernels check against.
    fn vk_tree_root(&self) -> Field;
}
