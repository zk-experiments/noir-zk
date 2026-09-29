//! Where a prover gets circuits from: the frozen bytecode (checked against
//! its pinned hash), the ABI, the Chonk verification key and the key's place
//! in the verification key tree the kernels check. `noir-zk-backend`
//! implements it over a generated registry and an artifact store (`Frozen`).

use crate::error::Error;
use crate::pipeline::{FamilyEntry, FamilyRef};
use crate::registry::RegistryEntry;
use crate::zk::Field;

/// A circuit's place in the verification key tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VkPath {
    /// Leaf index.
    pub index: u64,
    /// Siblings from the leaf up.
    pub siblings: Vec<Field>,
}

/// The circuits of one frozen release, or of several merged ([`Merged`]).
pub trait Artifacts {
    /// Base64 (gzipped) ACIR bytecode as nargo emits it, already checked
    /// against the circuit's pinned hash.
    fn bytecode_b64(&self, name: &str) -> Result<String, Error>;
    /// The circuit's ABI (nargo's JSON).
    fn abi_json(&self, name: &str) -> Result<String, Error>;
    /// The circuit's Chonk verification key.
    fn vk(&self, name: &str) -> Result<Vec<u8>, Error>;
    /// Its path in the verification key tree (the single-tree kernel
    /// convention of hand-written kernels).
    fn vk_path(&self, name: &str) -> Result<VkPath, Error>;
    /// The key tree root the kernels check against (that convention).
    fn vk_tree_root(&self) -> Field;
    /// The active registry entry of `name`, if this store has it.
    fn entry(&self, name: &str) -> Option<&'static RegistryEntry>;
    /// The family `id`, if this store declares it.
    fn family(&self, id: &FamilyRef) -> Option<&'static FamilyEntry>;
}

/// Several registries as one: the pool a pipeline fold draws from. Lookups
/// take the first store that has the circuit or family.
pub struct Merged<'a>(pub Vec<&'a dyn Artifacts>);

impl<'a> Merged<'a> {
    /// Merges `stores` in lookup order.
    pub fn new(stores: &[&'a dyn Artifacts]) -> Self {
        Self(stores.to_vec())
    }

    fn find<T>(
        &self,
        f: impl Fn(&'a dyn Artifacts) -> Result<T, Error>,
        what: &str,
    ) -> Result<T, Error> {
        let mut last = Error::Artifact(format!("{what}: no store"));
        for s in &self.0 {
            match f(*s) {
                Ok(v) => return Ok(v),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

impl Artifacts for Merged<'_> {
    fn bytecode_b64(&self, name: &str) -> Result<String, Error> {
        self.find(|s| s.bytecode_b64(name), name)
    }

    fn abi_json(&self, name: &str) -> Result<String, Error> {
        self.find(|s| s.abi_json(name), name)
    }

    fn vk(&self, name: &str) -> Result<Vec<u8>, Error> {
        self.find(|s| s.vk(name), name)
    }

    fn vk_path(&self, name: &str) -> Result<VkPath, Error> {
        self.find(|s| s.vk_path(name), name)
    }

    fn vk_tree_root(&self) -> Field {
        self.0
            .first()
            .map_or_else(|| Field::from(0u64), |s| s.vk_tree_root())
    }

    fn entry(&self, name: &str) -> Option<&'static RegistryEntry> {
        self.0.iter().find_map(|s| s.entry(name))
    }

    fn family(&self, id: &FamilyRef) -> Option<&'static FamilyEntry> {
        self.0.iter().find_map(|s| s.family(id))
    }
}
