//! A generated registry (`noir-zk-codegen`) as a prover's [`Artifacts`]:
//! keys, ABIs and tree paths come from the registry, bytecode from an
//! [`ArtifactStore`], rejected unless it hashes to the pinned value.

use std::collections::HashMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use noir_zk_core::codec::field_from_be_bytes_canonical;
use noir_zk_core::registry::active;
use noir_zk_core::{Artifacts, Error, Field, RegistryEntry, VkPath};

use crate::store::ArtifactStore;

/// A frozen registry with bytecode from `S`.
pub struct Frozen<S: ArtifactStore> {
    registry: &'static [RegistryEntry],
    vk_tree_root: Field,
    store: S,
    cache: Mutex<HashMap<&'static str, String>>,
}

fn field(b: &[u8; 32]) -> Result<Field, Error> {
    field_from_be_bytes_canonical(b, "registry field")
}

impl<S: ArtifactStore> Frozen<S> {
    /// The generated `REGISTRY` and `VK_TREE_ROOT`, with bytecode from `store`.
    pub fn new(
        registry: &'static [RegistryEntry],
        vk_tree_root: &[u8; 32],
        store: S,
    ) -> Result<Self, Error> {
        Ok(Self {
            registry,
            vk_tree_root: field(vk_tree_root)?,
            store,
            cache: Mutex::default(),
        })
    }

    fn entry(&self, name: &str) -> Result<&'static RegistryEntry, Error> {
        active(self.registry, name)
            .ok_or_else(|| Error::Artifact(format!("no active circuit {name}")))
    }
}

impl<S: ArtifactStore> Artifacts for Frozen<S> {
    fn bytecode_b64(&self, name: &str) -> Result<String, Error> {
        let e = self.entry(name)?;
        if let Some(b) = self
            .cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(e.label)
        {
            return Ok(b.clone());
        }
        let bytes = self.store.fetch(&e.asset_name())?;
        if Sha256::digest(&bytes).as_slice() != e.bytecode_sha256 {
            return Err(Error::Artifact(format!(
                "{}: bytecode does not match its pinned hash",
                e.asset_name()
            )));
        }
        let b64 = String::from_utf8(bytes)
            .map_err(|_| Error::Artifact(format!("{}: not base64 text", e.asset_name())))?;
        self.cache
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(e.label, b64.clone());
        Ok(b64)
    }

    fn abi_json(&self, name: &str) -> Result<String, Error> {
        self.entry(name)?
            .abi
            .map(str::to_string)
            .ok_or_else(|| Error::Artifact(format!("{name}: no ABI")))
    }

    fn vk(&self, name: &str) -> Result<Vec<u8>, Error> {
        Ok(self.entry(name)?.vk.to_vec())
    }

    fn vk_path(&self, name: &str) -> Result<VkPath, Error> {
        let e = self.entry(name)?;
        let index = e
            .vk_index
            .ok_or_else(|| Error::Artifact(format!("{name} is not in the key tree")))?;
        Ok(VkPath {
            index,
            siblings: e.vk_siblings.iter().map(field).collect::<Result<_, _>>()?,
        })
    }

    fn vk_tree_root(&self) -> Field {
        self.vk_tree_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noir_zk_core::{ChonkRole, ProofSystem, Status};

    struct Mem(&'static [u8]);
    impl ArtifactStore for Mem {
        fn fetch(&self, _: &str) -> Result<Vec<u8>, Error> {
            Ok(self.0.to_vec())
        }
    }

    const BYTECODE: &[u8] = b"H4sIAAAA";

    fn registry() -> &'static [RegistryEntry] {
        let sha: [u8; 32] = Sha256::digest(BYTECODE).into();
        Box::leak(Box::new([RegistryEntry {
            label: "c",
            version: "1.0.0",
            system: ProofSystem::Chonk(ChonkRole::App),
            status: Status::Active,
            bytecode_sha256: sha,
            abi: None,
            vk: &[],
            vk_index: None,
            vk_siblings: &[],
        }]))
    }

    #[test]
    fn bytecode_must_match_its_pin() {
        let ok = Frozen::new(registry(), &[0; 32], Mem(BYTECODE)).unwrap();
        assert_eq!(ok.bytecode_b64("c").unwrap().as_bytes(), BYTECODE);
        let bad = Frozen::new(registry(), &[0; 32], Mem(b"H4sIAAAB")).unwrap();
        assert!(bad.bytecode_b64("c").is_err());
        assert!(ok.bytecode_b64("missing").is_err());
    }
}
