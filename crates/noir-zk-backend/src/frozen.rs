//! A generated registry (`noir-zk-codegen`) as a prover's [`Artifacts`]:
//! keys, ABIs and tree paths come from the registry, bytecode from an
//! [`ArtifactStore`], rejected unless it hashes to the pinned value.

use std::collections::HashMap;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use noir_zk_core::codec::field_from_be_bytes_canonical;
use noir_zk_core::registry::active;
use noir_zk_core::{Artifacts, Error, FamilyEntry, FamilyRef, Field, RegistryEntry, VkPath};

use crate::store::ArtifactStore;

/// A frozen registry with bytecode from `S`.
pub struct Frozen<S: ArtifactStore> {
    registry: &'static [RegistryEntry],
    families: &'static [FamilyEntry],
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
            families: &[],
            vk_tree_root: field(vk_tree_root)?,
            store,
            cache: Mutex::default(),
        })
    }

    /// The generated `REGISTRY` and `FAMILIES` of a layered registry (no
    /// single key tree: the pipeline builder computes the trees), with
    /// bytecode from `store`.
    pub fn layered(
        registry: &'static [RegistryEntry],
        families: &'static [FamilyEntry],
        store: S,
    ) -> Self {
        Self {
            registry,
            families,
            vk_tree_root: Field::from(0u64),
            store,
            cache: Mutex::default(),
        }
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

    fn entry(&self, name: &str) -> Option<&'static RegistryEntry> {
        active(self.registry, name)
    }

    fn family(&self, id: &FamilyRef) -> Option<&'static FamilyEntry> {
        self.families.iter().find(|f| f.id == *id)
    }
}

/// Checks a directory of downloaded circuit files (an unpacked pack) against
/// the pins compiled into `registry`: every `<label>@<version>.b64` must hash
/// to its `bytecode_sha256` and every `<label>@<version>.vk` to its
/// `vk_sha256`. Other files (ABIs, `manifest.toml`, `vk-tree.json`) are
/// ignored: the registry embeds its own. Returns how many files it checked;
/// a file of a version the registry doesn't know is an error.
pub fn verify_dir(registry: &[RegistryEntry], dir: &std::path::Path) -> Result<usize, Error> {
    let mut checked = 0;
    let entries =
        std::fs::read_dir(dir).map_err(|e| Error::Artifact(format!("{}: {e}", dir.display())))?;
    for entry in entries {
        let path = entry
            .map_err(|e| Error::Artifact(format!("{}: {e}", dir.display())))?
            .path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let (stem, pin_of): (&str, fn(&RegistryEntry) -> [u8; 32]) =
            if let Some(stem) = name.strip_suffix(".b64") {
                (stem, |e| e.bytecode_sha256)
            } else if let Some(stem) = name.strip_suffix(".vk") {
                (stem, |e| e.vk_sha256)
            } else {
                continue;
            };
        let entry = stem
            .split_once('@')
            .and_then(|(label, version)| {
                registry
                    .iter()
                    .find(|e| e.label == label && e.version == version)
            })
            .ok_or_else(|| {
                Error::Artifact(format!("{name}: not a circuit version of this registry"))
            })?;
        let bytes = std::fs::read(&path).map_err(|e| Error::Artifact(format!("{name}: {e}")))?;
        if Sha256::digest(&bytes).as_slice() != pin_of(entry) {
            return Err(Error::Artifact(format!(
                "{name}: does not match its pinned hash"
            )));
        }
        checked += 1;
    }
    Ok(checked)
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
            vk_sha256: [0; 32],
            vk_hash: [0; 32],
            layer: "",
            family: "",
            abi: None,
            vk: &[],
            vk_index: None,
            vk_siblings: &[],
        }]))
    }

    #[test]
    fn verify_dir_checks_bytecode_and_keys() {
        const VK: &[u8] = b"key";
        let mut e = registry()[0];
        e.vk_sha256 = Sha256::digest(VK).into();
        let reg: &'static [RegistryEntry] = Box::leak(Box::new([e]));
        let dir = std::env::temp_dir().join(format!("noir-zk-verify-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("c@1.0.0.b64"), BYTECODE).unwrap();
        std::fs::write(dir.join("c@1.0.0.vk"), VK).unwrap();
        std::fs::write(dir.join("c@1.0.0.abi.json"), b"{}").unwrap();
        assert_eq!(verify_dir(reg, &dir).unwrap(), 2);
        std::fs::write(dir.join("c@1.0.0.vk"), b"other").unwrap();
        assert!(verify_dir(reg, &dir).is_err());
        std::fs::write(dir.join("c@1.0.0.vk"), VK).unwrap();
        std::fs::write(dir.join("d@1.0.0.b64"), BYTECODE).unwrap();
        assert!(verify_dir(reg, &dir).is_err());
        let _ = std::fs::remove_dir_all(dir);
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
