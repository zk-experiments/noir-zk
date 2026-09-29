//! The generic pipeline kernels of noir-zk, frozen: `kernel_init` folds a
//! pipeline's first app, `kernel_step` any later app, `kernel_tail` pads a
//! one-app pipeline to Chonk's minimum of four circuits, `kernel_hiding`
//! proves the pipeline root is in the deployment tree and publishes the
//! outputs. Their Noir source is `noir/` (the `pipeline_kernel` library
//! documents the state, the record, the layout and the key trees); their
//! keys and pins are `circuits/manifest.toml` and `resources/`; their
//! bytecode is bundled ([`ASSETS`], about 40 KB).
//!
//! The kernels form the family `noir-zk-kernels/kernels/step` ([`FAMILY`]),
//! whose root every pipeline tree commits to at its last leaf.

include!(concat!(env!("OUT_DIR"), "/kernels.rs"));

/// The kernel `label`'s active entry.
pub fn kernel(label: &str) -> Option<&'static noir_zk_core::RegistryEntry> {
    noir_zk_core::registry::active(KERNELS, label)
}

/// The kernels as artifacts (their bundled bytecode, keys and ABIs): merge
/// them into a pipeline's pool with `Merged`.
pub struct Kernels;

impl noir_zk_core::Artifacts for Kernels {
    fn bytecode_b64(&self, name: &str) -> Result<String, noir_zk_core::Error> {
        let e = kernel(name)
            .ok_or_else(|| noir_zk_core::Error::Artifact(format!("no kernel {name}")))?;
        let asset = e.asset_name();
        ASSETS
            .iter()
            .find(|(a, _)| *a == asset)
            .map(|(_, b)| String::from_utf8_lossy(b).into_owned())
            .ok_or_else(|| noir_zk_core::Error::Artifact(format!("{asset} is not bundled")))
    }

    fn abi_json(&self, name: &str) -> Result<String, noir_zk_core::Error> {
        kernel(name)
            .and_then(|e| e.abi)
            .map(str::to_string)
            .ok_or_else(|| noir_zk_core::Error::Artifact(format!("no kernel {name}")))
    }

    fn vk(&self, name: &str) -> Result<Vec<u8>, noir_zk_core::Error> {
        kernel(name)
            .map(|e| e.vk.to_vec())
            .ok_or_else(|| noir_zk_core::Error::Artifact(format!("no kernel {name}")))
    }

    fn vk_path(&self, name: &str) -> Result<noir_zk_core::VkPath, noir_zk_core::Error> {
        Err(noir_zk_core::Error::Artifact(format!(
            "{name}: the kernels check family and pipeline trees, not one key tree"
        )))
    }

    fn vk_tree_root(&self) -> noir_zk_core::Field {
        noir_zk_core::Field::from(0u64)
    }

    fn entry(&self, name: &str) -> Option<&'static noir_zk_core::RegistryEntry> {
        kernel(name)
    }

    fn family(&self, id: &noir_zk_core::FamilyRef) -> Option<&'static noir_zk_core::FamilyEntry> {
        (*id == FAMILY.id).then_some(&FAMILY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The family root in the table is what the runtime computes from the
    /// pinned key hashes.
    #[test]
    fn family_root_recomputes() {
        let hashes: Vec<noir_zk_core::Field> = FAMILY
            .members
            .iter()
            .map(|(_, h)| noir_zk_core::codec::field_from_be_bytes(h))
            .collect();
        let id = noir_zk_core::tree::family_id(LIBRARY.name, LIBRARY.version, "kernels", "step");
        assert_eq!(
            noir_zk_core::tree::family_root(id, &hashes),
            FAMILY.root_field()
        );
        assert_eq!(FAMILY.members.len(), 3);
        assert!(kernel("kernel_hiding").is_some() && kernel("kernel_step").is_some());
        assert_eq!(ASSETS.len(), 4);
    }
}
