//! The production path: the frozen registry (embedded Chonk keys and key tree
//! from `noir-zk-canonical`), bytecode from a release-asset directory checked
//! against its pinned hash, and the FFI prover and verifier.
//!
//! Runs when `NOIR_ZK_ASSETS` (release assets, e.g. `target/release-assets`
//! after `cargo xtask freeze-circuits`) and `NOIR_ZK_EID_CIRCUITS` (for a
//! synthetic document's Chain.toml inputs) are set.

use std::path::{Path, PathBuf};

use noir_zk_backend::chonk::FoldedProof;
use noir_zk_backend::fold::{prove_document, verify_document, Document, Inputs};
use noir_zk_canonical::{hiding_vk, vk_tree_root, Canonical, DirStore};
use noir_zk_core::Artifacts;

fn chain_toml(root: &Path, name: &str) -> String {
    let ws = std::fs::read_to_string(root.join("Nargo.toml")).unwrap();
    let dir = ws
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"')?.strip_suffix("\","))
        .map(|m| root.join(m))
        .find(|d| {
            std::fs::read_to_string(d.join("Nargo.toml"))
                .is_ok_and(|t| t.contains(&format!("name = \"{name}\"")))
        })
        .unwrap();
    std::fs::read_to_string(dir.join("Chain.toml")).unwrap()
}

#[test]
fn proves_with_the_frozen_registry() {
    let (Some(assets), Some(root)) = (
        std::env::var_os("NOIR_ZK_ASSETS").map(PathBuf::from),
        std::env::var_os("NOIR_ZK_EID_CIRCUITS").map(PathBuf::from),
    ) else {
        return;
    };
    let canonical = Canonical::new(DirStore(assets.clone()));
    let chains: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("noir/circuits/chains.json")).unwrap(),
    )
    .unwrap();
    for chain in chains["chains"].as_array().unwrap() {
        let name = |k: &str| chain[k].as_str().unwrap();
        let (d, s, e) = (
            chain_toml(&root, name("dsc")),
            chain_toml(&root, name("sod")),
            chain_toml(&root, name("envelope")),
        );
        let doc = Document {
            dsc: (name("dsc"), Inputs::Toml(&d)),
            sod: (name("sod"), Inputs::Toml(&s)),
            envelope: (name("envelope"), Inputs::Toml(&e)),
        };
        let (proof, public) = prove_document(&canonical, &doc).unwrap();
        let verified = verify_document(
            &FoldedProof::from_bytes(&proof.to_bytes()).unwrap(),
            hiding_vk(),
            vk_tree_root(),
        )
        .unwrap();
        assert_eq!(verified, public);
        assert_eq!(proof.to_bytes().len(), 39_872);
    }

    // A tampered asset is refused before it reaches the solver.
    let tmp = std::env::temp_dir().join(format!("noir-zk-tamper-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let asset = std::fs::read_dir(&assets).unwrap().next().unwrap().unwrap();
    let mut bytes = std::fs::read(asset.path()).unwrap();
    bytes[10] ^= 1;
    std::fs::write(tmp.join(asset.file_name()), bytes).unwrap();
    let label = asset
        .file_name()
        .to_string_lossy()
        .split('@')
        .next()
        .unwrap()
        .to_string();
    let err = Canonical::new(DirStore(tmp.clone()))
        .bytecode_b64(&label)
        .unwrap_err();
    assert!(err.to_string().contains("pinned hash"), "{err}");
    let _ = std::fs::remove_dir_all(tmp);
}
