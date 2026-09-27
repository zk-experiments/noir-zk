//! End to end against a local eid-circuits checkout compiled with the pinned
//! toolchain (`nargo compile --workspace`, `eid-vectors vk-tree`): prove one of
//! its synthetic documents (noir/circuits/chains.json, inputs in Chain.toml)
//! through the FFI, verify it, and check its public outputs.
//!
//! Runs only when `NOIR_ZK_EID_CIRCUITS` points at the checkout (it needs the
//! compiled artifacts and bb's cached SRS); otherwise it passes vacuously.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use noir_zk_backend::chonk::{self, FoldedProof};
use noir_zk_backend::fold::{prove_document, verify_document, Document, Inputs};
use noir_zk_backend::witness::Program;
use noir_zk_core::codec::field_from_be_bytes_canonical;
use noir_zk_core::{Artifacts, CircuitKind, Error, Field, VkPath};

struct Local {
    root: PathBuf,
    tree: serde_json::Value,
    vks: RefCell<HashMap<String, Vec<u8>>>,
}

fn kind(name: &str) -> CircuitKind {
    match name {
        "kernel_hiding" => CircuitKind::Hiding,
        n if n.starts_with("kernel_") => CircuitKind::Kernel,
        _ => CircuitKind::App,
    }
}

fn field(s: &str) -> Field {
    field_from_be_bytes_canonical(&hex::decode(s.trim_start_matches("0x")).unwrap(), "hex").unwrap()
}

impl Local {
    fn artifact(&self, name: &str) -> Result<serde_json::Value, Error> {
        let json = std::fs::read_to_string(self.root.join(format!("target/{name}.json")))
            .map_err(|e| Error::Artifact(format!("{name}: {e}")))?;
        serde_json::from_str(&json).map_err(|e| Error::Artifact(e.to_string()))
    }
}

impl Artifacts for Local {
    fn bytecode_b64(&self, name: &str) -> Result<String, Error> {
        Ok(self.artifact(name)?["bytecode"]
            .as_str()
            .unwrap()
            .to_string())
    }
    fn abi_json(&self, name: &str) -> Result<String, Error> {
        Ok(self.artifact(name)?["abi"].to_string())
    }
    fn vk(&self, name: &str) -> Result<Vec<u8>, Error> {
        if let Some(vk) = self.vks.borrow().get(name) {
            return Ok(vk.clone());
        }
        let p = Program::from_parts(name, &self.bytecode_b64(name)?, &self.abi_json(name)?)?;
        let (vk, _) = chonk::compute_vk(name, p.bytecode(), kind(name))?;
        self.vks.borrow_mut().insert(name.to_string(), vk.clone());
        Ok(vk)
    }
    fn vk_path(&self, name: &str) -> Result<VkPath, Error> {
        let leaf = self.tree["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["package"] == name)
            .ok_or_else(|| Error::Artifact(format!("{name} not in vk-tree.json")))?;
        Ok(VkPath {
            index: leaf["index"].as_u64().unwrap(),
            siblings: leaf["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| field(s.as_str().unwrap()))
                .collect(),
        })
    }
    fn vk_tree_root(&self) -> Field {
        field(self.tree["root"].as_str().unwrap())
    }
}

/// Directory of a circuit package in the checkout.
fn package_dir(root: &Path, name: &str) -> PathBuf {
    let ws = std::fs::read_to_string(root.join("Nargo.toml")).unwrap();
    ws.lines()
        .filter_map(|l| l.trim().strip_prefix('"')?.strip_suffix("\","))
        .map(|m| root.join(m))
        .find(|d| {
            std::fs::read_to_string(d.join("Nargo.toml"))
                .is_ok_and(|t| t.contains(&format!("name = \"{name}\"")))
        })
        .unwrap_or_else(|| panic!("no package {name}"))
}

#[test]
fn proves_and_verifies_a_document() {
    let Some(root) = std::env::var_os("NOIR_ZK_EID_CIRCUITS").map(PathBuf::from) else {
        return;
    };
    let tree: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("noir/circuits/vk-tree.json")).unwrap(),
    )
    .unwrap();
    let local = Local {
        root: root.clone(),
        tree,
        vks: RefCell::default(),
    };
    let chains: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("noir/circuits/chains.json")).unwrap(),
    )
    .unwrap();
    let chain = &chains["chains"][0];
    let toml = |k: &str| {
        let name = chain[k].as_str().unwrap();
        (
            name,
            std::fs::read_to_string(package_dir(&root, name).join("Chain.toml")).unwrap(),
        )
    };
    let (dsc, sod, env) = (toml("dsc"), toml("sod"), toml("envelope"));
    let doc = Document {
        dsc: (dsc.0, Inputs::Toml(&dsc.1)),
        sod: (sod.0, Inputs::Toml(&sod.1)),
        envelope: (env.0, Inputs::Toml(&env.1)),
    };

    let (proof, public) = prove_document(&local, &doc).unwrap();
    let hiding = local.vk("kernel_hiding").unwrap();
    let verified = verify_document(&proof, &hiding, local.vk_tree_root()).unwrap();
    assert_eq!(verified, public);
    assert_eq!(public.date, 1_790_467_200);
    assert!(!public.uses_sha1);

    // Bytes round-trip, and a flipped public byte breaks verification.
    let bytes = proof.to_bytes();
    assert_eq!(FoldedProof::from_bytes(&bytes).unwrap(), proof);
    let mut tampered = bytes.clone();
    tampered[31] ^= 1;
    let tampered = FoldedProof::from_bytes(&tampered).unwrap();
    assert!(!chonk::verify(&tampered, &hiding).unwrap());

    // A proof written by `bb prove --scheme chonk` verifies here too.
    if let Some(dir) = std::env::var_os("NOIR_ZK_CLI_PROOF").map(PathBuf::from) {
        let cli = FoldedProof::from_bytes(&std::fs::read(dir.join("proof")).unwrap()).unwrap();
        assert!(chonk::verify(&cli, &std::fs::read(dir.join("vk")).unwrap()).unwrap());
    }
}
