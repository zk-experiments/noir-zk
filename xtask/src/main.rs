//! `cargo xtask freeze-circuits` — the only step that reads compiled circuits
//! and derives their keys (ported from psonet's `pso-zk-circuits` xtask).
//!
//! It reads a compiled eid-circuits checkout (`nargo compile --workspace` and
//! `eid-vectors vk-tree` run there, with the toolchain pinned in this
//! repository's `mise.toml`) and freezes every circuit of its verification key
//! tree plus the hiding kernel:
//!
//! - `crates/noir-zk-canonical/resources/circuits/<label>/<version>/abi.json`
//!   and `circuit.vk` (the Chonk key, derived through the FFI);
//! - `crates/noir-zk-canonical/circuits/manifest.toml`: one `[[circuit]]` per
//!   version with its kind, status and `bytecode_sha256`;
//! - `crates/noir-zk-canonical/resources/vk-tree.json`: the key tree (root,
//!   and each circuit's index and siblings), checked leaf by leaf: the
//!   Poseidon2 hash of each derived key must be the tree's;
//! - `target/release-assets/<label>@<version>.b64`: the bytecode, published as
//!   release assets (too large for git) and fetched by hash.
//!
//! Versions: an unchanged bytecode is skipped; a changed bytecode with the
//! same ABI is a patch bump; an ABI change needs `--abi-change` (minor). The
//! superseded version becomes `deprecated`: it keeps its key, loses its ABI.
//!
//! `--check` derives everything again and fails if a committed active entry
//! differs, writing nothing.

#![allow(clippy::print_stdout, clippy::print_stderr, clippy::exit)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ark_ff::{BigInteger, PrimeField};
use noir_zk_backend::chonk;
use noir_zk_backend::witness::Program;
use noir_zk_core::{CircuitKind, Field};
use pso_poseidon::poseidon2::Poseidon2;
use sha2::{Digest, Sha256};
use toml_edit::{value, ArrayOfTables, DocumentMut, Table};

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("freeze-circuits: {msg}");
    std::process::exit(1)
}

fn kind_of(label: &str) -> CircuitKind {
    match label {
        "kernel_hiding" => CircuitKind::Hiding,
        l if l.starts_with("kernel_") => CircuitKind::Kernel,
        _ => CircuitKind::App,
    }
}

fn kind_name(k: CircuitKind) -> &'static str {
    match k {
        CircuitKind::App => "app",
        CircuitKind::Kernel => "kernel",
        CircuitKind::Hiding => "hiding",
    }
}

fn hex_field(f: &Field) -> String {
    format!("0x{}", hex::encode(f.into_bigint().to_bytes_be()))
}

fn bump(v: &str, minor: bool) -> String {
    let p: Vec<u64> = v.split('.').map(|x| x.parse().unwrap_or(0)).collect();
    let (ma, mi, pa) = (
        p.first().copied().unwrap_or(1),
        p.get(1).copied().unwrap_or(0),
        p.get(2).copied().unwrap_or(0),
    );
    if minor {
        format!("{ma}.{}.0", mi + 1)
    } else {
        format!("{ma}.{mi}.{}", pa + 1)
    }
}

struct Compiled {
    label: String,
    kind: CircuitKind,
    bytecode_b64: String,
    abi: String,
    sha: String,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("freeze-circuits") {
        eprintln!(
            "usage: cargo xtask freeze-circuits [--eid-circuits DIR] [--check | --abi-change]"
        );
        std::process::exit(2);
    }
    let mut eid = PathBuf::from("../eid-circuits");
    let (mut check, mut abi_change) = (false, false);
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--check" => check = true,
            "--abi-change" => abi_change = true,
            "--eid-circuits" => {
                eid = it
                    .next()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| fail("--eid-circuits needs a path"))
            }
            other => {
                eprintln!("unknown flag {other:?}");
                std::process::exit(2);
            }
        }
    }
    if check && abi_change {
        fail("--check mints nothing, so --abi-change with it is a mistake");
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let canonical = root.join("crates/noir-zk-canonical");
    freeze(
        &eid,
        &canonical,
        &root.join("target/release-assets"),
        check,
        abi_change,
    );
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())))
}

fn freeze(eid: &Path, canonical: &Path, assets: &Path, check: bool, abi_change: bool) {
    let tree: serde_json::Value =
        serde_json::from_str(&read(&eid.join("noir/circuits/vk-tree.json")))
            .unwrap_or_else(|e| fail(format!("vk-tree.json: {e}")));
    let leaves = tree["leaves"]
        .as_array()
        .unwrap_or_else(|| fail("vk-tree.json has no leaves"));
    let mut labels: Vec<String> = leaves
        .iter()
        .filter_map(|l| l["package"].as_str().map(str::to_string))
        .collect();
    labels.push("kernel_hiding".into());

    let compiled: Vec<Compiled> = labels
        .iter()
        .map(|label| {
            let v: serde_json::Value =
                serde_json::from_str(&read(&eid.join(format!("target/{label}.json"))))
                    .unwrap_or_else(|e| fail(format!("{label}: {e}")));
            let bytecode_b64 = v["bytecode"]
                .as_str()
                .unwrap_or_else(|| fail(format!("{label}: no bytecode")))
                .to_string();
            Compiled {
                label: label.clone(),
                kind: kind_of(label),
                sha: hex::encode(Sha256::digest(bytecode_b64.as_bytes())),
                abi: serde_json::to_string_pretty(&v["abi"]).unwrap_or_default(),
                bytecode_b64,
            }
        })
        .collect();
    let tree_hashes: BTreeMap<&str, &str> = leaves
        .iter()
        .filter_map(|l| Some((l["package"].as_str()?, l["vk_hash"].as_str()?)))
        .collect();

    let manifest_path = canonical.join("circuits/manifest.toml");
    let mut doc: DocumentMut = std::fs::read_to_string(&manifest_path)
        .unwrap_or_default()
        .parse()
        .unwrap_or_else(|e| fail(format!("manifest.toml: {e}")));
    // Latest active entry per label: (index in the array, version, sha).
    let mut active: BTreeMap<String, (usize, String, String)> = BTreeMap::new();
    if let Some(arr) = doc.get("circuit").and_then(|c| c.as_array_of_tables()) {
        for (i, t) in arr.iter().enumerate() {
            if t.get("status").and_then(|s| s.as_str()) == Some("active") {
                let label = t["label"].as_str().unwrap_or_default().to_string();
                active.insert(
                    label,
                    (
                        i,
                        t["version"].as_str().unwrap_or_default().to_string(),
                        t["bytecode_sha256"]
                            .as_str()
                            .unwrap_or_default()
                            .to_string(),
                    ),
                );
            }
        }
    }

    let (mut minted, mut failed) = (0usize, 0usize);
    let mut new_entries: Vec<(String, String, CircuitKind, String)> = vec![];
    let mut deprecate: Vec<usize> = vec![];
    for c in &compiled {
        let prev = active.get(&c.label);
        let dir_of = |v: &str| canonical.join(format!("resources/circuits/{}/{v}", c.label));
        if let Some((_, v, sha)) = prev {
            if *sha == c.sha {
                if check {
                    // Unchanged bytecode: the committed key must still derive from it.
                    let committed = std::fs::read(dir_of(v).join("circuit.vk")).unwrap_or_default();
                    let derived = derive_vk(c);
                    if committed != derived {
                        eprintln!(
                            "{}@{v}: committed key differs from the derived one",
                            c.label
                        );
                        failed += 1;
                    }
                }
                continue;
            }
        }
        if check {
            eprintln!(
                "{}: bytecode differs from the committed active version",
                c.label
            );
            failed += 1;
            continue;
        }
        let version = match prev {
            None => "1.0.0".to_string(),
            Some((i, v, _)) => {
                let old_abi =
                    std::fs::read_to_string(dir_of(v).join("abi.json")).unwrap_or_default();
                let abi_changed = old_abi != c.abi;
                if abi_changed && !abi_change {
                    fail(format!(
                        "{}: the ABI changed; rerun with --abi-change",
                        c.label
                    ));
                }
                deprecate.push(*i);
                let _ = std::fs::remove_file(dir_of(v).join("abi.json"));
                bump(v, abi_changed)
            }
        };
        let vk = derive_vk(c);
        if let Some(expected) = tree_hashes.get(c.label.as_str()) {
            let fields =
                chonk::vk_fields(&vk, c.kind).unwrap_or_else(|e| fail(format!("{}: {e}", c.label)));
            let h = Poseidon2::<Field>::new().hash_noir(&fields);
            if hex_field(&h) != *expected {
                fail(format!(
                    "{}: derived key hashes to {}, the key tree has {expected}",
                    c.label,
                    hex_field(&h)
                ));
            }
        }
        let dir = dir_of(&version);
        std::fs::create_dir_all(&dir).unwrap_or_else(|e| fail(e));
        std::fs::write(dir.join("abi.json"), format!("{}\n", c.abi)).unwrap_or_else(|e| fail(e));
        std::fs::write(dir.join("circuit.vk"), &vk).unwrap_or_else(|e| fail(e));
        new_entries.push((c.label.clone(), version, c.kind, c.sha.clone()));
        minted += 1;
    }
    if check {
        if failed > 0 {
            fail(format!(
                "{failed} circuits differ from the committed artifacts"
            ));
        }
        println!("freeze-circuits --check: {} circuits match", compiled.len());
        return;
    }

    if doc.get("circuit").is_none() {
        doc["proof_system"] = value("chonk");
        doc["circuit"] = toml_edit::Item::ArrayOfTables(ArrayOfTables::new());
    }
    doc["noir"] = value(env!("NOIR_VERSION_PIN"));
    doc["bb"] = value(env!("BB_VERSION_PIN"));
    doc["vk_tree_root"] = value(tree["root"].as_str().unwrap_or_default());
    let arr = doc["circuit"]
        .as_array_of_tables_mut()
        .unwrap_or_else(|| fail("manifest: circuit is not an array"));
    for i in deprecate {
        if let Some(t) = arr.get_mut(i) {
            t["status"] = value("deprecated");
        }
    }
    for (label, version, kind, sha) in new_entries {
        let mut t = Table::new();
        t["label"] = value(label);
        t["version"] = value(version);
        t["kind"] = value(kind_name(kind));
        t["status"] = value("active");
        t["bytecode_sha256"] = value(sha);
        arr.push(t);
    }
    std::fs::create_dir_all(manifest_path.parent().unwrap_or(canonical))
        .unwrap_or_else(|e| fail(e));
    std::fs::write(&manifest_path, doc.to_string()).unwrap_or_else(|e| fail(e));
    std::fs::write(
        canonical.join("resources/vk-tree.json"),
        read(&eid.join("noir/circuits/vk-tree.json")),
    )
    .unwrap_or_else(|e| fail(e));

    // Release assets: the bytecode of every active version.
    std::fs::create_dir_all(assets).unwrap_or_else(|e| fail(e));
    let versions: BTreeMap<String, String> = doc["circuit"]
        .as_array_of_tables()
        .into_iter()
        .flatten()
        .filter(|t| t.get("status").and_then(|s| s.as_str()) == Some("active"))
        .map(|t| {
            (
                t["label"].as_str().unwrap_or_default().to_string(),
                t["version"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    for c in &compiled {
        if let Some(v) = versions.get(&c.label) {
            std::fs::write(assets.join(format!("{}@{v}.b64", c.label)), &c.bytecode_b64)
                .unwrap_or_else(|e| fail(e));
        }
    }
    println!(
        "freeze-circuits: {minted} versions minted, {} circuits active; release assets in {}",
        versions.len(),
        assets.display()
    );
}

fn derive_vk(c: &Compiled) -> Vec<u8> {
    let program =
        Program::from_parts(&c.label, &c.bytecode_b64, &c.abi).unwrap_or_else(|e| fail(e));
    chonk::compute_vk(&c.label, program.bytecode(), c.kind)
        .unwrap_or_else(|e| fail(e))
        .0
}
