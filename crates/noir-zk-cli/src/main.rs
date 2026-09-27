//! `noir-zk freeze`: the only step that reads compiled circuits and derives
//! their keys (ported from psonet's `pso-zk-circuits` xtask).
//!
//! Inputs: nargo's `target/` (`<label>.json` per circuit) and the Poseidon2
//! verification key tree the kernels check (`vk-tree.json`: `root`, and
//! `leaves` with `package`, `vk_hash`, `index`, `siblings`). It freezes every
//! leaf plus the `--hiding` circuit into `--out` (the crate that runs
//! `noir_zk_codegen::generate_registry` from its `build.rs`):
//!
//! - `resources/circuits/<label>/<version>/abi.json` and `circuit.vk` (the
//!   Chonk key, derived through the FFI);
//! - `circuits/manifest.toml`: one `[[circuit]]` per version with its kind,
//!   status and `bytecode_sha256`;
//! - `resources/vk-tree.json`, checked leaf by leaf: the Poseidon2 hash of
//!   each derived key must be the tree's;
//! - `--assets`/`<label>@<version>.b64`: the bytecode, published as release
//!   assets (too large for git) and fetched by hash.
//!
//! Kinds: `--hiding` is the hiding kernel, labels starting with
//! `--kernel-prefix` (default `kernel_`) are kernels, the rest are apps.
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
    eprintln!("noir-zk freeze: {msg}");
    std::process::exit(1)
}

struct Opts {
    target: PathBuf,
    vk_tree: PathBuf,
    out: PathBuf,
    assets: PathBuf,
    hiding: String,
    kernel_prefix: String,
    check: bool,
    abi_change: bool,
}

impl Opts {
    fn kind_of(&self, label: &str) -> CircuitKind {
        if label == self.hiding {
            CircuitKind::Hiding
        } else if label.starts_with(&self.kernel_prefix) {
            CircuitKind::Kernel
        } else {
            CircuitKind::App
        }
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
    noir: String,
}

const USAGE: &str = "usage: noir-zk freeze --target DIR --vk-tree FILE --out DIR --assets DIR \
[--hiding LABEL] [--kernel-prefix PREFIX] [--check | --abi-change]";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) != Some("freeze") {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }
    let mut o = Opts {
        target: PathBuf::new(),
        vk_tree: PathBuf::new(),
        out: PathBuf::new(),
        assets: PathBuf::new(),
        hiding: "kernel_hiding".into(),
        kernel_prefix: "kernel_".into(),
        check: false,
        abi_change: false,
    };
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        let mut val = || {
            it.next()
                .cloned()
                .unwrap_or_else(|| fail(format!("{a} needs a value")))
        };
        match a.as_str() {
            "--check" => o.check = true,
            "--abi-change" => o.abi_change = true,
            "--target" => o.target = val().into(),
            "--vk-tree" => o.vk_tree = val().into(),
            "--out" => o.out = val().into(),
            "--assets" => o.assets = val().into(),
            "--hiding" => o.hiding = val(),
            "--kernel-prefix" => o.kernel_prefix = val(),
            other => fail(format!("unknown flag {other:?}\n{USAGE}")),
        }
    }
    for (flag, p) in [
        ("--target", &o.target),
        ("--vk-tree", &o.vk_tree),
        ("--out", &o.out),
        ("--assets", &o.assets),
    ] {
        if p.as_os_str().is_empty() {
            fail(format!("{flag} is required\n{USAGE}"));
        }
    }
    if o.check && o.abi_change {
        fail("--check mints nothing, so --abi-change with it is a mistake");
    }
    freeze(&o);
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())))
}

fn freeze(o: &Opts) {
    let (out, assets, check, abi_change) = (&o.out, &o.assets, o.check, o.abi_change);
    let tree: serde_json::Value = serde_json::from_str(&read(&o.vk_tree))
        .unwrap_or_else(|e| fail(format!("vk-tree.json: {e}")));
    let leaves = tree["leaves"]
        .as_array()
        .unwrap_or_else(|| fail("vk-tree.json has no leaves"));
    let mut labels: Vec<String> = leaves
        .iter()
        .filter_map(|l| l["package"].as_str().map(str::to_string))
        .collect();
    labels.push(o.hiding.clone());

    let compiled: Vec<Compiled> = labels
        .iter()
        .map(|label| {
            let v: serde_json::Value =
                serde_json::from_str(&read(&o.target.join(format!("{label}.json"))))
                    .unwrap_or_else(|e| fail(format!("{label}: {e}")));
            let bytecode_b64 = v["bytecode"]
                .as_str()
                .unwrap_or_else(|| fail(format!("{label}: no bytecode")))
                .to_string();
            Compiled {
                label: label.clone(),
                kind: o.kind_of(label),
                noir: v["noir_version"]
                    .as_str()
                    .unwrap_or("unknown")
                    .split('+')
                    .next()
                    .unwrap_or_default()
                    .to_string(),
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

    let manifest_path = out.join("circuits/manifest.toml");
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
        let dir_of = |v: &str| out.join(format!("resources/circuits/{}/{v}", c.label));
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
        println!("noir-zk freeze --check: {} circuits match", compiled.len());
        return;
    }

    if doc.get("circuit").is_none() {
        doc["proof_system"] = value("chonk");
        doc["circuit"] = toml_edit::Item::ArrayOfTables(ArrayOfTables::new());
    }
    doc["noir"] = value(compiled.first().map_or("unknown", |c| c.noir.as_str()));
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
    std::fs::create_dir_all(manifest_path.parent().unwrap_or(out)).unwrap_or_else(|e| fail(e));
    std::fs::write(&manifest_path, doc.to_string()).unwrap_or_else(|e| fail(e));
    std::fs::write(out.join("resources/vk-tree.json"), read(&o.vk_tree))
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
        "noir-zk freeze: {minted} versions minted, {} circuits active; release assets in {}",
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
