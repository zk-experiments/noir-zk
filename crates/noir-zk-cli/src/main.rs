//! `noir-zk freeze`: the only step that reads compiled circuits and derives
//! their keys (ported from psonet's `pso-zk-circuits` xtask).
//!
//! Inputs: nargo's `target/` (`<label>.json` per circuit; `--exclude`
//! prefixes skip some) and, for Chonk kernels, the Poseidon2 verification key
//! tree they check (`--vk-tree`: `root`, and `leaves` with `package`,
//! `vk_hash`, `index`, `siblings`). Everything is frozen into `--out` (the
//! crate that runs `noir_zk_codegen::generate_registry` from its `build.rs`):
//!
//! - `resources/circuits/<label>/<version>/abi.json` and `circuit.vk` (the
//!   verification key, derived through the FFI);
//! - `circuits/manifest.toml`: one `[[circuit]]` per version with its proof
//!   system, status, `bytecode_sha256` and `vk_sha256` (the pins a client
//!   checks downloads against);
//! - `resources/vk-tree.json`, checked leaf by leaf: the Poseidon2 hash of
//!   each derived key must be the tree's;
//! - `--assets`/`<label>@<version>.b64`: the bytecode, published as release
//!   assets (too large for git) and fetched by hash.
//!
//! The proof system comes from the ABI: a circuit using the databus is folded
//! by Chonk (UltraHonk rejects databus circuits) as a kernel if its parameters
//! follow the kernel convention (`prev`, `step`, `prev_vk`, `step_vk`,
//! `vk_tree_root`) — the hiding kernel if it returns `pub` — else as an app.
//! Any other circuit is proved by UltraHonk with the `--honk-oracle`
//! transcript hash (default `poseidon2`; `keccak` for EVM verifiers).
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
use noir_zk_backend::witness::Program;
use noir_zk_backend::{chonk, honk};
use noir_zk_core::{ChonkRole, Field, Oracle, ProofSystem};
use pso_poseidon::poseidon2::Poseidon2;
use sha2::{Digest, Sha256};
use toml_edit::{value, ArrayOfTables, DocumentMut, Table};

fn fail(msg: impl std::fmt::Display) -> ! {
    eprintln!("noir-zk freeze: {msg}");
    std::process::exit(1)
}

struct Opts {
    target: PathBuf,
    vk_tree: Option<PathBuf>,
    out: PathBuf,
    assets: PathBuf,
    exclude: Vec<String>,
    oracle: Oracle,
    check: bool,
    abi_change: bool,
}

/// First lines of every manifest freeze writes.
const MANIFEST_HEADER: &str = "# Written by noir-zk freeze; do not edit.\n\n";

const KERNEL_PARAMS: [&str; 5] = ["prev", "step", "prev_vk", "step_vk", "vk_tree_root"];

/// The proof system a circuit's ABI calls for (see the module docs).
fn system_of(label: &str, abi: &serde_json::Value, oracle: Oracle) -> ProofSystem {
    let params = abi["parameters"].as_array().cloned().unwrap_or_default();
    let ret = abi["return_type"]["visibility"].as_str();
    let databus = ret == Some("databus") || params.iter().any(|p| p["visibility"] == "databus");
    if !databus {
        return ProofSystem::UltraHonk(oracle);
    }
    if params.iter().any(|p| p["visibility"] == "public") {
        fail(format!(
            "{label}: a Chonk (databus) circuit can't have pub parameters"
        ));
    }
    let kernel = !params.is_empty()
        && params
            .iter()
            .all(|p| KERNEL_PARAMS.contains(&p["name"].as_str().unwrap_or_default()));
    ProofSystem::Chonk(match (kernel, ret) {
        (true, Some("public")) => ChonkRole::Hiding,
        (true, _) => ChonkRole::Kernel,
        (false, Some("public")) => fail(format!("{label}: a Chonk app can't return pub values")),
        (false, _) => ChonkRole::App,
    })
}

/// The manifest's `system`, `role` / `oracle` for a proof system.
fn system_fields(s: ProofSystem) -> [(&'static str, &'static str); 2] {
    match s {
        ProofSystem::UltraHonk(o) => [("system", "ultra_honk"), ("oracle", o.name())],
        ProofSystem::Chonk(r) => [
            ("system", "chonk"),
            (
                "role",
                match r {
                    ChonkRole::App => "app",
                    ChonkRole::Kernel => "kernel",
                    ChonkRole::Hiding => "hiding",
                },
            ),
        ],
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
    system: ProofSystem,
    bytecode_b64: String,
    abi: String,
    sha: String,
    noir: String,
}

const USAGE: &str = "usage: noir-zk freeze --target DIR --out DIR --assets DIR \
[--vk-tree FILE] [--exclude PREFIX].. [--honk-oracle poseidon2|keccak] [--check | --abi-change]
       noir-zk pack --out DIR --assets DIR --packs FILE --dest DIR [--version V]";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("pack") {
        pack(&args[1..]);
        return;
    }
    if args.first().map(String::as_str) != Some("freeze") {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }
    let mut o = Opts {
        target: PathBuf::new(),
        vk_tree: None,
        out: PathBuf::new(),
        assets: PathBuf::new(),
        exclude: vec![],
        oracle: Oracle::Poseidon2,
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
            "--vk-tree" => o.vk_tree = Some(val().into()),
            "--out" => o.out = val().into(),
            "--assets" => o.assets = val().into(),
            "--exclude" => o.exclude.push(val()),
            "--honk-oracle" => {
                o.oracle = match val().as_str() {
                    "poseidon2" => Oracle::Poseidon2,
                    "keccak" => Oracle::Keccak,
                    other => fail(format!("--honk-oracle {other:?}: poseidon2 or keccak")),
                }
            }
            other => fail(format!("unknown flag {other:?}\n{USAGE}")),
        }
    }
    for (flag, p) in [
        ("--target", &o.target),
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

/// `noir-zk pack`: for every table of the packs file with `circuits =
/// [labels]`, writes `<dest>/<name>@<version>.tar.gz` (`<name>.tar.gz`
/// without `--version`): per circuit its active version's bytecode (from
/// `--assets`, checked against the pin), verification key and ABI, plus the
/// key tree and the manifest's entries for them. Also writes
/// `catalog@<version>.json`: each pack's file, SHA-256, size and circuits,
/// the toolchain and key tree root, and the packs file's other tables (a
/// country map, say) as they are.
fn pack(args: &[String]) {
    let mut flags: BTreeMap<&str, String> = BTreeMap::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" | "--assets" | "--packs" | "--dest" | "--version" => {
                let v = it
                    .next()
                    .unwrap_or_else(|| fail(format!("{a} needs a value")));
                flags.insert(a.as_str(), v.clone());
            }
            other => fail(format!("unknown flag {other:?}\n{USAGE}")),
        }
    }
    let flag = |f: &str| -> PathBuf {
        flags
            .get(f)
            .map(PathBuf::from)
            .unwrap_or_else(|| fail(format!("{f} is required\n{USAGE}")))
    };
    let (out, assets, dest) = (flag("--out"), flag("--assets"), flag("--dest"));
    let suffix = flags
        .get("--version")
        .map_or(String::new(), |v| format!("@{v}"));
    let text = read(&out.join("circuits/manifest.toml"));
    let doc: DocumentMut = text
        .strip_prefix(MANIFEST_HEADER)
        .unwrap_or(&text)
        .parse()
        .unwrap_or_else(|e| fail(format!("manifest.toml: {e}")));
    let entries: &ArrayOfTables = doc["circuit"]
        .as_array_of_tables()
        .unwrap_or_else(|| fail("manifest has no circuits"));
    let active = |label: &str| {
        entries.iter().find(|t| {
            t.get("label").and_then(|v| v.as_str()) == Some(label)
                && t.get("status").and_then(|v| v.as_str()) == Some("active")
        })
    };
    let tree = std::fs::read(out.join("resources/vk-tree.json")).ok();
    let packs: toml::Table =
        toml::from_str(&read(&flag("--packs"))).unwrap_or_else(|e| fail(format!("packs: {e}")));
    std::fs::create_dir_all(&dest).unwrap_or_else(|e| fail(e));
    let mut catalog = serde_json::Map::new();
    catalog.insert("generated_by".into(), "noir-zk pack; do not edit".into());
    if let Some(v) = flags.get("--version") {
        catalog.insert("version".into(), v.as_str().into());
    }
    for key in ["noir", "bb", "vk_tree_root"] {
        if let Some(v) = doc.get(key).and_then(|v| v.as_str()) {
            catalog.insert(key.into(), v.into());
        }
    }
    let mut listed = serde_json::Map::new();
    for (name, p) in &packs {
        let Some(labels) = p.get("circuits").and_then(|c| c.as_array()) else {
            // Not a pack (a country map, say): carried into the catalog as is.
            catalog.insert(
                name.clone(),
                serde_json::to_value(p).unwrap_or_else(|e| fail(e)),
            );
            continue;
        };
        let mut files: Vec<(String, Vec<u8>)> = vec![];
        let mut subset = doc.clone();
        let kept = subset["circuit"]
            .as_array_of_tables_mut()
            .unwrap_or_else(|| fail("manifest has no circuits"));
        kept.clear();
        for l in labels {
            let label = l.as_str().unwrap_or_default();
            let t = active(label)
                .unwrap_or_else(|| fail(format!("pack {name}: {label} is not an active circuit")));
            let version = t["version"].as_str().unwrap_or_default();
            let asset = format!("{label}@{version}");
            let bytecode = std::fs::read(assets.join(format!("{asset}.b64")))
                .unwrap_or_else(|e| fail(format!("{asset}.b64: {e}")));
            if Some(hex::encode(Sha256::digest(&bytecode)).as_str())
                != t["bytecode_sha256"].as_str()
            {
                fail(format!("{asset}.b64: does not match its pinned hash"));
            }
            let res = out.join(format!("resources/circuits/{label}/{version}"));
            let vk = std::fs::read(res.join("circuit.vk"))
                .unwrap_or_else(|e| fail(format!("{asset}: circuit.vk: {e}")));
            let abi = std::fs::read(res.join("abi.json"))
                .unwrap_or_else(|e| fail(format!("{asset}: abi.json: {e}")));
            files.push((format!("{asset}.b64"), bytecode));
            files.push((format!("{asset}.vk"), vk));
            files.push((format!("{asset}.abi.json"), abi));
            kept.push(t.clone());
        }
        if let Some(tree) = &tree {
            files.push(("vk-tree.json".into(), tree.clone()));
        }
        files.push((
            "manifest.toml".into(),
            format!("{MANIFEST_HEADER}{subset}").into_bytes(),
        ));
        let file = format!("{name}{suffix}.tar.gz");
        let path = dest.join(&file);
        let mut archive = vec![];
        noir_zk_backend::pack::write_pack(&files, &mut archive).unwrap_or_else(|e| fail(e));
        std::fs::write(&path, &archive).unwrap_or_else(|e| fail(e));
        listed.insert(
            name.clone(),
            serde_json::json!({
                "file": file,
                "sha256": hex::encode(Sha256::digest(&archive)),
                "bytes": archive.len(),
                "circuits": labels.iter().filter_map(|l| l.as_str()).collect::<Vec<_>>(),
            }),
        );
        println!(
            "noir-zk pack: {} ({} circuits)",
            path.display(),
            labels.len()
        );
    }
    catalog.insert("packs".into(), listed.into());
    let path = dest.join(format!("catalog{suffix}.json"));
    let text = serde_json::to_string_pretty(&catalog).unwrap_or_else(|e| fail(e));
    std::fs::write(&path, format!("{text}\n")).unwrap_or_else(|e| fail(e));
    println!("noir-zk pack: {}", path.display());
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| fail(format!("{}: {e}", path.display())))
}

fn freeze(o: &Opts) {
    let (out, assets, check, abi_change) = (&o.out, &o.assets, o.check, o.abi_change);
    let tree: serde_json::Value = o.vk_tree.as_ref().map_or(serde_json::Value::Null, |p| {
        serde_json::from_str(&read(p)).unwrap_or_else(|e| fail(format!("vk-tree.json: {e}")))
    });
    let leaves = tree["leaves"].as_array().cloned().unwrap_or_default();
    let mut labels: Vec<String> = std::fs::read_dir(&o.target)
        .unwrap_or_else(|e| fail(format!("{}: {e}", o.target.display())))
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            let label = name.strip_suffix(".json")?.to_string();
            (!o.exclude.iter().any(|x| label.starts_with(x.as_str()))).then_some(label)
        })
        .collect();
    labels.sort();

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
                system: system_of(label, &v["abi"], o.oracle),
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
    // Kernels check every app and kernel they fold against the key tree.
    for c in &compiled {
        if matches!(
            c.system,
            ProofSystem::Chonk(ChonkRole::App | ChonkRole::Kernel)
        ) && !tree_hashes.contains_key(c.label.as_str())
        {
            fail(format!(
                "{}: a Chonk app or kernel must be a leaf of --vk-tree",
                c.label
            ));
        }
    }

    let manifest_path = out.join("circuits/manifest.toml");
    let text = std::fs::read_to_string(&manifest_path).unwrap_or_default();
    let mut doc: DocumentMut = text
        .strip_prefix(MANIFEST_HEADER)
        .unwrap_or(&text)
        .parse()
        .unwrap_or_else(|e| fail(format!("manifest.toml: {e}")));
    // Latest active entry per label: (index in the array, version, sha).
    let mut active: BTreeMap<String, (usize, String, String)> = BTreeMap::new();
    let mut recorded: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut vk_pins: BTreeMap<String, String> = BTreeMap::new();
    if let Some(arr) = doc.get("circuit").and_then(|c| c.as_array_of_tables()) {
        for (i, t) in arr.iter().enumerate() {
            if t.get("status").and_then(|s| s.as_str()) == Some("active") {
                let label = t["label"].as_str().unwrap_or_default().to_string();
                if let Some(pin) = t.get("vk_sha256").and_then(|v| v.as_str()) {
                    vk_pins.insert(label.clone(), pin.to_string());
                }
                recorded.insert(
                    label.clone(),
                    ["system", "role", "oracle"]
                        .iter()
                        .filter_map(|k| Some((k.to_string(), t.get(k)?.as_str()?.to_string())))
                        .collect(),
                );
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
    let mut new_entries: Vec<(String, String, ProofSystem, String, String)> = vec![];
    let mut deprecate: Vec<usize> = vec![];
    for c in &compiled {
        let prev = active.get(&c.label);
        let dir_of = |v: &str| out.join(format!("resources/circuits/{}/{v}", c.label));
        if let Some((_, v, sha)) = prev {
            if *sha == c.sha {
                if check {
                    let expected: Vec<(String, String)> = system_fields(c.system)
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    if recorded.get(&c.label) != Some(&expected) {
                        eprintln!(
                            "{}@{v}: recorded proof system differs from the ABI's",
                            c.label
                        );
                        failed += 1;
                    }
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
                    let committed_sha = hex::encode(Sha256::digest(&committed));
                    if vk_pins.get(&c.label) != Some(&committed_sha) {
                        eprintln!(
                            "{}@{v}: recorded vk_sha256 is missing or differs from the committed key",
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
            let fields = match c.system {
                ProofSystem::Chonk(role) => chonk::vk_fields(&vk, role),
                ProofSystem::UltraHonk(_) => {
                    fail(format!("{}: an UltraHonk circuit in the key tree", c.label))
                }
            }
            .unwrap_or_else(|e| fail(format!("{}: {e}", c.label)));
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
        new_entries.push((
            c.label.clone(),
            version,
            c.system,
            c.sha.clone(),
            hex::encode(Sha256::digest(&vk)),
        ));
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
        doc["circuit"] = toml_edit::Item::ArrayOfTables(ArrayOfTables::new());
    }
    doc["noir"] = value(compiled.first().map_or("unknown", |c| c.noir.as_str()));
    doc["bb"] = value(noir_zk_backend::BB_VERSION);
    match tree["root"].as_str() {
        Some(root) => doc["vk_tree_root"] = value(root),
        None => {
            doc.remove("vk_tree_root");
        }
    }
    let arr = doc["circuit"]
        .as_array_of_tables_mut()
        .unwrap_or_else(|| fail("manifest: circuit is not an array"));
    for i in deprecate {
        if let Some(t) = arr.get_mut(i) {
            t["status"] = value("deprecated");
        }
    }
    // Every version records its key's hash (entries frozen before it did get
    // it from their committed key).
    for t in arr.iter_mut() {
        if t.get("vk_sha256").is_none() {
            let (label, version) = (
                t["label"].as_str().unwrap_or_default().to_string(),
                t["version"].as_str().unwrap_or_default().to_string(),
            );
            let vk =
                std::fs::read(out.join(format!("resources/circuits/{label}/{version}/circuit.vk")))
                    .unwrap_or_else(|e| fail(format!("{label}@{version}: circuit.vk: {e}")));
            t["vk_sha256"] = value(hex::encode(Sha256::digest(&vk)));
        }
    }
    for (label, version, system, sha, vk_sha) in new_entries {
        let mut t = Table::new();
        t["label"] = value(label);
        t["version"] = value(version);
        for (k, v) in system_fields(system) {
            t[k] = value(v);
        }
        t["status"] = value("active");
        t["bytecode_sha256"] = value(sha);
        t["vk_sha256"] = value(vk_sha);
        arr.push(t);
    }
    std::fs::create_dir_all(manifest_path.parent().unwrap_or(out)).unwrap_or_else(|e| fail(e));
    std::fs::write(&manifest_path, format!("{MANIFEST_HEADER}{doc}")).unwrap_or_else(|e| fail(e));
    if let Some(path) = &o.vk_tree {
        // The frozen copy is freeze's output, so it says so.
        let mut tree = tree.clone();
        tree["generated_by"] = serde_json::Value::String(format!(
            "noir-zk freeze, from {}; do not edit",
            path.display()
        ));
        let text = serde_json::to_string_pretty(&tree).unwrap_or_else(|e| fail(e));
        std::fs::create_dir_all(out.join("resources")).unwrap_or_else(|e| fail(e));
        std::fs::write(out.join("resources/vk-tree.json"), format!("{text}\n"))
            .unwrap_or_else(|e| fail(e));
    }

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
    match c.system {
        ProofSystem::Chonk(role) => chonk::compute_vk(&c.label, program.bytecode(), role),
        ProofSystem::UltraHonk(oracle) => honk::compute_vk(&c.label, program.bytecode(), oracle),
    }
    .unwrap_or_else(|e| fail(e))
    .0
}
