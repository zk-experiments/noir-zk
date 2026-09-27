//! Rust code generation for Noir circuits: typed inputs from nargo ABIs, and
//! a frozen registry of circuit identities and Chonk verification keys.
//!
//! A crate calls it from its `build.rs` (as a build-dependency) instead of
//! carrying its own generator.
//!
//! ```ignore
//! // build.rs: typed inputs for a workspace's compiled circuits
//! fn main() {
//!     let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
//!     let abis = noir_zk_codegen::nargo_target_abis("../target", |n| n.starts_with("dsc_")).unwrap();
//!     std::fs::write(out.join("circuits.rs"), noir_zk_codegen::generate_types(&abis)).unwrap();
//! }
//! ```
//!
//! Generated code uses `noir-zk-core`'s `Circuit` / `CircuitId`; registry
//! code also its `RegistryEntry` and `Status`.

#![allow(clippy::panic, clippy::unwrap_used, clippy::expect_used)] // build-time codegen: fail loudly

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha256};

fn camel(s: &str) -> String {
    s.split('_')
        .map(|p| {
            let mut c = p.chars();
            c.next().map_or(String::new(), |f| {
                format!("{}{}", f.to_uppercase(), c.as_str())
            })
        })
        .collect()
}

fn hex32(s: &str) -> String {
    let h = s.trim_start_matches("0x");
    assert_eq!(h.len(), 64, "expected 32-byte hex, got {s}");
    let bytes: Vec<String> = (0..32)
        .map(|i| format!("0x{}", &h[2 * i..2 * i + 2]))
        .collect();
    format!("[{}]", bytes.join(", "))
}

/// Rust types for one circuit's ABI: struct definitions named by their Noir
/// path, suffixed with their array lengths when one path has several shapes.
struct Types {
    defs: BTreeMap<String, String>,
    names: BTreeMap<String, String>,
}

impl Types {
    fn signature(ty: &Value) -> String {
        ty.to_string()
    }

    fn rust(&mut self, ty: &Value, all: &[Value]) -> String {
        match ty["kind"].as_str() {
            Some("field") => "Fr".into(),
            Some("boolean") => "bool".into(),
            Some("integer") => {
                assert_eq!(ty["sign"], "unsigned", "signed integers are not supported");
                format!("u{}", ty["width"])
            }
            Some("array") => format!("[{}; {}]", self.rust(&ty["type"], all), ty["length"]),
            Some("struct") => self.strukt(ty, all),
            other => panic!("unsupported ABI kind {other:?}"),
        }
    }

    fn strukt(&mut self, ty: &Value, all: &[Value]) -> String {
        let sig = Self::signature(ty);
        if let Some(n) = self.names.get(&sig) {
            return n.clone();
        }
        let path = ty["path"].as_str().unwrap_or("Struct");
        let base = camel(path.rsplit("::").next().unwrap_or(path));
        // Several shapes of one path in this circuit: suffix the array lengths.
        let shapes = all
            .iter()
            .filter(|t| t["path"] == ty["path"] && Self::signature(t) != sig)
            .count();
        let name = if shapes == 0 {
            base
        } else {
            let lens: Vec<String> = ty["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|f| f["type"]["length"].as_u64().map(|l| l.to_string()))
                .collect();
            format!("{base}{}", lens.join("x"))
        };
        self.names.insert(sig, name.clone());
        let fields: Vec<(String, String)> = ty["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|f| {
                (
                    f["name"].as_str().unwrap_or("field").to_string(),
                    self.rust(&f["type"], all),
                )
            })
            .collect();
        let def = struct_def(&name, &format!("`{path}`."), &fields);
        self.defs.insert(name.clone(), def);
        name
    }
}

/// A struct with public fields and its `FromFields` impl (fields read in
/// declaration order, which is ABI order).
fn struct_def(name: &str, doc: &str, fields: &[(String, String)]) -> String {
    let mut def = format!(
        "    /// {doc}\n    #[derive(Clone, Debug, PartialEq, Eq)]\n    pub struct {name} {{\n"
    );
    for (f, t) in fields {
        writeln!(def, "        pub {f}: {t},").ok();
    }
    def.push_str("    }\n\n");
    let count: Vec<String> = fields
        .iter()
        .map(|(_, t)| format!("<{t} as noir_zk_core::FromFields>::FIELDS"))
        .collect();
    let reads: Vec<String> = fields
        .iter()
        .map(|(f, t)| format!("            {f}: <{t} as noir_zk_core::FromFields>::read(r)?,\n"))
        .collect();
    writeln!(
        def,
        "    impl noir_zk_core::FromFields for {name} {{\n        const FIELDS: usize = 0{};\n        fn read(r: &mut noir_zk_core::FieldReader<'_>) -> Result<Self, noir_zk_core::Error> {{\n            Ok(Self {{\n{}            }})\n        }}\n    }}",
        count.iter().map(|c| format!(" + {c}")).collect::<String>(),
        reads.concat().replace("            ", "                "),
    )
    .ok();
    def
}

/// Every struct type reachable from `ty` (to detect shapes sharing a path).
fn collect_structs(ty: &Value, out: &mut Vec<Value>) {
    match ty["kind"].as_str() {
        Some("struct") => {
            out.push(ty.clone());
            for f in ty["fields"].as_array().into_iter().flatten() {
                collect_structs(&f["type"], out);
            }
        }
        Some("array") => collect_structs(&ty["type"], out),
        _ => {}
    }
}

/// Code pushing `expr`'s field elements onto `v`, in ACIR witness order.
fn flatten(ty: &Value, expr: &str, depth: usize, out: &mut String) {
    let pad = format!("            {}", "    ".repeat(depth));
    match ty["kind"].as_str() {
        Some("field") => writeln!(out, "{pad}v.push({expr});"),
        Some("boolean") | Some("integer") => writeln!(out, "{pad}v.push(Fr::from({expr}));"),
        Some("array") => {
            let var = format!("e{depth}");
            writeln!(out, "{pad}for {var} in {expr}.iter() {{").ok();
            flatten(&ty["type"], &format!("*{var}"), depth + 1, out);
            writeln!(out, "{pad}}}")
        }
        Some("struct") => {
            // Fields of an array element: `e0.name` (auto-deref), not `*e0.name`.
            let base = expr.strip_prefix('*').unwrap_or(expr);
            for f in ty["fields"].as_array().into_iter().flatten() {
                let name = f["name"].as_str().unwrap_or("field");
                flatten(&f["type"], &format!("{base}.{name}"), depth, out);
            }
            Ok(())
        }
        other => panic!("unsupported ABI kind {other:?}"),
    }
    .ok();
}

fn field_count(ty: &Value) -> u64 {
    match ty["kind"].as_str() {
        Some("array") => ty["length"].as_u64().unwrap_or(0) * field_count(&ty["type"]),
        Some("struct") => ty["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|f| field_count(&f["type"]))
            .sum(),
        _ => 1,
    }
}

/// One circuit's ABI (nargo's `abi` JSON) under its package name.
pub struct CircuitAbi {
    /// Package name (becomes the module name).
    pub label: String,
    /// nargo's ABI.
    pub abi: Value,
}

/// The ABIs of the compiled circuits in a nargo `target/` directory whose
/// package name passes `keep`, sorted by name.
pub fn nargo_target_abis(
    target: impl AsRef<Path>,
    keep: impl Fn(&str) -> bool,
) -> std::io::Result<Vec<CircuitAbi>> {
    let mut out = vec![];
    for entry in std::fs::read_dir(target)? {
        let path = entry?.path();
        let Some(name) = path
            .file_stem()
            .and_then(|s| s.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if path.extension().is_some_and(|e| e == "json") && keep(&name) {
            let v: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
            out.push(CircuitAbi {
                label: name,
                abi: v["abi"].clone(),
            });
        }
    }
    out.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(out)
}

/// `main` parameters a kernel may have (the noir-zk kernel convention).
const KERNEL_PARAMS: [&str; 5] = ["prev", "step", "prev_vk", "step_vk", "vk_tree_root"];

/// Whether `abi` follows the kernel convention (every parameter is one of
/// [`KERNEL_PARAMS`]).
fn is_kernel(abi: &Value) -> bool {
    abi["parameters"].as_array().is_some_and(|ps| {
        ps.iter()
            .all(|p| KERNEL_PARAMS.contains(&p["name"].as_str().unwrap_or_default()))
    })
}

/// A module for one circuit: its typed inputs and outputs, and a marker
/// implementing `noir_zk_core::Circuit` (flattening inputs in ACIR witness
/// order). With `identity` (a `CircuitId` impl body, and `Honk`, `App`,
/// `Kernel` or `Hiding`) it also implements `CircuitId` and `Honk`, `App` or
/// `Kernel`.
fn circuit_module(label: &str, abi: &Value, doc: &str, identity: Option<(&str, &str)>) -> String {
    let params = abi["parameters"].as_array().expect("parameters");
    let ret = abi["return_type"].get("abi_type");
    let mut all = vec![];
    for p in params {
        collect_structs(&p["type"], &mut all);
    }
    if let Some(r) = ret {
        collect_structs(r, &mut all);
    }
    let mut types = Types {
        defs: BTreeMap::new(),
        names: BTreeMap::new(),
    };
    // `pub` parameters go to `PublicInputs` (UltraHonk's claim), the rest to
    // `Inputs`; witness order interleaves them as the ABI declares them.
    let (mut fields, mut public) = (vec![], vec![]);
    let (mut flat, mut flat_public) = (String::new(), String::new());
    for p in params {
        let name = p["name"].as_str().expect("param name");
        let t = types.rust(&p["type"], &all);
        if p["visibility"] == "public" {
            public.push((name.to_string(), t));
            flatten(&p["type"], &format!("p.{name}"), 0, &mut flat);
            flatten(&p["type"], &format!("p.{name}"), 0, &mut flat_public);
        } else {
            fields.push((name.to_string(), t));
            flatten(&p["type"], &format!("w.{name}"), 0, &mut flat);
        }
    }
    let mut inputs = struct_def(
        "Inputs",
        "The private `main` parameters, in ABI order.",
        &fields,
    );
    let public_type = if public.is_empty() {
        "()"
    } else {
        inputs.push('\n');
        inputs.push_str(&struct_def(
            "PublicInputs",
            "The `pub` `main` parameters, in ABI order.",
            &public,
        ));
        "PublicInputs"
    };
    let out_type = ret.map_or("()".to_string(), |r| types.rust(r, &all));
    let outputs = ret.map_or(0, field_count);
    // A hiding kernel's `vk_tree_root` output, which verifiers must check.
    let root_at = ret
        .filter(|r| r["kind"] == "struct")
        .and_then(|r| {
            let fs = r["fields"].as_array()?;
            let i = fs.iter().position(|f| f["name"] == "vk_tree_root")?;
            Some(fs[..i].iter().map(|f| field_count(&f["type"])).sum::<u64>())
        })
        .map_or("None".to_string(), |i| format!("Some({i})"));
    let marker = camel(label);
    let mut code = format!("/// {doc}\npub mod {label} {{\n    use noir_zk_core::Field as Fr;\n\n");
    for def in types.defs.values() {
        writeln!(code, "{def}").ok();
    }
    writeln!(
        code,
        "{inputs}\n    /// What `main` returns (through the databus, or public for a hiding kernel).\n    pub type Outputs = {out_type};\n\n    /// Field elements the circuit returns.\n    pub const OUTPUT_FIELDS: usize = {outputs};\n\n    /// The `{label}` circuit.\n    pub struct {marker};\n\n    impl noir_zk_core::Circuit for {marker} {{\n        type Witness = Inputs;\n        type PublicInputs = {public_type};\n        type Outputs = Outputs;\n        const VK_TREE_ROOT_OUTPUT: Option<usize> = {root_at};\n        #[allow(unused_mut, unused_variables)]\n        fn public_inputs(p: &{public_type}) -> Vec<Fr> {{\n            let mut v = Vec::new();\n{flat_public}            v\n        }}\n        #[allow(unused_variables)]\n        fn witness_inputs(w: &Inputs, p: &{public_type}) -> Vec<Fr> {{\n            let mut v = Vec::new();\n{flat}            v\n        }}\n    }}"
    )
    .ok();
    if let Some((id, kind)) = identity {
        writeln!(
            code,
            "\n    impl noir_zk_core::CircuitId for {marker} {{\n{id}    }}"
        )
        .ok();
        if kind == "Honk" {
            writeln!(code, "\n    impl noir_zk_core::Honk for {marker} {{}}").ok();
        } else if kind == "App" {
            writeln!(code, "\n    impl noir_zk_core::App for {marker} {{}}").ok();
        } else {
            assert!(
                is_kernel(abi),
                "{label}: a kernel's parameters must be among {KERNEL_PARAMS:?}"
            );
            let ty = |n: &str| {
                fields
                    .iter()
                    .find(|(f, _)| f == n)
                    .map_or("()".to_string(), |(_, t)| t.clone())
            };
            let mut body = String::new();
            for (f, _) in &fields {
                let v = match f.as_str() {
                    "prev" | "step" | "vk_tree_root" => format!("k.{f}"),
                    vk => format!("noir_zk_core::KernelInputs::<Self::Prev, Self::Step>::vk(&k.{vk}, \"{vk}\")?"),
                };
                writeln!(body, "                {f}: {v},").ok();
            }
            writeln!(
                code,
                "\n    impl noir_zk_core::Kernel for {marker} {{\n        type Prev = {};\n        type Step = {};\n        fn witness(k: noir_zk_core::KernelInputs<Self::Prev, Self::Step>) -> Result<Inputs, noir_zk_core::Error> {{\n            Ok(Inputs {{\n{body}            }})\n        }}\n    }}",
                ty("prev"),
                ty("step"),
            )
            .ok();
        }
    }
    code.push_str("}\n\n");
    code
}

/// Typed inputs and `Circuit` impls for `abis` (no identities or keys): the
/// generated code depends only on `noir-zk-core`.
pub fn generate_types(abis: &[CircuitAbi]) -> String {
    let mut code = String::from("// @generated by noir-zk-codegen. Do not edit.\n\n");
    for c in abis {
        code.push_str(&circuit_module(
            &c.label,
            &c.abi,
            &format!("`{}`.", c.label),
            None,
        ));
    }
    code
}

/// A frozen registry (written by `noir-zk freeze`): typed modules for every active
/// circuit with its `CircuitId` (embedded key), `REGISTRY`, `VK_TREE_ROOT` and
/// the toolchain versions, from `dir/circuits/manifest.toml`,
/// `dir/resources/circuits` and `dir/resources/vk-tree.json` (if any). `dir` must be
/// the host crate's `CARGO_MANIFEST_DIR` (the generated `include_bytes!`
/// paths are relative to it).
pub fn generate_registry(dir: &Path) -> String {
    let manifest_path = dir.join("circuits/manifest.toml");
    let tree_path = dir.join("resources/vk-tree.json");

    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(&manifest_path).expect("manifest.toml"))
            .expect("parse manifest.toml");
    // No key tree for registries without Chonk kernels.
    let tree: Value = std::fs::read_to_string(&tree_path).map_or(Value::Null, |t| {
        serde_json::from_str(&t).expect("parse vk-tree.json")
    });
    let paths: BTreeMap<String, (u64, Vec<String>)> = tree["leaves"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|l| {
            (
                l["package"].as_str().expect("package").to_string(),
                (
                    l["index"].as_u64().expect("index"),
                    l["siblings"]
                        .as_array()
                        .expect("siblings")
                        .iter()
                        .map(|s| s.as_str().expect("hex").to_string())
                        .collect(),
                ),
            )
        })
        .collect();

    let mut code = String::from(
        "// @generated by noir-zk-codegen from circuits/manifest.toml and resources/. Do not edit.\n\n",
    );
    for key in ["noir", "bb"] {
        let v = manifest[key].as_str().expect("toolchain pin");
        writeln!(code, "/// {key} version the frozen artifacts were built with.\npub const {}_VERSION: &str = {v:?};", key.to_uppercase()).ok();
    }
    writeln!(code, "/// Root of the verification key tree the kernels check (zero without one).\npub const VK_TREE_ROOT: [u8; 32] = {};\n", manifest.get("vk_tree_root").map_or_else(|| hex32(&"0".repeat(64)), |r| hex32(r.as_str().expect("vk_tree_root")))).ok();

    let mut apps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut kernels_with_step: Vec<(String, String)> = vec![];
    let mut registry = String::from(
        "/// Every frozen circuit version.\npub const REGISTRY: &[noir_zk_core::RegistryEntry] = &[\n",
    );
    for c in manifest["circuit"].as_array().expect("[[circuit]]") {
        let label = c["label"].as_str().expect("label");
        let version = c["version"].as_str().expect("version");
        let status = c["status"].as_str().expect("status");
        let (kind, system) = match (
            c["system"].as_str().expect("system"),
            c.get("role").and_then(|r| r.as_str()),
        ) {
            ("ultra_honk", _) => {
                let oracle = match c.get("oracle").and_then(|o| o.as_str()) {
                    Some("keccak") => "Keccak",
                    Some("poseidon2") => "Poseidon2",
                    o => panic!("{label}: unknown oracle {o:?}"),
                };
                (
                    "Honk",
                    format!("noir_zk_core::ProofSystem::UltraHonk(noir_zk_core::Oracle::{oracle})"),
                )
            }
            ("chonk", Some(role)) => {
                let role = match role {
                    "app" => "App",
                    "kernel" => "Kernel",
                    "hiding" => "Hiding",
                    r => panic!("{label}: unknown Chonk role {r}"),
                };
                (
                    role,
                    format!("noir_zk_core::ProofSystem::Chonk(noir_zk_core::ChonkRole::{role})"),
                )
            }
            (s, r) => panic!("{label}: unknown proof system {s} (role {r:?})"),
        };
        let rel = format!("resources/circuits/{label}/{version}");
        let abi_file = dir.join(&rel).join("abi.json");
        let res = |f: &str| format!("concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{rel}/{f}\")");
        let (index, siblings) = match (status, paths.get(label)) {
            ("active", Some((i, s))) => (
                format!("Some({i})"),
                s.iter().map(|h| hex32(h)).collect::<Vec<_>>().join(", "),
            ),
            _ => ("None".into(), String::new()),
        };
        // The key's pin: recorded by freeze, and it must be the embedded key's.
        let vk_file = dir.join(&rel).join("circuit.vk");
        let vk_hash = hex::encode(Sha256::digest(
            std::fs::read(&vk_file).unwrap_or_else(|e| panic!("{}: {e}", vk_file.display())),
        ));
        let recorded = c
            .get("vk_sha256")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{label}@{version}: no vk_sha256 (rerun noir-zk freeze)"));
        assert_eq!(
            recorded, vk_hash,
            "{label}@{version}: vk_sha256 doesn't match circuit.vk"
        );
        let vk_sha = hex32(&vk_hash);
        let status_v = match status {
            "active" => "Active",
            "deprecated" => "Deprecated",
            s => panic!("{label}: unknown status {s}"),
        };
        writeln!(
            registry,
            "    noir_zk_core::RegistryEntry {{\n        label: {label:?},\n        version: {version:?},\n        system: {system},\n        status: noir_zk_core::Status::{status_v},\n        bytecode_sha256: {},\n        vk_sha256: {vk_sha},\n        abi: {},\n        vk: include_bytes!({}),\n        vk_index: {index},\n        vk_siblings: &[{siblings}],\n    }},",
            hex32(c["bytecode_sha256"].as_str().expect("bytecode_sha256")),
            if status == "active" { format!("Some(include_str!({}))", res("abi.json")) } else { "None".into() },
            res("circuit.vk"),
        )
        .ok();

        if status != "active" {
            continue;
        }
        let abi: Value =
            serde_json::from_str(&std::fs::read_to_string(&abi_file).expect("abi.json"))
                .expect("parse abi.json");
        let id = format!(
            "        const LABEL: &'static str = {label:?};\n        const VERSION: &'static str = {version:?};\n        const SYSTEM: noir_zk_core::ProofSystem = {system};\n        const BYTECODE_SHA256: [u8; 32] = {};\n        const VK_BYTES: &'static [u8] = include_bytes!({});\n        const VK_SHA256: [u8; 32] = {vk_sha};\n",
            hex32(c["bytecode_sha256"].as_str().expect("sha")),
            res("circuit.vk"),
        );
        code.push_str(&circuit_module(
            label,
            &abi,
            &format!("`{label}` {version} ({kind})."),
            Some((&id, kind)),
        ));
        if kind == "Kernel" || kind == "Hiding" {
            if let Some(step) = abi["parameters"]
                .as_array()
                .and_then(|ps| ps.iter().find(|p| p["name"] == "step"))
            {
                kernels_with_step.push((label.to_string(), step["type"].to_string()));
            }
        }
        if kind == "App" {
            // Apps returning the same type share a dispatch; a struct output
            // is its module's own type, so it dispatches alone.
            let ret = &abi["return_type"]["abi_type"];
            let mut structs = vec![];
            collect_structs(ret, &mut structs);
            let key = if structs.is_empty() {
                ret.to_string()
            } else {
                label.to_string()
            };
            apps.entry(key).or_default().push(label.to_string());
        }
    }
    registry.push_str("];\n");
    code.push_str(&registry);
    code.push_str("\n/// Static dispatch from an app label to its circuit type (`noir_zk_core::AppDispatch`).\npub struct Registry;\n");
    for labels in apps.values() {
        let out = format!(
            "<{}::{} as noir_zk_core::Circuit>::Outputs",
            labels[0],
            camel(&labels[0])
        );
        let arms: String = labels
            .iter()
            .map(|l| {
                format!(
                    "            {l:?} => Some(v.visit::<{l}::{}>()),\n",
                    camel(l)
                )
            })
            .collect();
        writeln!(
            code,
            "\nimpl noir_zk_core::AppDispatch<{out}> for Registry {{\n    fn visit_app<V: noir_zk_core::AppVisitor<{out}>>(label: &str, v: V) -> Option<V::Output> {{\n        match label {{\n{arms}            _ => None,\n        }}\n    }}\n}}"
        )
        .ok();
    }
    // Kernels that fold an app: wrap one, typed or chosen at runtime.
    for (label, step) in &kernels_with_step {
        let marker = format!("{label}::{}", camel(label));
        let select = if apps.contains_key(step) {
            "\n    /// Wraps the app `label` (chosen at runtime) with its `Prover.toml` inputs; fails unless it is an app this kernel folds.\n    pub fn select<'i>(label: &str, toml: &'i str) -> Result<noir_zk_core::Wrapped<'i, Self>, noir_zk_core::Error> {\n        noir_zk_core::Wrapped::select::<Registry>(label, toml)\n    }\n".to_string()
        } else {
            String::new()
        };
        writeln!(
            code,
            "\nimpl {marker} {{\n    /// Wraps app `C` (typed witness) to be folded by this kernel.\n    pub fn wrap<C: noir_zk_core::App<Outputs = <Self as noir_zk_core::Kernel>::Step>>(witness: &C::Witness) -> noir_zk_core::Wrapped<'static, Self> {{\n        noir_zk_core::Wrapped::new::<C>(witness)\n    }}\n{select}}}"
        )
        .ok();
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn abi() -> Value {
        let path = |h: u64| {
            serde_json::json!({"kind": "struct", "path": "lib::MerklePath", "fields": [
                {"name": "index", "type": {"kind": "field"}},
                {"name": "siblings", "type": {"kind": "array", "length": h, "type": {"kind": "field"}}}
            ]})
        };
        serde_json::json!({
            "parameters": [
                {"name": "flag", "type": {"kind": "boolean"}, "visibility": "private"},
                {"name": "a", "type": path(16), "visibility": "private"},
                {"name": "b", "type": path(14), "visibility": "private"},
                {"name": "bytes", "type": {"kind": "array", "length": 2, "type": {"kind": "integer", "sign": "unsigned", "width": 8}}, "visibility": "private"}
            ],
            "return_type": {"abi_type": {"kind": "array", "length": 3, "type": {"kind": "field"}}, "visibility": "databus"}
        })
    }

    #[test]
    fn names_shapes_of_one_path_apart() {
        let code = generate_types(&[CircuitAbi {
            label: "demo_circuit".into(),
            abi: abi(),
        }]);
        assert!(code.contains("pub struct MerklePath16"));
        assert!(code.contains("pub struct MerklePath14"));
        assert!(code.contains("pub a: MerklePath16,"));
        assert!(code.contains("pub bytes: [u8; 2],"));
        assert!(code.contains("pub struct DemoCircuit;"));
        assert!(code.contains("pub const OUTPUT_FIELDS: usize = 3;"));
    }

    #[test]
    fn flattens_in_abi_order() {
        let code = generate_types(&[CircuitAbi {
            label: "demo_circuit".into(),
            abi: abi(),
        }]);
        let order = [
            "w.flag",
            "w.a.index",
            "w.a.siblings",
            "w.b.index",
            "w.b.siblings",
            "w.bytes",
        ];
        let pos: Vec<usize> = order.iter().map(|o| code.find(o).unwrap()).collect();
        assert!(pos.windows(2).all(|w| w[0] < w[1]), "{pos:?}");
    }
}
