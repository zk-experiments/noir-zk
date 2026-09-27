//! Rust code generation for Noir circuits: typed inputs from nargo ABIs, and
//! a frozen registry of circuit identities and Chonk verification keys.
//!
//! Ported from `pso-zk-canonical`'s build script and made reusable: a crate
//! calls it from its `build.rs` (as a build-dependency) instead of carrying a
//! copy of the generator.
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
        let mut def = format!("    /// `{path}`.\n    #[derive(Clone, Debug, PartialEq, Eq)]\n    pub struct {name} {{\n");
        for f in ty["fields"].as_array().into_iter().flatten() {
            let t = self.rust(&f["type"], all);
            writeln!(
                def,
                "        pub {}: {t},",
                f["name"].as_str().unwrap_or("field")
            )
            .ok();
        }
        def.push_str("    }\n");
        self.defs.insert(name.clone(), def);
        name
    }
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

/// A module for one circuit: its typed inputs, `OUTPUT_FIELDS`, and a marker
/// implementing `noir_zk_core::Circuit` (flattening inputs in ACIR witness
/// order); `identity` optionally adds a `noir_zk_core::CircuitId` impl body.
fn circuit_module(label: &str, abi: &Value, doc: &str, identity: Option<&str>) -> String {
    let params = abi["parameters"].as_array().expect("parameters");
    let mut all = vec![];
    for p in params {
        collect_structs(&p["type"], &mut all);
    }
    let mut types = Types {
        defs: BTreeMap::new(),
        names: BTreeMap::new(),
    };
    let mut inputs = String::from(
        "    /// Every `main` parameter, in ABI order.\n    #[derive(Clone, Debug, PartialEq, Eq)]\n    pub struct Inputs {\n",
    );
    let mut flat = String::new();
    for p in params {
        let name = p["name"].as_str().expect("param name");
        let t = types.rust(&p["type"], &all);
        writeln!(inputs, "        pub {name}: {t},").ok();
        flatten(&p["type"], &format!("w.{name}"), 0, &mut flat);
    }
    inputs.push_str("    }\n");
    let outputs = abi["return_type"].get("abi_type").map_or(0, field_count);
    let marker = camel(label);
    let mut code = format!("/// {doc}\npub mod {label} {{\n    use noir_zk_core::Field as Fr;\n\n");
    for def in types.defs.values() {
        writeln!(code, "{def}").ok();
    }
    writeln!(
        code,
        "{inputs}\n    /// Field elements the circuit returns (through the databus, or public for a hiding kernel).\n    pub const OUTPUT_FIELDS: usize = {outputs};\n\n    /// The `{label}` circuit.\n    pub struct {marker};\n\n    impl noir_zk_core::Circuit for {marker} {{\n        type Witness = Inputs;\n        type PublicInputs = ();\n        fn public_inputs(_: &()) -> Vec<Fr> {{\n            Vec::new()\n        }}\n        fn witness_inputs(w: &Inputs, _: &()) -> Vec<Fr> {{\n            let mut v = Vec::new();\n{flat}            v\n        }}\n    }}"
    )
    .ok();
    if let Some(id) = identity {
        writeln!(
            code,
            "\n    impl noir_zk_core::CircuitId for {marker} {{\n{id}    }}"
        )
        .ok();
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
/// `dir/resources/circuits` and `dir/resources/vk-tree.json`. `dir` must be
/// the host crate's `CARGO_MANIFEST_DIR` (the generated `include_bytes!`
/// paths are relative to it).
pub fn generate_registry(dir: &Path) -> String {
    let manifest_path = dir.join("circuits/manifest.toml");
    let tree_path = dir.join("resources/vk-tree.json");

    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(&manifest_path).expect("manifest.toml"))
            .expect("parse manifest.toml");
    let tree: Value =
        serde_json::from_str(&std::fs::read_to_string(&tree_path).expect("vk-tree.json"))
            .expect("parse vk-tree.json");
    let paths: BTreeMap<String, (u64, Vec<String>)> = tree["leaves"]
        .as_array()
        .expect("leaves")
        .iter()
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
    writeln!(code, "/// Root of the verification key tree the kernels check.\npub const VK_TREE_ROOT: [u8; 32] = {};\n", hex32(manifest["vk_tree_root"].as_str().expect("vk_tree_root"))).ok();

    let mut registry = String::from(
        "/// Every frozen circuit version.\npub const REGISTRY: &[noir_zk_core::RegistryEntry] = &[\n",
    );
    for c in manifest["circuit"].as_array().expect("[[circuit]]") {
        let label = c["label"].as_str().expect("label");
        let version = c["version"].as_str().expect("version");
        let status = c["status"].as_str().expect("status");
        let kind = match c["kind"].as_str().expect("kind") {
            "app" => "App",
            "kernel" => "Kernel",
            "hiding" => "Hiding",
            k => panic!("{label}: unknown kind {k}"),
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
        let status_v = match status {
            "active" => "Active",
            "deprecated" => "Deprecated",
            s => panic!("{label}: unknown status {s}"),
        };
        writeln!(
            registry,
            "    noir_zk_core::RegistryEntry {{\n        label: {label:?},\n        version: {version:?},\n        kind: noir_zk_core::CircuitKind::{kind},\n        status: noir_zk_core::Status::{status_v},\n        bytecode_sha256: {},\n        abi: {},\n        vk: include_bytes!({}),\n        vk_index: {index},\n        vk_siblings: &[{siblings}],\n    }},",
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
            "        const LABEL: &'static str = {label:?};\n        const VERSION: &'static str = {version:?};\n        const KIND: noir_zk_core::CircuitKind = noir_zk_core::CircuitKind::{kind};\n        const BYTECODE_SHA256: [u8; 32] = {};\n        const VK_BYTES: &'static [u8] = include_bytes!({});\n",
            hex32(c["bytecode_sha256"].as_str().expect("sha")),
            res("circuit.vk"),
        );
        code.push_str(&circuit_module(
            label,
            &abi,
            &format!("`{label}` {version} ({kind})."),
            Some(&id),
        ));
    }
    registry.push_str("];\n");
    code.push_str(&registry);
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
