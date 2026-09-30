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

mod pipelines;
mod tokens;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use serde_json::Value;
use sha2::{Digest, Sha256};

use tokens::{bytes32, doc, ident, u64_lit};

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

/// Parses the generated tokens as a Rust file and prints it: invalid Rust
/// fails here, at generation, rather than in the crate that includes it.
fn render(header: &str, code: TokenStream) -> String {
    let file: syn::File =
        syn::parse2(code).unwrap_or_else(|e| panic!("noir-zk-codegen generated invalid Rust: {e}"));
    format!("{header}{}", prettyplease::unparse(&file))
}

/// Rust types for one circuit's ABI: struct definitions named by their Noir
/// path, suffixed with their array lengths when one path has several shapes.
/// A name the module already uses (the circuit's marker, `Inputs`,
/// `PublicInputs`, `Outputs`, `Fr`) or another path's struct took is
/// qualified by the rest of the path (`lib::Move` → `LibMove`), then numbered.
struct Types {
    defs: BTreeMap<String, TokenStream>,
    names: BTreeMap<String, String>,
    reserved: Vec<String>,
}

impl Types {
    fn signature(ty: &Value) -> String {
        ty.to_string()
    }

    fn rust(&mut self, ty: &Value, all: &[Value]) -> TokenStream {
        match ty["kind"].as_str() {
            Some("field") => quote!(Fr),
            Some("boolean") => quote!(bool),
            Some("integer") => {
                assert_eq!(ty["sign"], "unsigned", "signed integers are not supported");
                let t = format_ident!("u{}", ty["width"].as_u64().expect("integer width"));
                quote!(#t)
            }
            Some("array") => {
                let t = self.rust(&ty["type"], all);
                let n = u64_lit(ty["length"].as_u64().expect("array length"));
                quote!([#t; #n])
            }
            Some("struct") => {
                let name = ident(&self.strukt(ty, all));
                quote!(#name)
            }
            other => panic!("unsupported ABI kind {other:?}"),
        }
    }

    fn strukt(&mut self, ty: &Value, all: &[Value]) -> String {
        let sig = Self::signature(ty);
        if let Some(n) = self.names.get(&sig) {
            return n.clone();
        }
        let path = ty["path"].as_str().unwrap_or("Struct");
        // Several shapes of one path in this circuit: suffix the array lengths.
        let shapes = all
            .iter()
            .filter(|t| t["path"] == ty["path"] && Self::signature(t) != sig)
            .count();
        let lens = if shapes == 0 {
            String::new()
        } else {
            ty["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|f| f["type"]["length"].as_u64().map(|l| l.to_string()))
                .collect::<Vec<_>>()
                .join("x")
        };
        let last = camel(path.rsplit("::").next().unwrap_or(path));
        let qualified: String = path.split("::").map(camel).collect();
        let taken = |n: &String| self.reserved.contains(n) || self.names.values().any(|m| m == n);
        let name = [format!("{last}{lens}"), format!("{qualified}{lens}")]
            .into_iter()
            .chain((2..).map(|i| format!("{qualified}{lens}{i}")))
            .find(|n| !taken(n))
            .expect("a free name");
        self.names.insert(sig, name.clone());
        let fields: Vec<(String, TokenStream)> = ty["fields"]
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
fn struct_def(name: &str, text: &str, fields: &[(String, TokenStream)]) -> TokenStream {
    let doc = doc(text);
    let name = ident(name);
    let names: Vec<_> = fields.iter().map(|(f, _)| ident(f)).collect();
    let types: Vec<_> = fields.iter().map(|(_, t)| t).collect();
    quote! {
        #doc
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct #name {
            #(pub #names: #types,)*
        }

        impl noir_zk_core::FromFields for #name {
            const FIELDS: usize = 0 #(+ <#types as noir_zk_core::FromFields>::FIELDS)*;
            fn read(r: &mut noir_zk_core::FieldReader<'_>) -> Result<Self, noir_zk_core::Error> {
                Ok(Self {
                    #(#names: <#types as noir_zk_core::FromFields>::read(r)?,)*
                })
            }
        }
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

/// An expression to flatten: a place (`w.a.index`), or a loop variable over
/// an array's elements (`e0`), which is a reference and is read as `*e0`.
struct Expr {
    place: TokenStream,
    element: bool,
}

/// Code pushing `expr`'s field elements onto `v`, in ACIR witness order.
fn flatten(ty: &Value, expr: &Expr, depth: usize) -> TokenStream {
    let place = &expr.place;
    let value = if expr.element {
        quote!(*#place)
    } else {
        quote!(#place)
    };
    match ty["kind"].as_str() {
        Some("field") => quote!(v.push(#value);),
        Some("boolean") | Some("integer") => quote!(v.push(Fr::from(#value));),
        Some("array") => {
            // Iterate by reference so nested arrays (`e0` is `&[T; N]`) and
            // struct elements both work: `for e1 in e0.iter()`.
            let var = format_ident!("e{depth}");
            let inner = flatten(
                &ty["type"],
                &Expr {
                    place: quote!(#var),
                    element: true,
                },
                depth + 1,
            );
            quote! {
                for #var in #place.iter() {
                    #inner
                }
            }
        }
        Some("struct") => {
            // Fields of an array element: `e0.name` (auto-deref), not `*e0.name`.
            ty["fields"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|f| {
                    let name = ident(f["name"].as_str().unwrap_or("field"));
                    flatten(
                        &f["type"],
                        &Expr {
                            place: quote!(#place.#name),
                            element: false,
                        },
                        depth,
                    )
                })
                .collect()
        }
        other => panic!("unsupported ABI kind {other:?}"),
    }
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

/// `main` parameters a kernel may have (the noir-zk kernel convention; the
/// pipeline kernels add `layout` and `deployment`).
const KERNEL_PARAMS: [&str; 7] = [
    "prev",
    "step",
    "prev_vk",
    "step_vk",
    "vk_tree_root",
    "layout",
    "deployment",
];

/// Whether `abi` follows the kernel convention (every parameter is one of
/// [`KERNEL_PARAMS`]).
fn is_kernel(abi: &Value) -> bool {
    abi["parameters"].as_array().is_some_and(|ps| {
        ps.iter()
            .all(|p| KERNEL_PARAMS.contains(&p["name"].as_str().unwrap_or_default()))
    })
}

/// A circuit's identity, for [`circuit_module`]: the body of its `CircuitId`
/// impl, and `Honk`, `App`, `Kernel` or `Hiding`.
struct Identity<'a> {
    consts: TokenStream,
    kind: &'a str,
}

/// A module for one circuit: its typed inputs and outputs, and a marker
/// implementing `noir_zk_core::Circuit` (flattening inputs in ACIR witness
/// order). With an identity it also implements `CircuitId` and `Honk`,
/// `App` or `Kernel`.
fn circuit_module(
    label: &str,
    abi: &Value,
    text: &str,
    identity: Option<Identity<'_>>,
) -> TokenStream {
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
        reserved: [
            camel(label).as_str(),
            "Inputs",
            "PublicInputs",
            "Outputs",
            "Fr",
        ]
        .map(str::to_string)
        .to_vec(),
    };
    // `pub` parameters go to `PublicInputs` (UltraHonk's claim), the rest to
    // `Inputs`; witness order interleaves them as the ABI declares them.
    let (mut fields, mut public) = (vec![], vec![]);
    let (mut flat, mut flat_public) = (TokenStream::new(), TokenStream::new());
    for p in params {
        let name = p["name"].as_str().expect("param name");
        let t = types.rust(&p["type"], &all);
        let n = ident(name);
        if p["visibility"] == "public" {
            public.push((name.to_string(), t));
            let e = Expr {
                place: quote!(p.#n),
                element: false,
            };
            flat.extend(flatten(&p["type"], &e, 0));
            flat_public.extend(flatten(&p["type"], &e, 0));
        } else {
            fields.push((name.to_string(), t));
            let e = Expr {
                place: quote!(w.#n),
                element: false,
            };
            flat.extend(flatten(&p["type"], &e, 0));
        }
    }
    let mut inputs = struct_def(
        "Inputs",
        "The private `main` parameters, in ABI order.",
        &fields,
    );
    let public_type = if public.is_empty() {
        quote!(())
    } else {
        inputs.extend(struct_def(
            "PublicInputs",
            "The `pub` `main` parameters, in ABI order.",
            &public,
        ));
        quote!(PublicInputs)
    };
    let out_type = ret.map_or_else(|| quote!(()), |r| types.rust(r, &all));
    let outputs = u64_lit(ret.map_or(0, field_count));
    // A hiding kernel's `vk_tree_root` output, which verifiers must check.
    let root_at = ret
        .filter(|r| r["kind"] == "struct")
        .and_then(|r| {
            let fs = r["fields"].as_array()?;
            let i = fs.iter().position(|f| f["name"] == "vk_tree_root")?;
            Some(fs[..i].iter().map(|f| field_count(&f["type"])).sum::<u64>())
        })
        .map_or_else(
            || quote!(None),
            |i| {
                let i = u64_lit(i);
                quote!(Some(#i))
            },
        );
    let module = ident(label);
    let marker = ident(&camel(label));
    let defs = types.defs.values();
    let mod_doc = doc(text);
    let marker_doc = doc(&format!("The `{label}` circuit."));
    let identity = identity.map(|Identity { consts, kind }| {
        let role = match kind {
            "Honk" => quote!(impl noir_zk_core::Honk for #marker {}),
            "App" => quote!(impl noir_zk_core::App for #marker {}),
            _ => {
                assert!(
                    is_kernel(abi),
                    "{label}: a kernel's parameters must be among {KERNEL_PARAMS:?}"
                );
                let ty = |n: &str| {
                    fields
                        .iter()
                        .find(|(f, _)| f == n)
                        .map_or_else(|| quote!(()), |(_, t)| t.clone())
                };
                let (prev, step) = (ty("prev"), ty("step"));
                let body = fields.iter().map(|(f, _)| {
                    let n = ident(f);
                    match f.as_str() {
                        "prev" | "step" | "vk_tree_root" => quote!(#n: k.#n,),
                        vk => quote!(#n: noir_zk_core::KernelInputs::<Self::Prev, Self::Step>::vk(&k.#n, #vk)?,),
                    }
                });
                quote! {
                    impl noir_zk_core::Kernel for #marker {
                        type Prev = #prev;
                        type Step = #step;
                        fn witness(k: noir_zk_core::KernelInputs<Self::Prev, Self::Step>) -> Result<Inputs, noir_zk_core::Error> {
                            Ok(Inputs { #(#body)* })
                        }
                    }
                }
            }
        };
        quote! {
            impl noir_zk_core::CircuitId for #marker {
                #consts
            }
            #role
        }
    });
    quote! {
        #mod_doc
        pub mod #module {
            use noir_zk_core::Field as Fr;
            #(#defs)*
            #inputs

            #[doc = " What `main` returns (through the databus, or public for a hiding kernel)."]
            pub type Outputs = #out_type;

            #[doc = " Field elements the circuit returns."]
            pub const OUTPUT_FIELDS: usize = #outputs;

            #marker_doc
            pub struct #marker;

            impl noir_zk_core::Circuit for #marker {
                type Witness = Inputs;
                type PublicInputs = #public_type;
                type Outputs = Outputs;
                const VK_TREE_ROOT_OUTPUT: Option<usize> = #root_at;
                #[allow(unused_mut, unused_variables)]
                fn public_inputs(p: &#public_type) -> Vec<Fr> {
                    let mut v = Vec::new();
                    #flat_public
                    v
                }
                #[allow(unused_variables)]
                fn witness_inputs(w: &Inputs, p: &#public_type) -> Vec<Fr> {
                    let mut v = Vec::new();
                    #flat
                    v
                }
            }
            #identity
        }
    }
}

/// Typed inputs and `Circuit` impls for `abis` (no identities or keys): the
/// generated code depends only on `noir-zk-core`.
pub fn generate_types(abis: &[CircuitAbi]) -> String {
    let modules = abis
        .iter()
        .map(|c| circuit_module(&c.label, &c.abi, &format!("`{}`.", c.label), None));
    render(
        "// @generated by noir-zk-codegen. Do not edit.\n\n",
        quote!(#(#modules)*),
    )
}

/// What [`generate_registry_with`] bundles: the bytecode of the active
/// circuits of these layers (`"*"` for every layer), from `dir/assets`, as
/// `ASSETS` (`include_bytes!`), for a `BundledStore`.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Layers to bundle.
    pub bundle: Vec<String>,
    /// Wrapped registries by name: a family with `source = "<name>"` reads
    /// this text (see [`wrapped`]) instead of a file.
    pub sources: Vec<(String, String)>,
}

/// A registry as another registry wraps it: its library, its circuits
/// (label, key hash, record width) and its families, as TOML. A combining
/// crate's `build.rs` calls it with a library's generated `LIBRARY`,
/// `REGISTRY` and `FAMILIES` and passes the text as an [`Options`] source;
/// a registry frozen with an older noir-zk is exported by a tool that
/// derives the key hashes (`noir_zk_backend::chonk::vk_fields`) and commits
/// the file.
pub fn wrapped(
    library: noir_zk_core::Library,
    registry: &[noir_zk_core::RegistryEntry],
    families: &[noir_zk_core::FamilyEntry],
) -> String {
    let mut out = format!(
        "# Written by noir-zk-codegen (wrapped); do not edit.\nlibrary = {:?}\nversion = {:?}\n",
        library.name, library.version
    );
    for e in registry
        .iter()
        .filter(|e| e.status == noir_zk_core::Status::Active)
    {
        let noir_zk_core::ProofSystem::Chonk(noir_zk_core::ChonkRole::App) = e.system else {
            continue;
        };
        let record = e.abi.map_or(0, |abi| {
            let v: Value = serde_json::from_str(abi).unwrap_or(Value::Null);
            v["return_type"].get("abi_type").map_or(0, field_count)
        });
        writeln!(
            out,
            "\n[[circuit]]\nlabel = {:?}\nvk_hash = \"0x{}\"\nrecord_fields = {record}",
            e.label,
            hex::encode(e.vk_hash)
        )
        .ok();
    }
    for f in families {
        let link = |l: &Option<noir_zk_core::LinkSpec>| {
            l.map_or(String::new(), |l| {
                format!(" index = {}, link = {:?} ", l.index, l.link)
            })
        };
        writeln!(
            out,
            "\n[[family]]\nlayer = {:?}\nname = {:?}\nmembers = [{}]\npublic_from = {}\nslots = [{}]\nbinds = [{}]\nbind_const = [{}]",
            f.id.layer,
            f.id.family,
            f.members.iter().map(|(l, _)| format!("{l:?}")).collect::<Vec<_>>().join(", "),
            f.public_from,
            f.slots.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>().join(", "),
            f.binds.iter().map(|b| format!("{{ slot = {:?}, index = {} }}", b.slot, b.index)).collect::<Vec<_>>().join(", "),
            f.consts.iter().map(|c| format!("{{ index = {}, value = \"0x{}\" }}", c.index, hex::encode(c.value))).collect::<Vec<_>>().join(", "),
        )
        .ok();
        if f.link_in.is_some() {
            writeln!(out, "link_in = {{{}}}", link(&f.link_in)).ok();
        }
        if f.link_out.is_some() {
            writeln!(out, "link_out = {{{}}}", link(&f.link_out)).ok();
        }
    }
    out
}

/// A frozen registry (written by `noir-zk freeze`): typed modules for every active
/// circuit with its `CircuitId` (embedded key), `REGISTRY`, `VK_TREE_ROOT` and
/// the toolchain versions, from `dir/circuits/manifest.toml`,
/// `dir/resources/circuits` and `dir/resources/vk-tree.json` (if any); and,
/// when the manifest declares them, `LIBRARY`, `FAMILIES` with a marker type
/// per family (`families::KernelStep*`), `pipelines::<name>` (root, typed
/// `Outputs`, `fold`, `verify`), `DEPLOYMENT` and a test recomputing every
/// root. `dir` must be the host crate's `CARGO_MANIFEST_DIR` (the generated
/// `include_bytes!` paths are relative to it). Pipeline code uses
/// `noir-zk-backend`, which the host crate must then depend on.
pub fn generate_registry(dir: &Path) -> String {
    generate_registry_with(dir, &Options::default())
}

/// A file of the host crate, as the generated code includes it.
fn resource(rel: &str) -> TokenStream {
    let rel = format!("/{rel}");
    quote!(concat!(env!("CARGO_MANIFEST_DIR"), #rel))
}

/// [`generate_registry`] with [`Options`].
pub fn generate_registry_with(dir: &Path, options: &Options) -> String {
    let manifest_path = dir.join("circuits/manifest.toml");
    let tree_path = dir.join("resources/vk-tree.json");

    let manifest: toml::Value =
        toml::from_str(&std::fs::read_to_string(&manifest_path).expect("manifest.toml"))
            .expect("parse manifest.toml");
    let library = manifest.get("library").map(|l| {
        (
            l["name"].as_str().expect("library.name").to_string(),
            l["version"].as_str().expect("library.version").to_string(),
        )
    });
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

    let mut code = TokenStream::new();
    for key in ["noir", "bb"] {
        let v = manifest.get(key).and_then(|v| v.as_str()).unwrap_or("");
        let name = format_ident!("{}_VERSION", key.to_uppercase());
        let doc = doc(&format!(
            "{key} version the frozen artifacts were built with."
        ));
        code.extend(quote! {
            #doc
            pub const #name: &str = #v;
        });
    }
    let vk_tree_root = bytes32(
        manifest
            .get("vk_tree_root")
            .map_or("0".repeat(64).as_str(), |r| {
                r.as_str().expect("vk_tree_root")
            }),
    );
    code.extend(quote! {
        #[doc = " Root of the verification key tree the kernels check (zero without one)."]
        pub const VK_TREE_ROOT: [u8; 32] = #vk_tree_root;
    });
    if let Some((name, version)) = &library {
        code.extend(quote! {
            #[doc = " The library this registry is frozen as."]
            pub const LIBRARY: noir_zk_core::Library = noir_zk_core::Library { name: #name, version: #version };
        });
    }
    // The families' view of the active circuits (record widths need the ABIs).
    let mut actives: BTreeMap<String, pipelines::Active> = BTreeMap::new();
    let mut assets: Vec<(String, String)> = vec![];
    let family_of = |label: &str| -> (String, String) {
        for f in manifest
            .get("family")
            .and_then(|f| f.as_array())
            .into_iter()
            .flatten()
        {
            if f.get("source").is_some() {
                continue;
            }
            let members = f["members"].as_array().expect("members");
            if members.iter().any(|m| {
                let m = m.as_str().unwrap_or_default();
                m.strip_suffix('*')
                    .map_or(m == label, |p| label.starts_with(p))
            }) {
                return (
                    f["layer"].as_str().unwrap_or_default().to_string(),
                    f["name"].as_str().unwrap_or_default().to_string(),
                );
            }
        }
        (String::new(), String::new())
    };

    let mut apps: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut kernels_with_step: Vec<(String, String)> = vec![];
    let mut registry = vec![];
    for c in manifest
        .get("circuit")
        .and_then(|c| c.as_array())
        .into_iter()
        .flatten()
    {
        let label = c["label"].as_str().expect("label");
        let version = c["version"].as_str().expect("version");
        let status = c["status"].as_str().expect("status");
        let (kind, system) = match (
            c["system"].as_str().expect("system"),
            c.get("role").and_then(|r| r.as_str()),
        ) {
            ("ultra_honk", _) => {
                let oracle = match c.get("oracle").and_then(|o| o.as_str()) {
                    Some("keccak") => format_ident!("Keccak"),
                    Some("poseidon2") => format_ident!("Poseidon2"),
                    o => panic!("{label}: unknown oracle {o:?}"),
                };
                (
                    "Honk",
                    quote!(noir_zk_core::ProofSystem::UltraHonk(noir_zk_core::Oracle::#oracle)),
                )
            }
            ("chonk", Some(role)) => {
                let role = match role {
                    "app" => "App",
                    "kernel" => "Kernel",
                    "hiding" => "Hiding",
                    r => panic!("{label}: unknown Chonk role {r}"),
                };
                let r = ident(role);
                (
                    role,
                    quote!(noir_zk_core::ProofSystem::Chonk(noir_zk_core::ChonkRole::#r)),
                )
            }
            (s, r) => panic!("{label}: unknown proof system {s} (role {r:?})"),
        };
        let rel = format!("resources/circuits/{label}/{version}");
        let abi_file = dir.join(&rel).join("abi.json");
        let (index, siblings) = match (status, paths.get(label)) {
            ("active", Some((i, s))) => {
                let i = u64_lit(*i);
                (quote!(Some(#i)), s.iter().map(|h| bytes32(h)).collect())
            }
            _ => (quote!(None), vec![]),
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
        let vk_sha = bytes32(&vk_hash);
        let status_v = match status {
            "active" => format_ident!("Active"),
            "deprecated" => format_ident!("Deprecated"),
            s => panic!("{label}: unknown status {s}"),
        };
        let (layer, family) = if status == "active" {
            family_of(label)
        } else {
            (String::new(), String::new())
        };
        let vk_hash_v = bytes32(
            c.get("vk_hash")
                .and_then(|h| h.as_str())
                .unwrap_or(&"0".repeat(64)),
        );
        let bytecode_sha = bytes32(c["bytecode_sha256"].as_str().expect("bytecode_sha256"));
        let abi = if status == "active" {
            let f = resource(&format!("{rel}/abi.json"));
            quote!(Some(include_str!(#f)))
        } else {
            quote!(None)
        };
        let vk = resource(&format!("{rel}/circuit.vk"));
        registry.push(quote! {
            noir_zk_core::RegistryEntry {
                label: #label,
                version: #version,
                system: #system,
                status: noir_zk_core::Status::#status_v,
                bytecode_sha256: #bytecode_sha,
                vk_sha256: #vk_sha,
                vk_hash: #vk_hash_v,
                layer: #layer,
                family: #family,
                abi: #abi,
                vk: include_bytes!(#vk),
                vk_index: #index,
                vk_siblings: &[#(#siblings),*],
            }
        });

        if status != "active" {
            continue;
        }
        let abi: Value =
            serde_json::from_str(&std::fs::read_to_string(&abi_file).expect("abi.json"))
                .expect("parse abi.json");
        actives.insert(
            label.to_string(),
            pipelines::Active {
                vk_hash: c
                    .get("vk_hash")
                    .and_then(|h| h.as_str())
                    .map(str::to_string),
                record_fields: abi["return_type"]
                    .get("abi_type")
                    .map_or(0, |r| usize::try_from(field_count(r)).unwrap()),
                is_app: kind == "App",
            },
        );
        if options.bundle.iter().any(|b| b == "*" || *b == layer) {
            assets.push((
                format!("{label}@{version}.b64"),
                format!("assets/{label}@{version}.b64"),
            ));
        }
        let consts = quote! {
            const LABEL: &'static str = #label;
            const VERSION: &'static str = #version;
            const SYSTEM: noir_zk_core::ProofSystem = #system;
            const BYTECODE_SHA256: [u8; 32] = #bytecode_sha;
            const VK_BYTES: &'static [u8] = include_bytes!(#vk);
            const VK_SHA256: [u8; 32] = #vk_sha;
        };
        code.extend(circuit_module(
            label,
            &abi,
            &format!("`{label}` {version} ({kind})."),
            Some(Identity { consts, kind }),
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
    code.extend(quote! {
        #[doc = " Every frozen circuit version."]
        pub const REGISTRY: &[noir_zk_core::RegistryEntry] = &[#(#registry),*];

        #[doc = " Static dispatch from an app label to its circuit type (`noir_zk_core::AppDispatch`)."]
        pub struct Registry;
    });
    for labels in apps.values() {
        let (m, t) = (ident(&labels[0]), ident(&camel(&labels[0])));
        let out = quote!(<#m::#t as noir_zk_core::Circuit>::Outputs);
        let arms = labels.iter().map(|l| {
            let (m, t) = (ident(l), ident(&camel(l)));
            quote!(#l => Some(v.visit::<#m::#t>()),)
        });
        code.extend(quote! {
            impl noir_zk_core::AppDispatch<#out> for Registry {
                fn visit_app<V: noir_zk_core::AppVisitor<#out>>(label: &str, v: V) -> Option<V::Output> {
                    match label {
                        #(#arms)*
                        _ => None,
                    }
                }
            }
        });
    }
    if !options.bundle.is_empty() {
        let entries = assets.iter().map(|(asset, rel)| {
            let f = resource(rel);
            quote!((#asset, include_bytes!(#f)))
        });
        code.extend(quote! {
            #[doc = " Bundled bytecode assets (`<label>@<version>.b64`), for a `BundledStore`."]
            pub const ASSETS: &[(&str, &[u8])] = &[#(#entries),*];
        });
    }
    if let Some(lib) = &library {
        let families =
            pipelines::families(dir, &manifest, (&lib.0, &lib.1), &actives, &options.sources);
        let declared = pipelines::pipelines(&manifest, &families);
        code.extend(pipelines::emit(&families, &declared));
    }
    // Kernels that fold an app: wrap one, typed or chosen at runtime.
    for (label, step) in &kernels_with_step {
        let (m, t) = (ident(label), ident(&camel(label)));
        let select = apps.contains_key(step).then(|| {
            quote! {
                #[doc = " Wraps the app `label` (chosen at runtime) with its `Prover.toml` inputs; fails unless it is an app this kernel folds."]
                pub fn select<'i>(label: &str, toml: &'i str) -> Result<noir_zk_core::Wrapped<'i, Self>, noir_zk_core::Error> {
                    noir_zk_core::Wrapped::select::<Registry>(label, toml)
                }
            }
        });
        code.extend(quote! {
            impl #m::#t {
                #[doc = " Wraps app `C` (typed witness) to be folded by this kernel."]
                pub fn wrap<C: noir_zk_core::App<Outputs = <Self as noir_zk_core::Kernel>::Step>>(witness: &C::Witness) -> noir_zk_core::Wrapped<'static, Self> {
                    noir_zk_core::Wrapped::new::<C>(witness)
                }
                #select
            }
        });
    }
    render(
        "// @generated by noir-zk-codegen from circuits/manifest.toml and resources/. Do not edit.\n\n",
        code,
    )
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
    fn flattens_nested_arrays_by_reference() {
        let nested = serde_json::json!({
            "parameters": [
                {"name": "m", "type": {"kind": "array", "length": 2, "type": {"kind": "array", "length": 3, "type": {"kind": "field"}}}, "visibility": "private"}
            ],
            "return_type": null
        });
        let code = generate_types(&[CircuitAbi {
            label: "nested".into(),
            abi: nested,
        }]);
        assert!(code.contains("for e0 in w.m.iter() {"));
        assert!(code.contains("for e1 in e0.iter() {"), "{code}");
        assert!(code.contains("v.push(*e1);"));
        assert!(!code.contains("in *e"));
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

    /// Noir allows names that are Rust keywords; they are generated as raw
    /// identifiers, and the output parses.
    #[test]
    fn rust_keywords_become_raw_identifiers() {
        let abi = serde_json::json!({
            "parameters": [
                {"name": "ref", "type": {"kind": "field"}, "visibility": "private"},
                {"name": "gen", "type": {"kind": "struct", "path": "lib::Pair", "fields": [
                    {"name": "static", "type": {"kind": "field"}}
                ]}, "visibility": "public"}
            ],
            "return_type": null
        });
        let code = generate_types(&[CircuitAbi {
            label: "move".into(),
            abi,
        }]);
        assert!(code.contains("pub mod r#move {"), "{code}");
        assert!(code.contains("pub r#ref: Fr,"), "{code}");
        assert!(code.contains("pub r#static: Fr,"), "{code}");
        assert!(code.contains("v.push(p.r#gen.r#static);"), "{code}");
        assert!(code.contains("pub struct Pair {"), "{code}");
    }

    /// A struct named like something the module generates, or like another
    /// path's struct, is qualified by its path; each keeps its own fields.
    #[test]
    fn struct_names_never_clash() {
        let st = |path: &str, field: &str| {
            serde_json::json!({"kind": "struct", "path": path, "fields": [
                {"name": field, "type": {"kind": "field"}}
            ]})
        };
        let abi = serde_json::json!({
            "parameters": [
                {"name": "a", "type": st("lib::Point", "x"), "visibility": "private"},
                {"name": "b", "type": st("other::Point", "y"), "visibility": "private"},
                {"name": "c", "type": st("lib::Demo", "z"), "visibility": "private"},
                {"name": "d", "type": st("lib::Inputs", "w"), "visibility": "private"}
            ],
            "return_type": null
        });
        let code = generate_types(&[CircuitAbi {
            label: "demo".into(),
            abi,
        }]);
        for s in [
            "Point",
            "OtherPoint",
            "LibDemo",
            "LibInputs",
            "Demo",
            "Inputs",
        ] {
            assert_eq!(
                code.matches(&format!("pub struct {s} ")).count()
                    + code.matches(&format!("pub struct {s};")).count(),
                1,
                "{s}: {code}"
            );
        }
        assert!(code.contains("pub a: Point,"), "{code}");
        assert!(code.contains("pub b: OtherPoint,"), "{code}");
        assert!(code.contains("pub c: LibDemo,"), "{code}");
        assert!(code.contains("pub d: LibInputs,"), "{code}");
        assert!(
            code.contains("pub y: Fr,"),
            "other::Point keeps its field: {code}"
        );
    }
}
