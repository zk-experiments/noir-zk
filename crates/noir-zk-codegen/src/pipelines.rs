//! The layered part of a registry: families, wrapped registries, pipelines
//! and the deployment, read from `circuits/manifest.toml` and emitted as
//! typed code with roots computed here (the same Poseidon2 as the runtime).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use noir_zk_core::codec::{field_from_be_bytes, field_to_be_bytes32};
use noir_zk_core::tree::{self, Tree, DEPLOYMENT_HEIGHT, PIPELINE_HEIGHT};
use noir_zk_core::{Field, Layout};

use crate::{camel, hex32};

/// One active circuit of this registry, as the families see it.
pub(crate) struct Active {
    pub vk_hash: Option<String>,
    pub record_fields: usize,
    pub is_app: bool,
}

pub(crate) struct Family {
    pub layer: String,
    pub name: String,
    pub library: String,
    pub version: String,
    /// `(label, vk_hash)`.
    pub members: Vec<(String, String)>,
    pub record_fields: usize,
    pub link_in: Option<(usize, String)>,
    pub link_out: Option<(usize, String)>,
    pub binds: Vec<(String, usize)>,
    /// (record index, value) constant bindings.
    pub consts: Vec<(usize, Field)>,
    pub public_from: usize,
    pub slots: Vec<String>,
    pub wrapped: bool,
    pub root: Field,
}

impl Family {
    fn id(&self) -> String {
        format!("{}/{}/{}", self.library, self.layer, self.name)
    }

    fn type_name(&self) -> String {
        format!("KernelStep{}", camel(&self.name))
    }
}

pub(crate) struct Pipeline {
    pub name: String,
    /// (family index, layout).
    pub positions: Vec<(usize, Layout)>,
    pub slots: Vec<String>,
    pub root: Field,
}

fn glob(members: &toml::Value, labels: &[&str], what: &str) -> Vec<String> {
    let mut out = vec![];
    for m in members
        .as_array()
        .unwrap_or_else(|| panic!("{what}: members must be a list"))
    {
        let m = m.as_str().expect("member");
        let matched: Vec<&&str> = match m.strip_suffix('*') {
            Some(prefix) => labels.iter().filter(|l| l.starts_with(prefix)).collect(),
            None => labels.iter().filter(|l| **l == m).collect(),
        };
        assert!(
            !matched.is_empty(),
            "{what}: member {m:?} matches no circuit"
        );
        out.extend(matched.into_iter().map(|l| (*l).to_string()));
    }
    out.sort();
    out.dedup();
    out
}

fn link(v: Option<&toml::Value>) -> Option<(usize, String)> {
    v.map(|l| {
        (
            usize::try_from(l["index"].as_integer().expect("link index")).expect("index"),
            l["link"].as_str().expect("link type").to_string(),
        )
    })
}

/// Reads the `[[family]]` tables: this registry's (members among `actives`)
/// and wrapped ones (`source = "path"`, a file written by
/// `noir_zk_backend::wrap::export`).
pub(crate) fn families(
    dir: &Path,
    manifest: &toml::Value,
    library: (&str, &str),
    actives: &BTreeMap<String, Active>,
    sources: &[(String, String)],
) -> Vec<Family> {
    let Some(tables) = manifest.get("family").and_then(|f| f.as_array()) else {
        return vec![];
    };
    let mut out = vec![];
    for f in tables {
        let layer = f["layer"].as_str().expect("family.layer").to_string();
        let name = f["name"].as_str().expect("family.name").to_string();
        let what = format!("family {layer}/{name}");
        // A wrapped family may take its definition from the source's own.
        let source_family: Option<toml::Value> = f.get("source").and_then(|s| {
            let s = s.as_str().expect("family.source");
            let text = sources
                .iter()
                .find(|(n, _)| n == s)
                .map(|(_, t)| t.clone())
                .unwrap_or_else(|| {
                    let path = dir.join(s);
                    std::fs::read_to_string(&path)
                        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
                });
            let w: toml::Value = toml::from_str(&text).expect("wrapped registry");
            w.get("family").and_then(|fs| fs.as_array()).and_then(|fs| {
                fs.iter()
                    .find(|x| {
                        x["layer"].as_str() == Some(&layer) && x["name"].as_str() == Some(&name)
                    })
                    .cloned()
            })
        });
        let get = |key: &str| {
            f.get(key)
                .or_else(|| source_family.as_ref().and_then(|s| s.get(key)))
                .cloned()
        };
        let (library, version, members, record_fields, wrapped) = match f.get("source") {
            None => {
                let labels: Vec<&str> = actives
                    .iter()
                    .filter(|(_, a)| a.is_app)
                    .map(|(l, _)| l.as_str())
                    .collect();
                let members: Vec<(String, String)> = glob(&f["members"], &labels, &what)
                    .into_iter()
                    .map(|l| {
                        let a = &actives[&l];
                        let h = a.vk_hash.clone().unwrap_or_else(|| {
                            panic!("{what}: {l} has no vk_hash (rerun noir-zk freeze)")
                        });
                        (l, h)
                    })
                    .collect();
                let records: BTreeSet<usize> = members
                    .iter()
                    .map(|(l, _)| actives[l].record_fields)
                    .collect();
                assert!(
                    records.len() == 1,
                    "{what}: members return records of different widths {records:?}"
                );
                (
                    library.0.to_string(),
                    library.1.to_string(),
                    members,
                    records.into_iter().next().unwrap(),
                    false,
                )
            }
            Some(source) => {
                let s = source.as_str().expect("family.source");
                let text = sources
                    .iter()
                    .find(|(n, _)| n == s)
                    .map(|(_, t)| t.clone())
                    .unwrap_or_else(|| {
                        let path = dir.join(s);
                        std::fs::read_to_string(&path)
                            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
                    });
                let w: toml::Value = toml::from_str(&text).expect("wrapped registry");
                let circuits: Vec<&toml::Value> = w["circuit"]
                    .as_array()
                    .expect("[[circuit]]")
                    .iter()
                    .collect();
                let labels: Vec<&str> = circuits
                    .iter()
                    .map(|c| c["label"].as_str().expect("label"))
                    .collect();
                let members_spec = get("members")
                    .unwrap_or_else(|| panic!("{what}: no members here or in the source"));
                let members: Vec<(String, String)> = glob(&members_spec, &labels, &what)
                    .into_iter()
                    .map(|l| {
                        let c = circuits
                            .iter()
                            .find(|c| c["label"].as_str() == Some(l.as_str()))
                            .unwrap();
                        (l, c["vk_hash"].as_str().expect("vk_hash").to_string())
                    })
                    .collect();
                let records: BTreeSet<usize> = members
                    .iter()
                    .map(|(l, _)| {
                        let c = circuits
                            .iter()
                            .find(|c| c["label"].as_str() == Some(l.as_str()))
                            .unwrap();
                        usize::try_from(c["record_fields"].as_integer().expect("record_fields"))
                            .unwrap()
                    })
                    .collect();
                assert!(
                    records.len() == 1,
                    "{what}: members return records of different widths"
                );
                (
                    w["library"].as_str().expect("library").to_string(),
                    w["version"].as_str().expect("version").to_string(),
                    members,
                    records.into_iter().next().unwrap(),
                    true,
                )
            }
        };
        let slots: Vec<String> = get("slots")
            .and_then(|s| s.as_array().cloned())
            .map(|s| {
                s.iter()
                    .map(|x| x.as_str().expect("slot").to_string())
                    .collect()
            })
            .unwrap_or_default();
        let binds: Vec<(String, usize)> = get("binds")
            .and_then(|b| b.as_array().cloned())
            .map(|b| {
                b.iter()
                    .map(|x| {
                        (
                            x["slot"].as_str().expect("bind slot").to_string(),
                            usize::try_from(x["index"].as_integer().expect("bind index")).unwrap(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let consts: Vec<(usize, Field)> = get("bind_const")
            .and_then(|b| b.as_array().cloned())
            .map(|b| {
                b.iter()
                    .map(|x| {
                        let index =
                            usize::try_from(x["index"].as_integer().expect("bind_const index"))
                                .unwrap();
                        let value = match &x["value"] {
                            toml::Value::Integer(i) => {
                                Field::from(u64::try_from(*i).expect("bind_const value"))
                            }
                            toml::Value::String(s) => {
                                let s = s.trim_start_matches("0x");
                                field_from_be_bytes(
                                    &hex::decode(format!("{s:0>64}"))
                                        .expect("bind_const value: hex"),
                                )
                            }
                            v => panic!("{what}: bind_const value {v}: an integer or a hex string"),
                        };
                        (index, value)
                    })
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            consts.len() <= noir_zk_core::pipeline::C,
            "{what}: at most {} constant bindings",
            noir_zk_core::pipeline::C
        );
        assert!(
            consts.iter().all(|(i, _)| *i < record_fields),
            "{what}: a constant binding beyond the record"
        );
        let public_from = get("public_from")
            .and_then(|p| p.as_integer())
            .map_or(0, |p| usize::try_from(p).unwrap());
        assert!(
            public_from + slots.len() <= record_fields,
            "{what}: public slots beyond the record ({record_fields} fields)"
        );
        let hashes: Vec<Field> = members
            .iter()
            .map(|(_, h)| {
                field_from_be_bytes(&hex::decode(h.trim_start_matches("0x")).expect("hex"))
            })
            .collect();
        let root = tree::family_root(tree::family_id(&library, &version, &layer, &name), &hashes);
        out.push(Family {
            layer,
            name,
            library,
            version,
            members,
            record_fields,
            link_in: link(get("link_in").as_ref()),
            link_out: link(get("link_out").as_ref()),
            binds,
            consts,
            public_from,
            slots,
            wrapped,
            root,
        });
    }
    let mut names = BTreeSet::new();
    for f in &out {
        assert!(
            names.insert(f.name.clone()),
            "two families named {}: family names must be unique across layers",
            f.name
        );
    }
    out
}

/// Reads the `[[pipeline]]` tables, resolving each position's layout and
/// computing the pipeline roots.
pub(crate) fn pipelines(manifest: &toml::Value, families: &[Family]) -> Vec<Pipeline> {
    let Some(tables) = manifest.get("pipeline").and_then(|p| p.as_array()) else {
        return vec![];
    };
    let kernels = field_from_be_bytes(&noir_zk_kernels::FAMILY.root);
    tables
        .iter()
        .map(|p| {
            let name = p["name"].as_str().expect("pipeline.name").to_string();
            let mut published: Vec<String> = vec![];
            let mut positions = vec![];
            let mut link: Option<String> = None;
            for (i, pos) in p["positions"].as_array().expect("positions").iter().enumerate() {
                let id = pos.as_str().expect("position");
                let fi = families
                    .iter()
                    .position(|f| f.id() == id)
                    .unwrap_or_else(|| panic!("pipeline {name}: no family {id}"));
                let f = &families[fi];
                // The links, as the builder checks them at compile time.
                if let Some((_, l)) = &f.link_in {
                    assert!(
                        link.as_deref() == Some(l.as_str()),
                        "pipeline {name}, position {i} ({id}): continues link {l}, but the link so far is {}",
                        link.as_deref().unwrap_or("none")
                    );
                }
                if let Some((_, l)) = &f.link_out {
                    link = Some(l.clone());
                }
                let binds = f
                    .binds
                    .iter()
                    .map(|(slot, index)| {
                        let s = published.iter().position(|x| x == slot).unwrap_or_else(|| {
                            panic!("pipeline {name}, position {i} ({id}): binds slot {slot}, which no earlier position publishes")
                        });
                        (s, *index)
                    })
                    .collect();
                // Two positions folding one circuit under the same constant
                // bindings (two envelope instances pinned to one key domain,
                // say) would be indistinguishable to the app: refused.
                for (j, (fj, _)) in positions.iter().enumerate() {
                    let g: &Family = &families[*fj];
                    let shared = g.members.iter().any(|(l, _)| f.members.iter().any(|(m, _)| m == l));
                    assert!(
                        !(shared && g.consts == f.consts),
                        "pipeline {name}, positions {j} ({}) and {i} ({id}): the same circuit under the same constant bindings",
                        g.id()
                    );
                }
                positions.push((
                    fi,
                    Layout {
                        link_in: f.link_in.as_ref().map(|l| l.0),
                        link_out: f.link_out.as_ref().map(|l| l.0),
                        binds,
                        pub_from: f.public_from,
                        n_pub: f.slots.len(),
                        consts: f.consts.clone(),
                    },
                ));
                published.extend(f.slots.iter().cloned());
            }
            assert!(published.len() <= noir_zk_core::pipeline::P, "pipeline {name}: more than {} public slots", noir_zk_core::pipeline::P);
            let mut leaves: Vec<Field> = positions
                .iter()
                .enumerate()
                .map(|(i, (fi, l))| tree::position_leaf(i as u64, families[*fi].root, l.hash()))
                .collect();
            assert!(leaves.len() < tree::KERNEL_LEAF, "pipeline {name}: at most {} positions", tree::KERNEL_LEAF - 1);
            leaves.resize(tree::KERNEL_LEAF, Field::from(0u64));
            leaves.push(tree::position_leaf(tree::ROLE_KERNEL, kernels, Field::from(0u64)));
            let root = Tree::build(&leaves, PIPELINE_HEIGHT).root;
            Pipeline { name, positions, slots: published, root }
        })
        .collect()
}

/// Link types defined by `noir_zk_core::pipeline::links` (shared across libraries).
const SHARED_LINKS: [&str; 1] = ["PayloadCommitment"];

fn hexf(f: &Field) -> String {
    hex32(&hex::encode(field_to_be_bytes32(f)))
}

fn ident(slot: &str) -> String {
    let s: String = slot
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    if s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("s_{s}")
    } else {
        s
    }
}

/// The generated code: `WRAPPED`, `layer_of`, `links`, `FAMILIES`,
/// `families`, `pipelines`, `DEPLOYMENT` and the roots test.
pub(crate) fn emit(families: &[Family], pipelines: &[Pipeline]) -> String {
    let mut code = String::new();
    if families.is_empty() {
        return code;
    }
    // Wrapped members as registry entries (their bytecode, ABI and key come
    // from the wrapped registry's own artifacts at run time).
    code.push_str("/// Circuits of wrapped registries (other libraries' families): identity only.\npub const WRAPPED: &[noir_zk_core::RegistryEntry] = &[\n");
    for f in families.iter().filter(|f| f.wrapped) {
        for (label, h) in &f.members {
            writeln!(code, "    noir_zk_core::RegistryEntry {{ label: {label:?}, version: {:?}, system: noir_zk_core::ProofSystem::Chonk(noir_zk_core::ChonkRole::App), status: noir_zk_core::Status::Active, bytecode_sha256: [0; 32], vk_sha256: [0; 32], vk_hash: {}, layer: {:?}, family: {:?}, abi: None, vk: &[], vk_index: None, vk_siblings: &[] }},", f.version, hex32(h), f.layer, f.name).ok();
        }
    }
    code.push_str("];\n\n/// The layer of a circuit of this registry or a wrapped one.\npub fn layer_of(label: &str) -> Option<&'static str> {\n    match label {\n");
    let mut seen = BTreeSet::new();
    for f in families {
        for (label, _) in &f.members {
            if seen.insert(label.clone()) {
                writeln!(code, "        {label:?} => Some({:?}),", f.layer).ok();
            }
        }
    }
    code.push_str("        _ => None,\n    }\n}\n\n");
    // Links.
    let links: BTreeSet<&str> = families
        .iter()
        .flat_map(|f| [&f.link_in, &f.link_out])
        .filter_map(|l| l.as_ref().map(|(_, n)| n.as_str()))
        .collect();
    code.push_str("/// The link types the families declare (noir-zk's shared vocabulary re-exported, the rest generated).\npub mod links {\n    pub use noir_zk_core::NoLink;\n");
    let (shared, own): (Vec<&str>, Vec<&str>) = links
        .iter()
        .copied()
        .partition(|l| SHARED_LINKS.contains(l));
    for l in shared {
        writeln!(code, "    pub use noir_zk_core::pipeline::links::{l};").ok();
    }
    if !own.is_empty() {
        writeln!(code, "    noir_zk_core::links!({});", own.join(", ")).ok();
    }
    code.push_str("}\n\n");
    // FAMILIES.
    code.push_str("/// Every family this registry declares (its own and wrapped ones).\npub static FAMILIES: &[noir_zk_core::FamilyEntry] = &[\n");
    for f in families {
        let members: Vec<String> = f
            .members
            .iter()
            .map(|(l, h)| format!("({l:?}, {})", hex32(h)))
            .collect();
        let spec = |l: &Option<(usize, String)>| {
            l.as_ref().map_or("None".to_string(), |(i, n)| {
                format!("Some(noir_zk_core::LinkSpec {{ index: {i}, link: {n:?} }})")
            })
        };
        let binds: Vec<String> = f
            .binds
            .iter()
            .map(|(s, i)| format!("noir_zk_core::BindSpec {{ slot: {s:?}, index: {i} }}"))
            .collect();
        let slots: Vec<String> = f.slots.iter().map(|s| format!("{s:?}")).collect();
        let consts: Vec<String> = f
            .consts
            .iter()
            .map(|(i, v)| {
                format!(
                    "noir_zk_core::ConstSpec {{ index: {i}, value: {} }}",
                    hexf(v)
                )
            })
            .collect();
        writeln!(code, "    noir_zk_core::FamilyEntry {{\n        id: noir_zk_core::FamilyRef {{ library: {:?}, layer: {:?}, family: {:?} }},\n        version: {:?},\n        members: &[{}],\n        record_fields: {},\n        link_in: {},\n        link_out: {},\n        binds: &[{}],\n        consts: &[{}],\n        public_from: {},\n        slots: &[{}],\n        root: {},\n    }},", f.library, f.layer, f.name, f.version, members.join(", "), f.record_fields, spec(&f.link_in), spec(&f.link_out), binds.join(", "), consts.join(", "), f.public_from, slots.join(", "), hexf(&f.root)).ok();
    }
    code.push_str("];\n\n");
    // Family marker types.
    code.push_str("/// One marker type per family: what the pipeline builder folds at a position.\npub mod families {\n");
    for (i, f) in families.iter().enumerate() {
        let l = |l: &Option<(usize, String)>| {
            l.as_ref()
                .map_or("super::links::NoLink".to_string(), |(_, n)| {
                    format!("super::links::{n}")
                })
        };
        writeln!(code, "    /// Family `{}` ({} circuits, record `[Fr; {}]`).\n    pub struct {};\n    impl noir_zk_core::StepFamily for {} {{\n        type Record = [noir_zk_core::Field; {}];\n        type LinkIn = {};\n        type LinkOut = {};\n        fn family() -> &'static noir_zk_core::FamilyEntry {{\n            &super::FAMILIES[{i}]\n        }}\n    }}", f.id(), f.members.len(), f.record_fields, f.type_name(), f.type_name(), f.record_fields, l(&f.link_in), l(&f.link_out)).ok();
    }
    code.push_str("}\n\n");
    if pipelines.is_empty() {
        return code;
    }
    // Pipelines.
    let roots: Vec<Field> = pipelines.iter().map(|p| p.root).collect();
    let deployment = Tree::build(&roots, DEPLOYMENT_HEIGHT).root;
    code.push_str("/// The pipelines this registry declares: each with its root, its typed outputs, `fold` and `verify`.\npub mod pipelines {\n");
    for (index, p) in pipelines.iter().enumerate() {
        let positions: Vec<String> = p
            .positions
            .iter()
            .map(|(fi, l)| {
                let f = &families[*fi];
                let opt = |o: Option<usize>| o.map_or("None".to_string(), |i| format!("Some({i})"));
                format!("noir_zk_core::PositionEntry {{ family: noir_zk_core::FamilyRef {{ library: {:?}, layer: {:?}, family: {:?} }}, layout: noir_zk_core::Layout {{ link_in: {}, link_out: {}, binds: vec![{}], pub_from: {}, n_pub: {}, consts: vec![{}] }} }}", f.library, f.layer, f.name, opt(l.link_in), opt(l.link_out), l.binds.iter().map(|(s, r)| format!("({s}, {r})")).collect::<Vec<_>>().join(", "), l.pub_from, l.n_pub, l.consts.iter().map(|(i, v)| format!("({i}, noir_zk_core::codec::field_from_be_bytes(&{}))", hexf(v))).collect::<Vec<_>>().join(", "))
            })
            .collect();
        let slot_fields: String = p
            .slots
            .iter()
            .map(|s| {
                format!(
                    "        /// Slot `{s}`.\n        pub {}: noir_zk_core::Field,\n",
                    ident(s)
                )
            })
            .collect();
        let slot_reads: String = p
            .slots
            .iter()
            .enumerate()
            .map(|(i, s)| format!("            {}: f[{}],\n", ident(s), 3 + i))
            .collect();
        writeln!(code, "    /// Pipeline `{name}`: {}.\n    pub mod {name} {{\n        /// The pipeline root (big-endian).\n        pub const ROOT: [u8; 32] = {root};\n        /// Its index in the deployment tree.\n        pub const INDEX: usize = {index};\n        /// The pipeline as the builder folds it.\n        pub static PIPELINE: std::sync::LazyLock<noir_zk_core::PipelineEntry> = std::sync::LazyLock::new(|| noir_zk_core::PipelineEntry {{\n            name: {name:?},\n            index: {index},\n            positions: vec![{positions}],\n            slots: vec![{slots}],\n            root: ROOT,\n        }});\n\n        /// The proof's public outputs: the deployment and pipeline roots, the length, then the slots by name.\n        #[derive(Clone, Debug, PartialEq, Eq)]\n        pub struct Outputs {{\n            /// The deployment root the verifier pins.\n            pub deployment_root: noir_zk_core::Field,\n            /// This pipeline's root.\n            pub pipeline_root: noir_zk_core::Field,\n            /// The number of positions folded.\n            pub length: u64,\n{slot_fields}        }}\n\n        impl Outputs {{\n            /// From the hiding kernel's public fields.\n            pub fn from_fields(f: &[noir_zk_core::Field]) -> Self {{\n                Self {{\n                    deployment_root: f[0],\n                    pipeline_root: f[1],\n                    length: noir_zk_core::codec::field_to_u64(&f[2]).unwrap_or(u64::MAX),\n{slot_reads}                }}\n            }}\n        }}\n\n        /// Starts folding this pipeline over `artifacts` (the merged pool of every registry it draws from, plus the kernels).\n        pub fn fold<'a>(artifacts: &'a dyn noir_zk_core::Artifacts) -> Result<noir_zk_backend::pipeline::PipelineFold<'a, noir_zk_core::NoLink>, noir_zk_core::Error> {{\n            noir_zk_backend::pipeline::PipelineFold::new(artifacts, &PIPELINE)\n        }}\n\n        /// Verifies `proof` (hiding key, deployment root, pipeline root, length) and returns its outputs.\n        pub fn verify(proof: &noir_zk_backend::chonk::FoldedProof) -> Result<Outputs, noir_zk_core::Error> {{\n            let f = noir_zk_backend::pipeline::verify(proof, &PIPELINE, super::super::DEPLOYMENT.root_field(), noir_zk_backend::pipeline::hiding_vk())?;\n            Ok(Outputs::from_fields(&f))\n        }}\n    }}",
            p.positions.iter().map(|(fi, _)| families[*fi].id()).collect::<Vec<_>>().join(", "),
            name = p.name, root = hexf(&p.root), positions = positions.join(", "), slots = p.slots.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>().join(", ")).ok();
    }
    code.push_str("}\n\n");
    writeln!(code, "/// The deployment root: the tree over the pipelines' roots, in declaration order. Verifiers pin it.\npub const DEPLOYMENT_ROOT: [u8; 32] = {};\n/// The deployment: the pipeline roots and their tree.\npub static DEPLOYMENT: noir_zk_core::DeploymentEntry = noir_zk_core::DeploymentEntry {{\n    roots: &[{}],\n    root: DEPLOYMENT_ROOT,\n}};\n", hexf(&deployment), roots.iter().map(hexf).collect::<Vec<_>>().join(", ")).ok();
    // The roots test.
    code.push_str("#[cfg(test)]\nmod generated_roots {\n    /// Every family, pipeline and deployment root recomputed at run time equals its constant.\n    #[test]\n    fn roots_match_the_constants() {\n        use noir_zk_core::tree;\n        for f in super::FAMILIES {\n            let hashes: Vec<noir_zk_core::Field> = f.members.iter().map(|(_, h)| noir_zk_core::codec::field_from_be_bytes(h)).collect();\n            assert_eq!(tree::family_root(tree::family_id(f.id.library, f.version, f.id.layer, f.id.family), &hashes), f.root_field(), \"family {}\", f.id);\n        }\n        let kernels = noir_zk_backend::kernels::FAMILY.root_field();\n        let mut roots = vec![];\n");
    for p in pipelines {
        writeln!(code, "        {{\n            let p = &*super::pipelines::{}::PIPELINE;\n            let leaves = noir_zk_core::PipelineEntry::leaves(&|id| super::FAMILIES.iter().find(|f| f.id == *id).map(|f| f.root_field()), &p.positions, kernels).unwrap();\n            assert_eq!(tree::Tree::build(&leaves, tree::PIPELINE_HEIGHT).root, p.root_field(), \"pipeline {}\");\n            roots.push(p.root_field());\n        }}", p.name, p.name).ok();
    }
    code.push_str("        assert_eq!(tree::Tree::build(&roots, tree::DEPLOYMENT_HEIGHT).root, super::DEPLOYMENT.root_field(), \"deployment\");\n    }\n}\n");
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(pipeline: &str) -> toml::Value {
        toml::from_str(&format!(
            r#"
[library]
name = "lib"
version = "1.0.0"

[[circuit]]
label = "env"
version = "1.0.0"
system = "chonk"
role = "app"
status = "active"
vk_hash = "0x01"
bytecode_sha256 = "00"
vk_sha256 = "00"

[[circuit]]
label = "seed"
version = "1.0.0"
system = "chonk"
role = "app"
status = "active"
vk_hash = "0x02"
bytecode_sha256 = "00"
vk_sha256 = "00"

[[family]]
layer = "l"
name = "seed"
members = ["seed"]
link_out = {{ index = 0, link = "Seed" }}
public_from = 1
slots = ["ctx"]

[[family]]
layer = "l"
name = "env_a"
members = ["env"]
link_in = {{ index = 0, link = "Seed" }}
binds = [{{ slot = "ctx", index = 1 }}]
bind_const = [{{ index = 2, value = "0x0a" }}]
public_from = 3
slots = ["a0"]

[[family]]
layer = "l"
name = "env_b"
members = ["env"]
link_in = {{ index = 0, link = "Seed" }}
binds = [{{ slot = "ctx", index = 1 }}]
bind_const = [{{ index = 2, value = 11 }}]
public_from = 3
slots = ["b0"]

[[family]]
layer = "l"
name = "env_a2"
members = ["env"]
link_in = {{ index = 0, link = "Seed" }}
bind_const = [{{ index = 2, value = "0x0a" }}]
public_from = 3
slots = ["a1"]

[[pipeline]]
name = "p"
positions = [{pipeline}]
"#
        ))
        .unwrap()
    }

    fn actives() -> BTreeMap<String, Active> {
        ["env", "seed"]
            .iter()
            .map(|l| {
                (
                    l.to_string(),
                    Active {
                        vk_hash: Some(format!("0x0{}", l.len())),
                        record_fields: 4,
                        is_app: true,
                    },
                )
            })
            .collect()
    }

    /// One circuit under two constant bindings is two families with two
    /// layouts; the same binding twice in one pipeline is refused.
    #[test]
    fn constant_bindings_distinguish_families_and_positions() {
        let m = manifest(r#""lib/l/seed", "lib/l/env_a", "lib/l/env_b""#);
        let fs = families(Path::new("."), &m, ("lib", "1.0.0"), &actives(), &[]);
        assert_eq!(fs[1].consts, vec![(2, Field::from(10u64))]);
        assert_eq!(fs[2].consts, vec![(2, Field::from(11u64))]);
        assert_ne!(
            fs[1].root, fs[2].root,
            "two families over one circuit: two identities"
        );
        let ps = pipelines(&m, &fs);
        assert_ne!(ps[0].positions[1].1.hash(), ps[0].positions[2].1.hash());
        assert_eq!(ps[0].positions[1].1.consts, vec![(2, Field::from(10u64))]);
    }

    #[test]
    #[should_panic(expected = "the same circuit under the same constant bindings")]
    fn the_same_circuit_under_one_constant_twice_is_refused() {
        let m = manifest(r#""lib/l/seed", "lib/l/env_a", "lib/l/env_a2""#);
        let fs = families(Path::new("."), &m, ("lib", "1.0.0"), &actives(), &[]);
        let _ = pipelines(&m, &fs);
    }
}
