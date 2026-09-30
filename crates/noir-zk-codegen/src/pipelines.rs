//! The layered part of a registry: families, wrapped registries, pipelines
//! and the deployment, read from `circuits/manifest.toml` and emitted as
//! typed code with roots computed here (the same Poseidon2 as the runtime).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use noir_zk_core::codec::{field_from_be_bytes, field_to_be_bytes32};
use noir_zk_core::tree::{self, Tree, DEPLOYMENT_HEIGHT, PIPELINE_HEIGHT};
use noir_zk_core::{Field, Layout};
use proc_macro2::TokenStream;
use quote::quote;

use crate::camel;
use crate::tokens::{bytes32, doc, ident, usize_lit};

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

/// A field element as its 32-byte big-endian array.
fn field(f: &Field) -> TokenStream {
    bytes32(&hex::encode(field_to_be_bytes32(f)))
}

/// A slot name as a Rust field name.
fn slot_ident(slot: &str) -> proc_macro2::Ident {
    let s: String = slot
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    ident(&if s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        format!("s_{s}")
    } else {
        s
    })
}

fn family_ref(f: &Family) -> TokenStream {
    let (library, layer, name) = (&f.library, &f.layer, &f.name);
    quote!(noir_zk_core::FamilyRef { library: #library, layer: #layer, family: #name })
}

fn option(o: Option<usize>) -> TokenStream {
    o.map_or_else(
        || quote!(None),
        |i| {
            let i = usize_lit(i);
            quote!(Some(#i))
        },
    )
}

/// A family as its `FamilyEntry`.
fn family_entry(f: &Family) -> TokenStream {
    let id = family_ref(f);
    let version = &f.version;
    let members = f.members.iter().map(|(l, h)| {
        let h = bytes32(h);
        quote!((#l, #h))
    });
    let spec = |l: &Option<(usize, String)>| {
        l.as_ref().map_or_else(
            || quote!(None),
            |(i, n)| {
                let i = usize_lit(*i);
                quote!(Some(noir_zk_core::LinkSpec { index: #i, link: #n }))
            },
        )
    };
    let (link_in, link_out) = (spec(&f.link_in), spec(&f.link_out));
    let binds = f.binds.iter().map(|(s, i)| {
        let i = usize_lit(*i);
        quote!(noir_zk_core::BindSpec { slot: #s, index: #i })
    });
    let consts = f.consts.iter().map(|(i, v)| {
        let (i, v) = (usize_lit(*i), field(v));
        quote!(noir_zk_core::ConstSpec { index: #i, value: #v })
    });
    let (record_fields, public_from) = (usize_lit(f.record_fields), usize_lit(f.public_from));
    let slots = &f.slots;
    let root = field(&f.root);
    quote! {
        noir_zk_core::FamilyEntry {
            id: #id,
            version: #version,
            members: &[#(#members),*],
            record_fields: #record_fields,
            link_in: #link_in,
            link_out: #link_out,
            binds: &[#(#binds),*],
            consts: &[#(#consts),*],
            public_from: #public_from,
            slots: &[#(#slots),*],
            root: #root,
        }
    }
}

/// A pipeline position as its `PositionEntry`.
fn position_entry(f: &Family, l: &Layout) -> TokenStream {
    let family = family_ref(f);
    let (link_in, link_out) = (option(l.link_in), option(l.link_out));
    let binds = l.binds.iter().map(|(s, r)| {
        let (s, r) = (usize_lit(*s), usize_lit(*r));
        quote!((#s, #r))
    });
    let consts = l.consts.iter().map(|(i, v)| {
        let (i, v) = (usize_lit(*i), field(v));
        quote!((#i, noir_zk_core::codec::field_from_be_bytes(&#v)))
    });
    let (pub_from, n_pub) = (usize_lit(l.pub_from), usize_lit(l.n_pub));
    // Inside `vec![…]`, which is printed as written: no trailing commas.
    quote! {
        noir_zk_core::PositionEntry {
            family: #family,
            layout: noir_zk_core::Layout {
                link_in: #link_in,
                link_out: #link_out,
                binds: vec![#(#binds),*],
                pub_from: #pub_from,
                n_pub: #n_pub,
                consts: vec![#(#consts),*]
            }
        }
    }
}

/// `pipelines::<name>`: the root, the entry, the typed outputs, `fold` and `verify`.
fn pipeline_module(index: usize, p: &Pipeline, families: &[Family]) -> TokenStream {
    let text = format!(
        "Pipeline `{}`: {}.",
        p.name,
        p.positions
            .iter()
            .map(|(fi, _)| families[*fi].id())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let module_doc = doc(&text);
    let module = ident(&p.name);
    let name = &p.name;
    let root = field(&p.root);
    let index = usize_lit(index);
    let positions = p
        .positions
        .iter()
        .map(|(fi, l)| position_entry(&families[*fi], l));
    let slots = &p.slots;
    let slot_fields = p.slots.iter().map(|s| {
        let (d, n) = (doc(&format!("Slot `{s}`.")), slot_ident(s));
        quote! {
            #d
            pub #n: noir_zk_core::Field,
        }
    });
    let slot_reads = p.slots.iter().enumerate().map(|(i, s)| {
        let (n, at) = (slot_ident(s), usize_lit(3 + i));
        quote!(#n: f[#at],)
    });
    quote! {
        #module_doc
        pub mod #module {
            #[doc = " The pipeline root (big-endian)."]
            pub const ROOT: [u8; 32] = #root;
            #[doc = " Its index in the deployment tree."]
            pub const INDEX: usize = #index;
            #[doc = " The pipeline as the builder folds it."]
            pub static PIPELINE: std::sync::LazyLock<noir_zk_core::PipelineEntry> = std::sync::LazyLock::new(|| noir_zk_core::PipelineEntry {
                name: #name,
                index: #index,
                positions: vec![#(#positions),*],
                slots: vec![#(#slots),*],
                root: ROOT,
            });

            #[doc = " The proof's public outputs: the deployment and pipeline roots, the length, then the slots by name."]
            #[derive(Clone, Debug, PartialEq, Eq)]
            pub struct Outputs {
                #[doc = " The deployment root the verifier pins."]
                pub deployment_root: noir_zk_core::Field,
                #[doc = " This pipeline's root."]
                pub pipeline_root: noir_zk_core::Field,
                #[doc = " The number of positions folded."]
                pub length: u64,
                #(#slot_fields)*
            }

            impl Outputs {
                #[doc = " From the hiding kernel's public fields."]
                pub fn from_fields(f: &[noir_zk_core::Field]) -> Self {
                    Self {
                        deployment_root: f[0],
                        pipeline_root: f[1],
                        length: noir_zk_core::codec::field_to_u64(&f[2]).unwrap_or(u64::MAX),
                        #(#slot_reads)*
                    }
                }
            }

            #[doc = " Starts folding this pipeline over `artifacts` (the merged pool of every registry it draws from, plus the kernels)."]
            pub fn fold<'a>(artifacts: &'a dyn noir_zk_core::Artifacts) -> Result<noir_zk_backend::pipeline::PipelineFold<'a, noir_zk_core::NoLink>, noir_zk_core::Error> {
                noir_zk_backend::pipeline::PipelineFold::new(artifacts, &PIPELINE)
            }

            #[doc = " Verifies `proof` (hiding key, deployment root, pipeline root, length) and returns its outputs."]
            pub fn verify(proof: &noir_zk_backend::chonk::FoldedProof) -> Result<Outputs, noir_zk_core::Error> {
                let f = noir_zk_backend::pipeline::verify(proof, &PIPELINE, super::super::DEPLOYMENT.root_field(), noir_zk_backend::pipeline::hiding_vk())?;
                Ok(Outputs::from_fields(&f))
            }
        }
    }
}

/// The generated code: `WRAPPED`, `layer_of`, `links`, `FAMILIES`,
/// `families`, `pipelines`, `DEPLOYMENT` and the roots test.
pub(crate) fn emit(families: &[Family], pipelines: &[Pipeline]) -> TokenStream {
    if families.is_empty() {
        return TokenStream::new();
    }
    // Wrapped members as registry entries (their bytecode, ABI and key come
    // from the wrapped registry's own artifacts at run time).
    let wrapped = families.iter().filter(|f| f.wrapped).flat_map(|f| {
        f.members.iter().map(move |(label, h)| {
            let (version, layer, name, h) = (&f.version, &f.layer, &f.name, bytes32(h));
            quote! {
                noir_zk_core::RegistryEntry { label: #label, version: #version, system: noir_zk_core::ProofSystem::Chonk(noir_zk_core::ChonkRole::App), status: noir_zk_core::Status::Active, bytecode_sha256: [0; 32], vk_sha256: [0; 32], vk_hash: #h, layer: #layer, family: #name, abi: None, vk: &[], vk_index: None, vk_siblings: &[] }
            }
        })
    });
    let mut seen = BTreeSet::new();
    let layers: Vec<TokenStream> = families
        .iter()
        .flat_map(|f| f.members.iter().map(move |(label, _)| (label, &f.layer)))
        .filter(|(label, _)| seen.insert((*label).clone()))
        .map(|(label, layer)| quote!(#label => Some(#layer),))
        .collect();
    // Links.
    let links: BTreeSet<&str> = families
        .iter()
        .flat_map(|f| [&f.link_in, &f.link_out])
        .filter_map(|l| l.as_ref().map(|(_, n)| n.as_str()))
        .collect();
    let (shared, own): (Vec<&str>, Vec<&str>) = links
        .iter()
        .copied()
        .partition(|l| SHARED_LINKS.contains(l));
    let shared = shared.iter().map(|l| ident(l));
    let own_links = (!own.is_empty()).then(|| {
        let own = own.iter().map(|l| ident(l));
        quote!(noir_zk_core::links!(#(#own),*);)
    });
    let entries = families.iter().map(family_entry);
    // Family marker types.
    let markers = families.iter().enumerate().map(|(i, f)| {
        let d = doc(&format!(
            "Family `{}` ({} circuits, record `[Fr; {}]`).",
            f.id(),
            f.members.len(),
            f.record_fields
        ));
        let ty = ident(&f.type_name());
        let n = usize_lit(f.record_fields);
        let link = |l: &Option<(usize, String)>| {
            let l = ident(l.as_ref().map_or("NoLink", |(_, n)| n.as_str()));
            quote!(super::links::#l)
        };
        let (link_in, link_out) = (link(&f.link_in), link(&f.link_out));
        let i = usize_lit(i);
        quote! {
            #d
            pub struct #ty;
            impl noir_zk_core::StepFamily for #ty {
                type Record = [noir_zk_core::Field; #n];
                type LinkIn = #link_in;
                type LinkOut = #link_out;
                fn family() -> &'static noir_zk_core::FamilyEntry {
                    &super::FAMILIES[#i]
                }
            }
        }
    });
    let mut code = quote! {
        #[doc = " Circuits of wrapped registries (other libraries' families): identity only."]
        pub const WRAPPED: &[noir_zk_core::RegistryEntry] = &[#(#wrapped),*];

        #[doc = " The layer of a circuit of this registry or a wrapped one."]
        pub fn layer_of(label: &str) -> Option<&'static str> {
            match label {
                #(#layers)*
                _ => None,
            }
        }

        #[doc = " The link types the families declare (noir-zk's shared vocabulary re-exported, the rest generated)."]
        pub mod links {
            pub use noir_zk_core::NoLink;
            #(pub use noir_zk_core::pipeline::links::#shared;)*
            #own_links
        }

        #[doc = " Every family this registry declares (its own and wrapped ones)."]
        pub static FAMILIES: &[noir_zk_core::FamilyEntry] = &[#(#entries),*];

        #[doc = " One marker type per family: what the pipeline builder folds at a position."]
        pub mod families {
            #(#markers)*
        }
    };
    if pipelines.is_empty() {
        return code;
    }
    // Pipelines.
    let roots: Vec<Field> = pipelines.iter().map(|p| p.root).collect();
    let deployment = field(&Tree::build(&roots, DEPLOYMENT_HEIGHT).root);
    let modules = pipelines
        .iter()
        .enumerate()
        .map(|(i, p)| pipeline_module(i, p, families));
    let root_values = roots.iter().map(field);
    // The roots test.
    let checks = pipelines.iter().map(|p| {
        let (m, name) = (ident(&p.name), format!("pipeline {}", p.name));
        quote! {
            {
                let p = &*super::pipelines::#m::PIPELINE;
                let leaves = noir_zk_core::PipelineEntry::leaves(&|id| super::FAMILIES.iter().find(|f| f.id == *id).map(|f| f.root_field()), &p.positions, kernels).unwrap();
                assert_eq!(tree::Tree::build(&leaves, tree::PIPELINE_HEIGHT).root, p.root_field(), #name);
                roots.push(p.root_field());
            }
        }
    });
    code.extend(quote! {
        #[doc = " The pipelines this registry declares: each with its root, its typed outputs, `fold` and `verify`."]
        pub mod pipelines {
            #(#modules)*
        }

        #[doc = " The deployment root: the tree over the pipelines' roots, in declaration order. Verifiers pin it."]
        pub const DEPLOYMENT_ROOT: [u8; 32] = #deployment;
        #[doc = " The deployment: the pipeline roots and their tree."]
        pub static DEPLOYMENT: noir_zk_core::DeploymentEntry = noir_zk_core::DeploymentEntry {
            roots: &[#(#root_values),*],
            root: DEPLOYMENT_ROOT,
        };

        #[cfg(test)]
        mod generated_roots {
            #[doc = " Every family, pipeline and deployment root recomputed at run time equals its constant."]
            #[test]
            fn roots_match_the_constants() {
                use noir_zk_core::tree;
                for f in super::FAMILIES {
                    let hashes: Vec<noir_zk_core::Field> = f.members.iter().map(|(_, h)| noir_zk_core::codec::field_from_be_bytes(h)).collect();
                    assert_eq!(tree::family_root(tree::family_id(f.id.library, f.version, f.id.layer, f.id.family), &hashes), f.root_field(), "family {}", f.id);
                }
                let kernels = noir_zk_backend::kernels::FAMILY.root_field();
                let mut roots = vec![];
                #(#checks)*
                assert_eq!(tree::Tree::build(&roots, tree::DEPLOYMENT_HEIGHT).root, super::DEPLOYMENT.root_field(), "deployment");
            }
        }
    });
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
