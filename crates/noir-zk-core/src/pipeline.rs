//! Pipelines: ordered lists of *families* (circuits sharing a record shape)
//! folded by the generic kernels of `noir-zk-kernels`. What a registry
//! declares about them ([`FamilyEntry`], [`PipelineEntry`]), the kernel's
//! view of a position ([`Layout`]), the link types the builder checks at
//! compile time ([`Link`], [`Accepts`], [`Next`]), and the family marker
//! types codegen generates ([`StepFamily`]).
//!
//! The kernels' state is `[pipeline_root, position, link, write_ptr,
//! slot × P]`; an app's record is its databus outputs zero-padded to `R`;
//! the hiding kernel publishes `[deployment_root, pipeline_root, length,
//! slot × P]`.

use crate::error::Error;
use crate::tree::{hash, position_leaf};
use crate::zk::Field;
use std::marker::PhantomData;

/// Record width (`kernel::R`): an app returns at most this many fields.
pub const R: usize = 16;
/// Public slots (`kernel::P`).
pub const P: usize = 32;
/// Bindings per position (`kernel::B`).
pub const B: usize = 2;
/// The state between kernels.
pub const STATE_FIELDS: usize = 4 + P;
/// The hiding kernel's outputs: `deployment_root`, `pipeline_root`, `length`, the slots.
pub const PUBLIC_FIELDS: usize = 3 + P;
/// The `Vk` key size of the kernels (bb 7's Chonk key as fields).
pub const VK_FIELDS: usize = 151;

/// How the kernel reads a position's record, resolved (slot indices).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Record index that must equal the state's link, or none.
    pub link_in: Option<usize>,
    /// Record index that becomes the state's link, or none.
    pub link_out: Option<usize>,
    /// (public slot index, record index) pairs that must be equal.
    pub binds: Vec<(usize, usize)>,
    /// The record range made public: `pub_from .. pub_from + n_pub`.
    pub pub_from: usize,
    /// Its length.
    pub n_pub: usize,
}

impl Layout {
    fn idx(i: Option<usize>) -> u64 {
        i.map_or(R as u64, |x| x as u64)
    }

    fn bind(&self, i: usize) -> (u64, u64) {
        self.binds
            .get(i)
            .map_or((0, 0), |(s, r)| (*s as u64, *r as u64))
    }

    /// `H(link_in, link_out, n_bind, bind_slot × B, bind_index × B, pub_from, n_pub)`,
    /// with `R` for "no link".
    pub fn hash(&self) -> Field {
        let mut v = vec![
            Self::idx(self.link_in),
            Self::idx(self.link_out),
            self.binds.len() as u64,
        ];
        v.extend((0..B).map(|i| self.bind(i).0));
        v.extend((0..B).map(|i| self.bind(i).1));
        v.extend([self.pub_from as u64, self.n_pub as u64]);
        hash(&v.into_iter().map(Field::from).collect::<Vec<_>>())
    }

    /// The kernel's `Layout` parameter as fields, in ABI order.
    pub fn fields(&self) -> Vec<Field> {
        let mut v = vec![
            Self::idx(self.link_in),
            Self::idx(self.link_out),
            self.binds.len() as u64,
        ];
        v.extend((0..B).map(|i| self.bind(i).0));
        v.extend((0..B).map(|i| self.bind(i).1));
        v.extend([self.pub_from as u64, self.n_pub as u64]);
        v.into_iter().map(Field::from).collect()
    }
}

/// A family's link declaration: the record index and the link type's name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkSpec {
    /// Record index.
    pub index: usize,
    /// The link type (a name; codegen makes it a type).
    pub link: &'static str,
}

/// A family's binding: a public slot name and the record index it must equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindSpec {
    /// The slot, published by an earlier position.
    pub slot: &'static str,
    /// Record index.
    pub index: usize,
}

/// A family reference: `library/layer/family`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FamilyRef {
    /// The library that owns the family.
    pub library: &'static str,
    /// The layer.
    pub layer: &'static str,
    /// The family's name.
    pub family: &'static str,
}

impl std::fmt::Display for FamilyRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.library, self.layer, self.family)
    }
}

/// A family as a registry declares it: its circuits, its kernel-step
/// definition (links, bindings, public slots) and its tree's root.
#[derive(Clone, Debug)]
pub struct FamilyEntry {
    /// `library/layer/family`.
    pub id: FamilyRef,
    /// The library's version (part of the family's identity).
    pub version: &'static str,
    /// The circuits (labels) and their key hashes (`H(vk fields)`).
    pub members: &'static [(&'static str, [u8; 32])],
    /// Fields of the record (the members' databus outputs).
    pub record_fields: usize,
    /// The link the family continues.
    pub link_in: Option<LinkSpec>,
    /// The link the family leaves.
    pub link_out: Option<LinkSpec>,
    /// Bindings to public slots.
    pub binds: &'static [BindSpec],
    /// Record index the public fields start at.
    pub public_from: usize,
    /// The public fields' slot names, from `public_from`.
    pub slots: &'static [&'static str],
    /// `family_root` (big-endian).
    pub root: [u8; 32],
}

impl FamilyEntry {
    /// Whether `label` is a member.
    pub fn has(&self, label: &str) -> bool {
        self.members.iter().any(|(l, _)| *l == label)
    }

    /// The family root as a field.
    pub fn root_field(&self) -> Field {
        crate::codec::field_from_be_bytes(&self.root)
    }

    /// Resolves the layout for a pipeline that has published `slots` so far.
    pub fn layout(&self, published: &[&str]) -> Result<Layout, Error> {
        let binds = self
            .binds
            .iter()
            .map(|b| {
                published
                    .iter()
                    .position(|s| *s == b.slot)
                    .map(|s| (s, b.index))
                    .ok_or_else(|| {
                        Error::Abi(format!(
                            "{}: binds slot {}, which no earlier position publishes",
                            self.id, b.slot
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if binds.len() > B || self.public_from + self.slots.len() > R {
            return Err(Error::Abi(format!(
                "{}: exceeds the kernel's bounds",
                self.id
            )));
        }
        Ok(Layout {
            link_in: self.link_in.map(|l| l.index),
            link_out: self.link_out.map(|l| l.index),
            binds,
            pub_from: self.public_from,
            n_pub: self.slots.len(),
        })
    }
}

/// One position of a declared pipeline, resolved at codegen.
#[derive(Clone, Debug)]
pub struct PositionEntry {
    /// The family.
    pub family: FamilyRef,
    /// Its layout in this pipeline.
    pub layout: Layout,
}

/// A pipeline as a registry declares it.
#[derive(Clone, Debug)]
pub struct PipelineEntry {
    /// Its name.
    pub name: &'static str,
    /// Its index in the deployment tree.
    pub index: usize,
    /// Its positions.
    pub positions: Vec<PositionEntry>,
    /// Every public slot's name, in state order.
    pub slots: Vec<&'static str>,
    /// Its root (big-endian).
    pub root: [u8; 32],
}

impl PipelineEntry {
    /// Number of positions.
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    /// Whether it has no position.
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    /// The root as a field.
    pub fn root_field(&self) -> Field {
        crate::codec::field_from_be_bytes(&self.root)
    }

    /// The pipeline tree's leaves (positions, zeros, the kernels' family last).
    pub fn leaves(
        families: &dyn Fn(&FamilyRef) -> Option<Field>,
        positions: &[PositionEntry],
        kernels_root: Field,
    ) -> Result<Vec<Field>, Error> {
        if positions.len() >= crate::tree::KERNEL_LEAF {
            return Err(Error::Abi(format!(
                "{} positions: at most {}",
                positions.len(),
                crate::tree::KERNEL_LEAF - 1
            )));
        }
        let mut leaves = positions
            .iter()
            .enumerate()
            .map(|(p, pos)| {
                let root = families(&pos.family)
                    .ok_or_else(|| Error::Artifact(format!("no family {}", pos.family)))?;
                Ok(position_leaf(p as u64, root, pos.layout.hash()))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        leaves.resize(crate::tree::KERNEL_LEAF, Field::from(0u64));
        leaves.push(position_leaf(
            crate::tree::ROLE_KERNEL,
            kernels_root,
            Field::from(0u64),
        ));
        Ok(leaves)
    }
}

/// The deployment a registry declares: its pipelines' roots, in order, and
/// the tree over them. The verifier pins `root`.
#[derive(Clone, Debug)]
pub struct DeploymentEntry {
    /// The pipeline roots (big-endian), in declaration order.
    pub roots: &'static [[u8; 32]],
    /// The deployment root (big-endian).
    pub root: [u8; 32],
}

impl DeploymentEntry {
    /// The root as a field.
    pub fn root_field(&self) -> Field {
        crate::codec::field_from_be_bytes(&self.root)
    }

    /// The tree over the pipeline roots.
    pub fn tree(&self) -> crate::tree::Tree {
        let leaves: Vec<Field> = self
            .roots
            .iter()
            .map(|r| crate::codec::field_from_be_bytes(r))
            .collect();
        crate::tree::Tree::build(&leaves, crate::tree::DEPLOYMENT_HEIGHT)
    }
}

// ------------------------------------------------------------ links

/// A value that continues from one position to the next (one record field).
pub trait Link: 'static {}

/// `LinkIn` of a family that continues nothing, `LinkOut` of one that
/// leaves the link as it was.
pub struct NoLink;
impl Link for NoLink {}

/// `Self` (a family's `LinkIn`) may follow a position whose `LinkOut` is `Prev`.
pub trait Accepts<Prev: Link>: Link {}
impl<P: Link> Accepts<P> for NoLink {}

/// The pipeline's link after a position with `LinkOut = Self`, given `Prev`.
pub trait Next<Prev: Link>: Link {
    /// The link after.
    type Out: Link;
}
impl<P: Link> Next<P> for NoLink {
    type Out = P;
}

/// Declares link types: `links!(CA, CB)` defines unit types `CA`, `CB` that
/// accept only themselves and replace the previous link.
#[macro_export]
macro_rules! links {
    ($($(#[$doc:meta])* $l:ident),* $(,)?) => {$(
        $(#[$doc])*
        pub struct $l;
        impl $crate::pipeline::Link for $l {}
        impl $crate::pipeline::Accepts<$l> for $l {}
        impl<P: $crate::pipeline::Link> $crate::pipeline::Next<P> for $l { type Out = $l; }
    )*};
}

/// Link types with a meaning shared across libraries, so that families of
/// different registries can chain: a family declaring `link = "PayloadCommitment"`
/// gets this type rather than one generated for its registry.
pub mod links {
    crate::links!(
        /// A hiding commitment to a six-field payload, `H(domain, salt, payload)`,
        /// as a payload envelope opens it (the domain is the committing library's
        /// and names the size). Another payload size is another link type here,
        /// with its own envelope instantiation and family in the libraries.
        PayloadCommitment,
    );
}

// ------------------------------------------------------------ families

/// A family marker type (generated): what the pipeline builder needs to fold
/// one of its circuits at a position.
pub trait StepFamily: 'static {
    /// The family's record (its circuits' typed outputs).
    type Record: crate::codec::FromFields + crate::codec::FieldEncode;
    /// The link it continues.
    type LinkIn: Link;
    /// The link it leaves.
    type LinkOut: Link;
    /// The family's registry entry.
    fn family() -> &'static FamilyEntry;

    /// Chooses the member `label` with its `Prover.toml` inputs.
    fn select(label: &str, toml: impl Into<String>) -> Result<Selected<Self>, Error>
    where
        Self: Sized,
    {
        let f = Self::family();
        let (label, _) = f
            .members
            .iter()
            .find(|(l, _)| *l == label)
            .ok_or_else(|| Error::Artifact(format!("{label} is not a circuit of {}", f.id)))?;
        Ok(Selected {
            label,
            toml: toml.into(),
            _f: PhantomData,
        })
    }
}

/// A circuit chosen from family `F`, with its inputs.
#[derive(Clone, Debug)]
pub struct Selected<F> {
    /// The circuit.
    pub label: &'static str,
    /// Its `Prover.toml`.
    pub toml: String,
    _f: PhantomData<F>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_resolve_bindings_against_published_slots() {
        let f = FamilyEntry {
            id: FamilyRef {
                library: "lib",
                layer: "l",
                family: "env",
            },
            version: "1.0.0",
            members: &[("env", [0; 32])],
            record_fields: 9,
            link_in: Some(LinkSpec {
                index: 0,
                link: "Dg1",
            }),
            link_out: None,
            binds: &[
                BindSpec {
                    slot: "ctx",
                    index: 1,
                },
                BindSpec {
                    slot: "c_t",
                    index: 2,
                },
            ],
            public_from: 3,
            slots: &["c_id0", "c_id1"],
            root: [0; 32],
        };
        let l = f.layout(&["a", "ctx", "c_t"]).unwrap();
        assert_eq!(l.binds, vec![(1, 1), (2, 2)]);
        assert_eq!(
            (l.link_in, l.link_out, l.pub_from, l.n_pub),
            (Some(0), None, 3, 2)
        );
        assert!(f.layout(&["a"]).is_err(), "ctx not published");
        assert_ne!(l.hash(), f.layout(&["ctx", "c_t"]).unwrap().hash());
        assert_eq!(l.fields().len(), 3 + 2 * B + 2);
    }
}
