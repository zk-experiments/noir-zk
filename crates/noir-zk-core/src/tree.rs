//! The key trees the pipeline kernels check (`noir-zk-kernels`), with the
//! same Poseidon2 as Noir's, so build scripts (`noir-zk-codegen`) and the
//! runtime compute the same roots.
//!
//! - A *family* tree: height [`FAMILY_HEIGHT`] over the sorted key hashes of
//!   a family's circuits (zero-padded), prefixed by the family's identity:
//!   `family_root = H(DOMAIN_FAMILY, H(library, version, layer, family), tree_root)`.
//!   The same circuit in two libraries or versions gives different roots; a
//!   one-circuit family is a one-leaf tree with that prefix.
//! - A *pipeline* tree: height [`PIPELINE_HEIGHT`], leaf `p` =
//!   `H(DOMAIN_POSITION, p, family_root, layout_hash)` for position `p`, and
//!   the kernels' family at the last index under [`ROLE_KERNEL`].
//! - A *deployment* tree: height [`DEPLOYMENT_HEIGHT`] over the pipeline
//!   roots a registry declares, in order. The verifier pins its root.
//!
//! Limits: 256 circuits per family, 15 positions per pipeline, 16 pipelines
//! per deployment. Node = `H(left, right)`, empty leaves are 0.

use ark_ff::Zero;
use pso_poseidon::poseidon2::Poseidon2;

use crate::zk::Field;

/// Height of a family tree (256 circuits).
pub const FAMILY_HEIGHT: usize = 8;
/// Height of a pipeline tree (15 positions plus the kernels).
pub const PIPELINE_HEIGHT: usize = 4;
/// Height of a deployment tree (16 pipelines).
pub const DEPLOYMENT_HEIGHT: usize = 4;
/// The pipeline-tree leaf of the kernels' family.
pub const KERNEL_LEAF: usize = (1 << PIPELINE_HEIGHT) - 1;
/// The kernels' "position" in their pipeline-tree leaf (`kernel::ROLE_KERNEL`).
pub const ROLE_KERNEL: u64 = 0xffff_ffff;

/// Noir's `Poseidon2::hash(x, N)`.
pub fn hash(inputs: &[Field]) -> Field {
    Poseidon2::<Field>::new().hash_noir(inputs)
}

/// A string as field elements: 31-byte big-endian chunks, then the length.
fn chunks(s: &str) -> Vec<Field> {
    let mut v: Vec<Field> = s
        .as_bytes()
        .chunks(31)
        .map(ark_ff::PrimeField::from_be_bytes_mod_order)
        .collect();
    v.push(Field::from(s.len() as u64));
    v
}

/// A domain tag: the ASCII string as a big-endian integer (at most 31 bytes).
pub fn domain(tag: &str) -> Field {
    debug_assert!(tag.len() <= 31);
    ark_ff::PrimeField::from_be_bytes_mod_order(tag.as_bytes())
}

/// `"noir-zk/family/v1"`.
pub fn domain_family() -> Field {
    domain("noir-zk/family/v1")
}

/// `"noir-zk/position/v1"`.
pub fn domain_position() -> Field {
    domain("noir-zk/position/v1")
}

/// A family's identity: `H(library, version, layer, family)` over the names' chunks.
pub fn family_id(library: &str, version: &str, layer: &str, family: &str) -> Field {
    let mut v = vec![];
    for s in [library, version, layer, family] {
        v.push(hash(&chunks(s)));
    }
    hash(&v)
}

/// A family's root over its circuits' key hashes (sorted here).
pub fn family_root(id: Field, key_hashes: &[Field]) -> Field {
    let mut leaves = key_hashes.to_vec();
    leaves.sort();
    hash(&[
        domain_family(),
        id,
        Tree::build(&leaves, FAMILY_HEIGHT).root,
    ])
}

/// A pipeline-tree leaf: `H(DOMAIN_POSITION, position, family_root, layout_hash)`.
pub fn position_leaf(position: u64, family_root: Field, layout_hash: Field) -> Field {
    hash(&[
        domain_position(),
        Field::from(position),
        family_root,
        layout_hash,
    ])
}

/// A leaf's authentication path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    /// Leaf index.
    pub index: u64,
    /// Siblings from the leaf up.
    pub siblings: Vec<Field>,
}

impl Path {
    /// The root this path gives for `leaf`.
    pub fn root(&self, leaf: Field) -> Field {
        self.siblings.iter().enumerate().fold(leaf, |node, (l, s)| {
            if (self.index >> l) & 1 == 1 {
                hash(&[*s, node])
            } else {
                hash(&[node, *s])
            }
        })
    }
}

/// A Poseidon2 Merkle tree of fixed height over the given leaves, the rest zero.
#[derive(Clone, Debug)]
pub struct Tree {
    /// The root.
    pub root: Field,
    paths: Vec<Path>,
}

impl Tree {
    /// Builds the tree; panics if `leaves` exceed the height.
    pub fn build(leaves: &[Field], height: usize) -> Self {
        assert!(
            leaves.len() <= 1 << height,
            "{} leaves exceed a tree of height {height}",
            leaves.len()
        );
        let mut level = leaves.to_vec();
        level.resize(1 << height, Field::zero());
        let mut levels = vec![level];
        for h in 0..height {
            let next = levels[h].chunks(2).map(|p| hash(&[p[0], p[1]])).collect();
            levels.push(next);
        }
        let paths = (0..leaves.len())
            .map(|i| Path {
                index: i as u64,
                siblings: (0..height).map(|h| levels[h][(i >> h) ^ 1]).collect(),
            })
            .collect();
        Self {
            root: levels[height][0],
            paths,
        }
    }

    /// The path of leaf `index`.
    pub fn path(&self, index: usize) -> &Path {
        &self.paths[index]
    }

    /// Number of leaves given.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Whether no leaf was given.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_give_the_root() {
        let leaves: Vec<Field> = (1..=5u64).map(Field::from).collect();
        let t = Tree::build(&leaves, 3);
        for (i, l) in leaves.iter().enumerate() {
            assert_eq!(t.path(i).root(*l), t.root);
        }
        assert_ne!(t.path(0).root(leaves[1]), t.root);
    }

    #[test]
    fn family_roots_are_domain_separated() {
        let keys = [Field::from(7u64)];
        let a = family_root(family_id("lib", "1.0.0", "layer", "f"), &keys);
        assert_ne!(
            a,
            family_root(family_id("lib", "1.0.1", "layer", "f"), &keys),
            "another version"
        );
        assert_ne!(
            a,
            family_root(family_id("other", "1.0.0", "layer", "f"), &keys),
            "another library"
        );
        assert_ne!(
            a,
            family_root(family_id("lib", "1.0.0", "layer", "g"), &keys),
            "another family"
        );
        // A one-circuit family is a one-leaf tree with the prefix, not the key hash.
        assert_ne!(a, keys[0]);
        assert_ne!(a, Tree::build(&keys, FAMILY_HEIGHT).root);
        // Sorted: order of the key hashes doesn't matter.
        let id = family_id("lib", "1.0.0", "layer", "f");
        let (x, y) = (Field::from(3u64), Field::from(9u64));
        assert_eq!(family_root(id, &[x, y]), family_root(id, &[y, x]));
        assert_ne!(
            position_leaf(0, a, Field::zero()),
            position_leaf(1, a, Field::zero())
        );
    }
}
