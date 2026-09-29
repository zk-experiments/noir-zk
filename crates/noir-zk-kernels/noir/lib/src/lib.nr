//! The generic pipeline kernels (noir-zk): one step kernel folds any app at
//! any position of a pipeline, so an ordered list of app families folds with
//! the same three kernel circuits (plus a padding kernel for one-app pipelines).
//!
//! ```text
//! app_0 -> kernel_init -> app_1 -> kernel_step -> ... -> app_{n-1} -> kernel_step -> kernel_hiding
//! ```
//!
//! An app returns its raw outputs through the databus (up to `R` fields; a
//! shorter record is read zero-padded). How the kernel reads them is a
//! `Layout` committed in the pipeline tree with the app's family and its
//! position. Keys are checked in two levels: the app's `H(vk)` is a leaf of
//! its family's tree (height `FAMILY_HEIGHT`, whose root is
//! `H(DOMAIN_FAMILY, family id, tree root)` computed by the registry), and
//! `H(DOMAIN_POSITION, position, family_root, H(layout))` is a leaf of the
//! pipeline tree (height `PIPELINE_HEIGHT`; the kernels' family at the last
//! index under `ROLE_KERNEL`). The hiding kernel proves the pipeline root is
//! a leaf of the deployment tree (height `DEPLOYMENT_HEIGHT`) and publishes
//! the deployment root, the pipeline root, the length (position reached)
//! and the slots.

use poseidon::poseidon2::Poseidon2;

/// Fields of a Chonk (Mega) verification key (bb 7.0.0-nightly.20260927).
pub global VK_FIELDS: u32 = 151;
/// Recursion proof types of bb 7.0.0-nightly.20260927.
pub global PROOF_TYPE_OINK: u32 = 1;
pub global PROOF_TYPE_HN: u32 = 2;
pub global PROOF_TYPE_HN_FINAL: u32 = 7;

pub global FAMILY_HEIGHT: u32 = 8;
pub global PIPELINE_HEIGHT: u32 = 4;
pub global DEPLOYMENT_HEIGHT: u32 = 4;

/// "noir-zk/family/v1" and "noir-zk/position/v1" as big-endian integers.
pub global DOMAIN_FAMILY: Field = 0x6e6f69722d7a6b2f66616d696c792f7631;
pub global DOMAIN_POSITION: Field = 0x6e6f69722d7a6b2f706f736974696f6e2f7631;
/// The kernels' "position" in the pipeline tree.
pub global ROLE_KERNEL: Field = 0xffffffff;

/// An app record: an app's databus outputs, zero-padded to `R`.
pub global R: u32 = 16;
/// Public slots of a pipeline.
pub global P: u32 = 24;
/// Bindings per position.
pub global B: u32 = 2;
/// A layout index meaning "none".
pub global NONE: u32 = R;

/// The state between kernels: `[pipeline_root, position, link, write_ptr, slot × P]`.
pub global STATE_FIELDS: u32 = 4 + P;
pub global S_PIPELINE_ROOT: u32 = 0;
pub global S_POSITION: u32 = 1;
pub global S_LINK: u32 = 2;
pub global S_WRITE_PTR: u32 = 3;
pub global S_SLOTS: u32 = 4;

pub fn hash<let N: u32>(x: [Field; N]) -> Field {
    Poseidon2::hash(x, N)
}

/// A leaf's authentication path: siblings from the leaf up; bit `l` of
/// `index` says the node is the right child at level `l`.
pub struct MerklePath<let N: u32> {
    pub index: Field,
    pub siblings: [Field; N],
}

pub fn merkle_root<let N: u32>(leaf: Field, path: MerklePath<N>) -> Field {
    let bits: [bool; N] = path.index.to_le_bits();
    let mut node = leaf;
    for l in 0..N {
        node = if bits[l] {
            hash([path.siblings[l], node])
        } else {
            hash([node, path.siblings[l]])
        };
    }
    node
}

/// A verification key with its two paths: in its family's tree (whose root,
/// prefixed with the family's identity `H(library, version, layer, family)`,
/// is the family root) and, with that root, in the pipeline tree.
pub struct Vk {
    pub key: [Field; VK_FIELDS],
    pub family: MerklePath<FAMILY_HEIGHT>,
    pub family_id: Field,
    pub pipeline: MerklePath<PIPELINE_HEIGHT>,
}

/// How a kernel reads one app's record (committed in the pipeline tree).
pub struct Layout {
    /// Record index that must equal the state's link, or `NONE`.
    pub link_in: u32,
    /// Record index that becomes the state's link, or `NONE`.
    pub link_out: u32,
    /// Bindings: `slot[bind_slot[i]] == record[bind_index[i]]` for `i < n_bind`.
    pub n_bind: u32,
    pub bind_slot: [u32; B],
    pub bind_index: [u32; B],
    /// The public outputs: `record[pub_from .. pub_from + n_pub]`, appended to the slots.
    pub pub_from: u32,
    pub n_pub: u32,
}

impl Layout {
    pub fn hash(self) -> Field {
        hash([
            self.link_in as Field,
            self.link_out as Field,
            self.n_bind as Field,
            self.bind_slot[0] as Field,
            self.bind_slot[1] as Field,
            self.bind_index[0] as Field,
            self.bind_index[1] as Field,
            self.pub_from as Field,
            self.n_pub as Field,
        ])
    }
}

/// Asserts `vk` is in its family's tree and the family (its root from its
/// identity and that tree) is in the pipeline tree with root `root` at
/// `position` with `layout_hash`; returns the key's hash (bb checks the
/// folded proof against it).
pub fn check_vk(root: Field, position: Field, layout_hash: Field, vk: Vk) -> Field {
    let vk_hash = hash(vk.key);
    let family_root = hash(
        [DOMAIN_FAMILY, vk.family_id, merkle_root(vk_hash, vk.family)],
    );
    assert_eq(
        merkle_root(
            hash([DOMAIN_POSITION, position, family_root, layout_hash]),
            vk.pipeline,
        ),
        root,
        "the key's family is not in the pipeline tree at this position with this layout",
    );
    vk_hash
}

/// The state after folding the app whose record is `step` under `l`.
pub fn apply(prev: [Field; STATE_FIELDS], step: [Field; R], l: Layout) -> [Field; STATE_FIELDS] {
    let mut s = prev;
    if l.link_in != NONE {
        assert_eq(step[l.link_in], prev[S_LINK], "app does not continue the pipeline's link");
    }
    if l.link_out != NONE {
        s[S_LINK] = step[l.link_out];
    }
    assert(l.n_bind <= B, "too many bindings");
    for i in 0..B {
        if i < l.n_bind {
            assert_eq(
                prev[S_SLOTS + l.bind_slot[i]],
                step[l.bind_index[i]],
                "app output differs from the public slot it is bound to",
            );
        }
    }
    let w = prev[S_WRITE_PTR] as u32;
    assert(l.pub_from + l.n_pub <= R, "public outputs beyond the record");
    assert(w + l.n_pub <= P, "no room left in the public slots");
    for i in 0..R {
        if i < l.n_pub {
            s[S_SLOTS + w + i] = step[l.pub_from + i];
        }
    }
    s[S_POSITION] = prev[S_POSITION] + 1;
    s[S_WRITE_PTR] = (w + l.n_pub) as Field;
    s
}

/// What the folded proof makes public.
pub struct PublicOutputs {
    pub deployment_root: Field,
    pub pipeline_root: Field,
    pub length: Field,
    pub slots: [Field; P],
}
