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
pub global P: u32 = 32;
/// Bindings per position.
pub global B: u32 = 2;
/// Constant bindings per position.
pub global C: u32 = 2;
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
        // Order the pair, then hash once (hashing inside each branch costs two).
        let (left, right) = if bits[l] {
            (path.siblings[l], node)
        } else {
            (node, path.siblings[l])
        };
        node = hash([left, right]);
    }
    node
}

/// A verification key with its two paths: in its family's tree (whose root,
/// prefixed with the family's identity `H(library, version, layer, family)`,
/// is the family root) and, with that root, in the pipeline tree.
pub struct Vk {
    pub key: [Field; VK_FIELDS],
    /// `H(key)`, the Poseidon2 hash of the key's fields (`noir_zk_core::tree::hash`), supplied by
    /// the prover rather than recomputed: Barretenberg constrains it (see `check_vk`).
    pub key_hash: Field,
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
    /// Constant bindings: `record[const_index[i]] == const_value[i]` for
    /// `i < n_const` (a family pins a record field to a constant).
    pub n_const: u32,
    pub const_index: [u32; C],
    pub const_value: [Field; C],
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
            self.n_const as Field,
            self.const_index[0] as Field,
            self.const_index[1] as Field,
            self.const_value[0],
            self.const_value[1],
        ])
    }
}

/// Asserts `vk` is in its family's tree and the family (its root from its
/// identity and that tree) is in the pipeline tree with root `root` at
/// `position` with `layout_hash`; returns the key's hash (bb checks the
/// folded proof against it).
///
/// The key's hash is `vk.key_hash`, not recomputed here: `std::verify_proof_with_type(key, _, _,
/// key_hash, _)` makes Barretenberg hash `key` in-circuit and constrain the result equal to
/// `key_hash`, so a key that isn't the one hashed can't be folded. In bb 7.0.0-nightly.20260927
/// (aztec-packages 5cb127606d5921cf7995287f7985e00f2c534d54, barretenberg/cpp/src/barretenberg):
/// `dsl/acir_format/recursion_constraint.cpp:195` pairs every recursion constraint's `key_hash`
/// witness with its `key`; `chonk/chonk.cpp:293` verifies each queue entry (OINK, HN and
/// HN_FINAL alike) through Oink; `ultra_honk/oink_verifier.cpp:49-64` hashes the key (the same
/// Poseidon2, rate 3, over the same 151 fields) and asserts `vk_and_hash->hash.assert_equal(vk_hash)`.
/// A bb upgrade must keep that check: `examples/pipelines/combined/tests/key_hash.rs` folds a
/// key under another registered key's hash and expects proving to fail.
pub fn check_vk(root: Field, position: Field, layout_hash: Field, vk: Vk) -> Field {
    let vk_hash = vk.key_hash;
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
    assert(l.n_const <= C, "too many constant bindings");
    for i in 0..C {
        if i < l.n_const {
            assert_eq(
                step[l.const_index[i]],
                l.const_value[i],
                "app output differs from the constant its family pins",
            );
        }
    }
    // The write pointer is a small count (≤ P), so a 32-bit range check makes the cast exact; a bare
    // Field-to-u32 cast would range check 222 bits and compare against the modulus.
    prev[S_WRITE_PTR].assert_max_bit_size::<32>();
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
