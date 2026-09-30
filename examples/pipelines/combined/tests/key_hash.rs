//! The kernels take each verification key's hash as a witness instead of hashing the key in
//! Noir (`noir-zk-kernels/noir/lib/src/lib.nr`, `check_vk`): Barretenberg hashes the key in-circuit
//! and constrains the result equal to the supplied hash. This test holds bb to that: it folds
//! `seed_count` by hand, as `PipelineFold` does, once honestly (proves and verifies) and once with
//! `kernel_step`'s previous kernel presented as `kernel_init`'s real key under `kernel_tail`'s
//! registered hash and family path. The Noir checks accept that key hash (it is in the kernels'
//! family and the pipeline tree), so only bb's constraint stops it: proving must fail. A bb
//! upgrade that dropped the check would make this test fail. Proves, so it runs only with
//! `NOIR_ZK_PROVE` set (bb's SRS in `~/.bb-crs` or `$BB_CRS_PATH`).

use combined::circuits::pipelines::seed_count;
use combined::circuits::{DEPLOYMENT, FAMILIES};
use noir_zk_backend::chonk::{self, Step};
use noir_zk_backend::kernels::FAMILY as KERNELS;
use noir_zk_backend::witness::Program;
use noir_zk_core::codec::field_from_be_bytes;
use noir_zk_core::pipeline::R;
use noir_zk_core::tree::{self, Path, Tree, FAMILY_HEIGHT, KERNEL_LEAF, PIPELINE_HEIGHT};
use noir_zk_core::{Artifacts, ChonkRole, FamilyEntry, Field};

/// A family's tree: its members' key hashes, sorted, as `PipelineFold` builds it.
struct Family {
    members: Vec<(&'static str, Field)>,
    tree: Tree,
    id: Field,
}

impl Family {
    fn new(e: &FamilyEntry) -> Self {
        let mut members: Vec<_> = e
            .members
            .iter()
            .map(|(l, h)| (*l, field_from_be_bytes(h)))
            .collect();
        members.sort_by_key(|m| m.1);
        let hashes: Vec<Field> = members.iter().map(|m| m.1).collect();
        Self {
            tree: Tree::build(&hashes, FAMILY_HEIGHT),
            id: tree::family_id(e.id.library, e.version, e.id.layer, e.id.family),
            members,
        }
    }

    fn path(&self, label: &str) -> &Path {
        self.tree
            .path(self.members.iter().position(|m| m.0 == label).unwrap())
    }

    fn hash(&self, label: &str) -> Field {
        self.members.iter().find(|m| m.0 == label).unwrap().1
    }
}

fn push_path(p: &Path, v: &mut Vec<Field>) {
    v.push(Field::from(p.index));
    v.extend_from_slice(&p.siblings);
}

/// Folds `seed_count` (seed, then counter) and proves; with `forge`, `kernel_step` gets
/// `kernel_init`'s key under `kernel_tail`'s hash and path.
fn fold(forge: bool) -> Result<bool, noir_zk_core::Error> {
    let (a, b) = (lib_a::artifacts(), lib_b::artifacts());
    let pool = combined::pool(&a, &b);
    let p = &*seed_count::PIPELINE;
    let kernels = Family::new(&KERNELS);
    let family = |i: usize| {
        Family::new(
            FAMILIES
                .iter()
                .find(|f| f.id == p.positions[i].family)
                .unwrap(),
        )
    };
    let leaves = noir_zk_core::PipelineEntry::leaves(
        &|id| {
            FAMILIES
                .iter()
                .find(|f| f.id == *id)
                .map(|f| f.root_field())
        },
        &p.positions,
        KERNELS.root_field(),
    )?;
    let pipeline = Tree::build(&leaves, PIPELINE_HEIGHT);
    // `Vk { key, key_hash, family, family_id, pipeline }`.
    let vk = |label: &str, key_of: &str, f: &Family, leaf: usize, role| {
        let mut v = chonk::vk_fields(&pool.vk(key_of).unwrap(), role).unwrap();
        v.push(f.hash(label));
        push_path(f.path(label), &mut v);
        v.push(f.id);
        push_path(pipeline.path(leaf), &mut v);
        v
    };
    let program = |label: &str| {
        Program::from_parts(
            label,
            &pool.bytecode_b64(label).unwrap(),
            &pool.abi_json(label).unwrap(),
        )
        .unwrap()
    };
    let mut circuits: Vec<(&str, ChonkRole, Program, Vec<u8>)> = vec![];
    let mut run = |label: &'static str, role, inputs: Result<Vec<Field>, &str>| {
        let prog = program(label);
        let solved = match inputs {
            Ok(fields) => prog.solve(prog.inputs_from_fields(&fields).unwrap()),
            Err(toml) => prog.solve(prog.inputs_from_toml(toml).unwrap()),
        }
        .unwrap_or_else(|e| panic!("{label}: {e}"));
        circuits.push((label, role, prog, solved.witness));
        solved.outputs
    };
    let record = |mut r: Vec<Field>| {
        r.resize(R, Field::from(0u64));
        r
    };
    // Position 0: the seed app, then kernel_init.
    let seed = record(run("seed", ChonkRole::App, Err("s = \"7\"")));
    let mut i = seed;
    i.extend(vk("seed", "seed", &family(0), 0, ChonkRole::App));
    i.extend(p.positions[0].layout.fields());
    i.push(pipeline.root);
    let state = run("kernel_init", ChonkRole::Kernel, Ok(i));
    // Position 1: the counter app, then kernel_step folding kernel_init.
    let counter = record(run(
        "counter_small",
        ChonkRole::App,
        Err("s = \"7\"\nn = \"5\""),
    ));
    let mut i = state;
    i.extend(counter);
    let prev = if forge { "kernel_tail" } else { "kernel_init" };
    i.extend(vk(
        prev,
        "kernel_init",
        &kernels,
        KERNEL_LEAF,
        ChonkRole::Kernel,
    ));
    i.extend(vk(
        "counter_small",
        "counter_small",
        &family(1),
        1,
        ChonkRole::App,
    ));
    i.extend(p.positions[1].layout.fields());
    let state = run("kernel_step", ChonkRole::Kernel, Ok(i));
    // The hiding kernel.
    let mut i = state;
    i.extend(vk(
        "kernel_step",
        "kernel_step",
        &kernels,
        KERNEL_LEAF,
        ChonkRole::Kernel,
    ));
    let index = DEPLOYMENT.roots.iter().position(|r| *r == p.root).unwrap();
    push_path(DEPLOYMENT.tree().path(index), &mut i);
    run("kernel_hiding", ChonkRole::Hiding, Ok(i));
    let vks: Vec<Vec<u8>> = circuits.iter().map(|c| pool.vk(c.0).unwrap()).collect();
    let steps: Vec<Step<'_>> = circuits
        .iter()
        .zip(&vks)
        .map(|((name, kind, prog, witness), vk)| Step {
            name,
            kind: *kind,
            bytecode: prog.bytecode(),
            vk,
            witness,
        })
        .collect();
    let proof = chonk::prove(&steps)?;
    chonk::verify(&proof, &pool.vk("kernel_hiding").unwrap())
}

#[test]
fn a_key_under_another_keys_hash_is_refused() {
    if std::env::var_os("NOIR_ZK_PROVE").is_none() {
        return;
    }
    // The hand-built fold is right: honestly, it proves and verifies.
    assert!(fold(false).expect("the honest fold proves"));
    // kernel_init's key under kernel_tail's hash passes the Noir checks, not bb's.
    assert!(
        !matches!(fold(true), Ok(true)),
        "a kernel key folded under another registered key's hash was accepted"
    );
}
