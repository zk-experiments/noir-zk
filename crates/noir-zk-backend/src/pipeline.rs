//! Folding a declared pipeline with the generic kernels (`noir-zk-kernels`):
//! `PipelineFold` takes one selected circuit per position, solves it and
//! the kernel after it, and proves the stack under the hiding kernel; the
//! link types of the families are checked at compile time (a position whose
//! `LinkIn` doesn't accept the previous `LinkOut` doesn't compile), the
//! families, bindings and record shapes at run time against the registry.
//!
//! ```ignore
//! let pool = Merged::new(&[&eid, &ours, &Kernels]);
//! let (proof, out) = PipelineFold::new(&pool, &identity_transfer::PIPELINE)?
//!     .app(KernelStepDsc::select(dsc_label, dsc_toml)?)?
//!     .app(KernelStepSod::select(sod_label, sod_toml)?)?
//!     .hiding(&DEPLOYMENT)?;
//! ```
//!
//! Codegen wraps this per declared pipeline (`pipelines::<name>::fold`,
//! `verify`) with typed outputs.

use std::collections::HashMap;
use std::marker::PhantomData;

use ark_ff::{BigInteger, PrimeField, Zero};
use noir_zk_core::codec::{field_from_be_bytes, FieldEncode};
use noir_zk_core::pipeline::{PUBLIC_FIELDS, R, STATE_FIELDS};
use noir_zk_core::tree::{self, Path, Tree, FAMILY_HEIGHT, KERNEL_LEAF, PIPELINE_HEIGHT};
use noir_zk_core::{
    Accepts, Artifacts, ChonkRole, DeploymentEntry, Error, FamilyEntry, FamilyRef, Field, Layout,
    Link, Next, NoLink, PipelineEntry, Selected, StepFamily,
};

use crate::chonk::{self, FoldedProof, Step};
use crate::witness::Program;

/// A family's key tree at run time, from its registry entry.
struct FamilyTree {
    entry: &'static FamilyEntry,
    /// `(label, key hash)` sorted by hash: the tree's leaves.
    members: Vec<(&'static str, Field)>,
    tree: Tree,
}

impl FamilyTree {
    fn build(entry: &'static FamilyEntry) -> Result<Self, Error> {
        let mut members: Vec<(&'static str, Field)> = entry
            .members
            .iter()
            .map(|(l, h)| (*l, field_from_be_bytes(h)))
            .collect();
        members.sort_by_key(|m| m.1);
        let tree = Tree::build(
            &members.iter().map(|m| m.1).collect::<Vec<_>>(),
            FAMILY_HEIGHT,
        );
        let id = tree::family_id(
            entry.id.library,
            entry.version,
            entry.id.layer,
            entry.id.family,
        );
        if tree::hash(&[tree::domain_family(), id, tree.root]) != entry.root_field() {
            return Err(Error::Artifact(format!(
                "family {}: the registry's root differs from its members' tree",
                entry.id
            )));
        }
        Ok(Self {
            entry,
            members,
            tree,
        })
    }

    fn path(&self, label: &str) -> Result<&Path, Error> {
        let i = self
            .members
            .iter()
            .position(|m| m.0 == label)
            .ok_or_else(|| {
                Error::Artifact(format!("{label} is not in family {}", self.entry.id))
            })?;
        Ok(self.tree.path(i))
    }
}

struct Solving {
    label: &'static str,
    kind: ChonkRole,
    program: Program,
    vk: Vec<u8>,
    witness: Vec<u8>,
    /// Its inputs in witness-index order (for `NOIR_ZK_BENCH_DUMP`).
    inputs: Vec<Field>,
}

/// A pipeline fold in progress; `L` is the link the next position must accept.
pub struct PipelineFold<'a, L> {
    artifacts: &'a dyn Artifacts,
    pipeline: &'static PipelineEntry,
    tree: Tree,
    kernels: FamilyTree,
    families: HashMap<FamilyRef, FamilyTree>,
    circuits: Vec<Solving>,
    state: Vec<Field>,
    prev: &'static str,
    _l: PhantomData<L>,
}

/// Verifies `proof` under `hiding_vk` and checks it is `pipeline` of the
/// deployment with `deployment_root`: returns the public fields
/// (`deployment_root`, `pipeline_root`, `length`, the slots).
pub fn verify(
    proof: &FoldedProof,
    pipeline: &PipelineEntry,
    deployment_root: Field,
    hiding_vk: &[u8],
) -> Result<Vec<Field>, Error> {
    let fields = proof.public_fields(PUBLIC_FIELDS)?;
    if fields[0] != deployment_root {
        return Err(Error::Proof("the proof is of another deployment".into()));
    }
    if fields[1] != pipeline.root_field() {
        return Err(Error::Proof(format!(
            "the proof is of another pipeline than {}",
            pipeline.name
        )));
    }
    if fields[2] != Field::from(pipeline.len() as u64) {
        return Err(Error::Proof(format!(
            "the proof folds {} apps, {} has {}",
            fields[2],
            pipeline.name,
            pipeline.len()
        )));
    }
    if fields[3 + pipeline.slots.len()..]
        .iter()
        .any(|f| !f.is_zero())
    {
        return Err(Error::Proof("unused slots are not zero".into()));
    }
    if !chonk::verify(proof, hiding_vk)? {
        return Err(Error::Proof("the proof does not verify".into()));
    }
    Ok(fields)
}

/// The hiding kernel's key: what every pipeline's proofs verify under.
pub fn hiding_vk() -> &'static [u8] {
    noir_zk_kernels::kernel("kernel_hiding")
        .map(|k| k.vk)
        .unwrap_or_default()
}

fn path_fields(p: &Path, out: &mut Vec<Field>) {
    out.push(Field::from(p.index));
    out.extend_from_slice(&p.siblings);
}

impl<'a> PipelineFold<'a, NoLink> {
    /// Starts folding `pipeline` over `artifacts` (the merged pool of every
    /// registry the pipeline draws from, plus the kernels).
    pub fn new(
        artifacts: &'a dyn Artifacts,
        pipeline: &'static PipelineEntry,
    ) -> Result<Self, Error> {
        let mut families = HashMap::new();
        for pos in &pipeline.positions {
            if families.contains_key(&pos.family) {
                continue;
            }
            let entry = artifacts.family(&pos.family).ok_or_else(|| {
                Error::Artifact(format!("no family {} in the artifacts", pos.family))
            })?;
            families.insert(pos.family, FamilyTree::build(entry)?);
        }
        let kernels = FamilyTree::build(&noir_zk_kernels::FAMILY)?;
        let leaves = PipelineEntry::leaves(
            &|f| families.get(f).map(|t| t.entry.root_field()),
            &pipeline.positions,
            kernels.entry.root_field(),
        )?;
        let tree = Tree::build(&leaves, PIPELINE_HEIGHT);
        if tree.root != pipeline.root_field() {
            return Err(Error::Artifact(format!(
                "pipeline {}: the registry's root differs from its positions' tree",
                pipeline.name
            )));
        }
        Ok(Self {
            artifacts,
            pipeline,
            tree,
            kernels,
            families,
            circuits: vec![],
            state: vec![],
            prev: "",
            _l: PhantomData,
        })
    }
}

impl<'a, L: Link> PipelineFold<'a, L> {
    fn position(&self) -> usize {
        self.circuits.len() / 2
    }

    fn program(&self, label: &str) -> Result<Program, Error> {
        Program::from_parts(
            label,
            &self.artifacts.bytecode_b64(label)?,
            &self.artifacts.abi_json(label)?,
        )
    }

    /// `Vk { key, key_hash, family, family_id, pipeline }` of `label` in `family` at pipeline leaf
    /// `leaf` (`key_hash` is `tree::hash(key)`, which bb constrains against the key).
    fn vk_fields(
        &self,
        family: &FamilyTree,
        label: &str,
        leaf: usize,
        kind: ChonkRole,
    ) -> Result<Vec<Field>, Error> {
        let vk = self.artifacts.vk(label)?;
        let mut v = chonk::vk_fields(&vk, kind)?;
        v.push(tree::hash(&v));
        path_fields(family.path(label)?, &mut v);
        let e = family.entry;
        v.push(tree::family_id(
            e.id.library,
            e.version,
            e.id.layer,
            e.id.family,
        ));
        path_fields(self.tree.path(leaf), &mut v);
        Ok(v)
    }

    fn push(
        &mut self,
        label: &'static str,
        kind: ChonkRole,
        inputs: &[Field],
    ) -> Result<Vec<Field>, Error> {
        let program = self.program(label)?;
        let solved = program
            .solve(program.inputs_from_fields(inputs)?)
            .map_err(|e| match e {
                Error::Unsatisfied(m) => Error::Unsatisfied(format!("{label}: {m}")),
                e => e,
            })?;
        self.circuits.push(Solving {
            label,
            kind,
            program,
            vk: self.artifacts.vk(label)?,
            witness: solved.witness,
            inputs: inputs.to_vec(),
        });
        Ok(solved.outputs)
    }

    fn prev_vk(&self) -> Result<Vec<Field>, Error> {
        self.vk_fields(&self.kernels, self.prev, KERNEL_LEAF, ChonkRole::Kernel)
    }

    /// Folds `step` at the next position: the circuit, then `kernel_init`
    /// (position 0) or `kernel_step`. Compiles only if `K::LinkIn` accepts
    /// the link left by the previous position.
    pub fn app<K: StepFamily>(
        mut self,
        step: Selected<K>,
    ) -> Result<PipelineFold<'a, <K::LinkOut as Next<L>>::Out>, Error>
    where
        K::LinkIn: Accepts<L>,
        K::LinkOut: Next<L>,
    {
        let p = self.position();
        let pos = self.pipeline.positions.get(p).ok_or_else(|| {
            Error::Proof(format!(
                "{} has {} positions; no room for {}",
                self.pipeline.name,
                self.pipeline.len(),
                step.label
            ))
        })?;
        let family = K::family();
        if family.id != pos.family {
            return Err(Error::Proof(format!(
                "position {p} of {} is {}, not {}",
                self.pipeline.name, pos.family, family.id
            )));
        }
        let label = step.label;
        // The app: `Prover.toml` encoded by its ABI.
        let program = self.program(label)?;
        let app_inputs = program.fields_from_toml(&step.toml)?;
        let solved = program.solve(program.inputs_from_fields(&app_inputs)?)?;
        if solved.outputs.len() != family.record_fields || family.record_fields > R {
            return Err(Error::Abi(format!(
                "{label} returns {} fields, family {} declares {}",
                solved.outputs.len(),
                family.id,
                family.record_fields
            )));
        }
        // Typed: the record decodes as the family's record type.
        let record: K::Record = noir_zk_core::from_fields(&solved.outputs)?;
        let mut fields = vec![];
        record.encode(&mut fields)?;
        fields.resize(R, Field::zero());
        let entry = self
            .artifacts
            .entry(label)
            .ok_or_else(|| Error::Artifact(format!("no entry {label}")))?;
        self.circuits.push(Solving {
            label: entry.label,
            kind: ChonkRole::App,
            program,
            vk: self.artifacts.vk(label)?,
            witness: solved.witness,
            inputs: app_inputs,
        });
        // The kernel after it.
        let tree = self
            .families
            .get(&pos.family)
            .ok_or_else(|| Error::Artifact(format!("no family {}", pos.family)))?;
        let step_vk = self.vk_fields(tree, label, p, ChonkRole::App)?;
        let layout: Layout = pos.layout.clone();
        let mut inputs = vec![];
        let kernel = if p == 0 {
            inputs.extend(fields);
            inputs.extend(step_vk);
            inputs.extend(layout.fields());
            inputs.push(self.tree.root);
            "kernel_init"
        } else {
            inputs.extend(self.state.clone());
            inputs.extend(fields);
            inputs.extend(self.prev_vk()?);
            inputs.extend(step_vk);
            inputs.extend(layout.fields());
            "kernel_step"
        };
        let state = self.push(kernel, ChonkRole::Kernel, &inputs)?;
        debug_assert_eq!(state.len(), STATE_FIELDS);
        self.state = state;
        self.prev = kernel;
        Ok(PipelineFold {
            artifacts: self.artifacts,
            pipeline: self.pipeline,
            tree: self.tree,
            kernels: self.kernels,
            families: self.families,
            circuits: self.circuits,
            state: self.state,
            prev: self.prev,
            _l: PhantomData,
        })
    }

    /// Folds the hiding kernel (after `kernel_tail` for a one-app pipeline,
    /// Chonk's minimum being four circuits) and proves. Returns the proof and
    /// its public fields: `deployment_root`, `pipeline_root`, `length`, the slots.
    pub fn hiding(
        mut self,
        deployment: &DeploymentEntry,
    ) -> Result<(FoldedProof, Vec<Field>), Error> {
        let p = self.position();
        if p != self.pipeline.len() {
            return Err(Error::Proof(format!(
                "{} apps folded, {} has {}",
                p,
                self.pipeline.name,
                self.pipeline.len()
            )));
        }
        if p == 1 {
            let mut inputs = self.state.clone();
            inputs.extend(self.prev_vk()?);
            self.state = self.push("kernel_tail", ChonkRole::Kernel, &inputs)?;
            self.prev = "kernel_tail";
        }
        let index = deployment
            .roots
            .iter()
            .position(|r| *r == self.pipeline.root)
            .ok_or_else(|| {
                Error::Proof(format!(
                    "{} is not a pipeline of this deployment",
                    self.pipeline.name
                ))
            })?;
        let mut inputs = self.state.clone();
        inputs.extend(self.prev_vk()?);
        path_fields(deployment.tree().path(index), &mut inputs);
        let public = self.push("kernel_hiding", ChonkRole::Hiding, &inputs)?;
        let steps: Vec<Step<'_>> = self
            .circuits
            .iter()
            .map(|c| Step {
                name: c.label,
                kind: c.kind,
                bytecode: c.program.bytecode(),
                vk: &c.vk,
                witness: &c.witness,
            })
            .collect();
        let proof = chonk::prove(&steps)?;
        if let Some(dir) = std::env::var_os("NOIR_ZK_BENCH_DUMP") {
            self.dump(&std::path::Path::new(&dir).join(self.pipeline.name), &proof, &public)?;
        }
        if proof.public_fields(PUBLIC_FIELDS)? != public {
            return Err(Error::Proof(
                "the proof's public fields differ from the hiding kernel's outputs".into(),
            ));
        }
        Ok((proof, public))
    }
}

impl<L> PipelineFold<'_, L> {
    /// Writes the fold's circuits, inputs and proof for an external (WASM)
    /// prover to replay: `fold.json`, `proof.bin`, `public.json`.
    fn dump(&self, dir: &std::path::Path, proof: &FoldedProof, public: &[Field]) -> Result<(), Error> {
        use base64::Engine;
        let io = |e: std::io::Error| Error::Proof(format!("bench dump {}: {e}", dir.display()));
        let steps: Vec<_> = self
            .circuits
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.label,
                    "kind": c.kind.code(),
                    "bytecode": base64::engine::general_purpose::STANDARD.encode(c.program.bytecode()),
                    "vk": hex::encode(&c.vk),
                    "inputs": c.inputs.iter().map(hex).collect::<Vec<_>>(),
                })
            })
            .collect();
        std::fs::create_dir_all(dir).map_err(io)?;
        std::fs::write(dir.join("fold.json"), serde_json::Value::from(steps).to_string()).map_err(io)?;
        std::fs::write(dir.join("proof.bin"), proof.to_bytes()).map_err(io)?;
        let public: Vec<_> = public.iter().map(hex).collect();
        std::fs::write(dir.join("public.json"), serde_json::to_string(&public).unwrap_or_default())
            .map_err(io)
    }
}

/// A field as `0x` hex (for diagnostics).
pub fn hex(f: &Field) -> String {
    format!("0x{}", hex::encode(f.into_bigint().to_bytes_be()))
}
