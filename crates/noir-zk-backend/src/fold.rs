//! Typed Chonk folding over generated circuit types.
//!
//! ```ignore
//! let (proof, out) = Folding::new(&artifacts)
//!     .app(KernelDsc::wrap::<Dsc>(&dsc_inputs))?       // typed app, folded by KernelDsc
//!     .app(KernelSod::select(sod_label, &sod_toml)?)?  // app chosen at runtime
//!     .kernel::<KernelTail>()?                         // a kernel without an app
//!     .hiding::<KernelHiding>()?;                      // proves; out: KernelHiding::Outputs
//! let out = verify::<KernelHiding>(&proof, vk_tree_root)?;
//! ```
//!
//! The chain type-checks at compile time: an app is wrapped with the kernel
//! that folds it (its outputs must be the kernel's `Step`), and each kernel's
//! `Prev` must be the previous kernel's outputs. Kernel inputs (outputs, keys,
//! key-tree paths, root) are filled by the builder (`noir_zk_core::fold`'s
//! kernel convention).

use noir_zk_core::fold::VkInput;
use noir_zk_core::{
    from_fields, AppStep, Artifacts, ChonkRole, Circuit, CircuitId, Error, Field, FromFields,
    Kernel, KernelInputs, ProofSystem, StepInputs, Wrapped,
};

use crate::chonk::{self, FoldedProof, Step};
use crate::witness::{Program, Solved};

struct Solving {
    label: &'static str,
    kind: ChonkRole,
    program: Program,
    vk: &'static [u8],
    solved: Solved,
}

/// A folding chain in progress; `P` is the last kernel's outputs (`()`
/// before the first kernel).
pub struct Folding<'a, A: Artifacts, P> {
    artifacts: &'a A,
    circuits: Vec<Solving>,
    prev: P,
    prev_label: Option<&'static str>,
}

impl<'a, A: Artifacts> Folding<'a, A, ()> {
    /// An empty chain over `artifacts`.
    pub fn new(artifacts: &'a A) -> Self {
        Self {
            artifacts,
            circuits: vec![],
            prev: (),
            prev_label: None,
        }
    }
}

impl<'a, A: Artifacts, P> Folding<'a, A, P> {
    fn program(&self, label: &str) -> Result<Program, Error> {
        Program::from_parts(
            label,
            &self.artifacts.bytecode_b64(label)?,
            &self.artifacts.abi_json(label)?,
        )
    }

    /// Solves one circuit and appends it; returns its raw outputs.
    fn push(
        &mut self,
        label: &'static str,
        kind: ChonkRole,
        vk: &'static [u8],
        program: Program,
        fields: &[Field],
    ) -> Result<Vec<Field>, Error> {
        let solved = program.solve(program.inputs_from_fields(fields)?)?;
        let outputs = solved.outputs.clone();
        self.circuits.push(Solving {
            label,
            kind,
            program,
            vk,
            solved,
        });
        Ok(outputs)
    }

    fn vk_input(&self, label: Option<&str>) -> Result<Option<VkInput>, Error> {
        let Some(label) = label else { return Ok(None) };
        let c = self
            .circuits
            .iter()
            .find(|c| c.label == label)
            .ok_or_else(|| Error::Proof(format!("{label} is not in the chain")))?;
        Ok(Some(VkInput {
            key: chonk::vk_fields(c.vk, c.kind)?,
            path: self.artifacts.vk_path(label)?,
        }))
    }

    fn fold_app(&mut self, app: AppStep<'_>) -> Result<Vec<Field>, Error> {
        let program = self.program(app.label)?;
        let fields = match app.inputs {
            StepInputs::Fields(f) => f,
            StepInputs::Toml { toml, check } => check(&program.fields_from_toml(toml)?)?,
        };
        self.push(app.label, ChonkRole::App, app.vk, program, &fields)
    }

    /// Solves kernel `K` over the last kernel's outputs and `step`.
    fn fold_kernel<K: Kernel<Prev = P>>(
        self,
        step: K::Step,
        step_label: Option<&'static str>,
    ) -> Result<Folding<'a, A, K::Outputs>, Error> {
        let Self {
            artifacts,
            circuits,
            prev,
            prev_label,
        } = self;
        let mut next = Folding {
            artifacts,
            circuits,
            prev: (),
            prev_label: None,
        };
        let witness = K::witness(KernelInputs {
            prev,
            step,
            prev_vk: next.vk_input(prev_label)?,
            step_vk: next.vk_input(step_label)?,
            vk_tree_root: artifacts.vk_tree_root(),
        })?;
        let program = next.program(K::LABEL)?;
        let ProofSystem::Chonk(role) = K::SYSTEM else {
            return Err(Error::Proof(format!("{} is not a Chonk circuit", K::LABEL)));
        };
        let out = next.push(
            K::LABEL,
            role,
            K::VK_BYTES,
            program,
            &K::witness_inputs(&witness, &()),
        )?;
        Ok(Folding {
            artifacts: next.artifacts,
            circuits: next.circuits,
            prev: from_fields(&out)?,
            prev_label: Some(K::LABEL),
        })
    }

    /// Folds an app and the kernel it is wrapped with.
    pub fn app<K: Kernel<Prev = P>>(
        mut self,
        wrapped: Wrapped<'_, K>,
    ) -> Result<Folding<'a, A, K::Outputs>, Error> {
        if K::SYSTEM != ProofSystem::Chonk(ChonkRole::Kernel) {
            return Err(Error::Proof(format!("{} is not a kernel", K::LABEL)));
        }
        let label = wrapped.app.label;
        let step = from_fields(&self.fold_app(wrapped.app)?)?;
        self.fold_kernel::<K>(step, Some(label))
    }

    /// Folds a kernel that takes no app (only the previous kernel).
    pub fn kernel<K: Kernel<Prev = P, Step = ()>>(
        self,
    ) -> Result<Folding<'a, A, K::Outputs>, Error> {
        if K::SYSTEM != ProofSystem::Chonk(ChonkRole::Kernel) {
            return Err(Error::Proof(format!("{} is not a kernel", K::LABEL)));
        }
        self.fold_kernel::<K>((), None)
    }

    /// Folds the hiding kernel `H` and proves the chain. Returns the proof and
    /// its public outputs.
    pub fn hiding<H: Kernel<Prev = P, Step = ()>>(
        self,
    ) -> Result<(FoldedProof, H::Outputs), Error> {
        if H::SYSTEM != ProofSystem::Chonk(ChonkRole::Hiding) {
            return Err(Error::Proof(format!("{} is not a hiding kernel", H::LABEL)));
        }
        let done = self.fold_kernel::<H>((), None)?;
        let steps: Vec<Step<'_>> = done
            .circuits
            .iter()
            .map(|c| Step {
                name: c.label,
                kind: c.kind,
                bytecode: c.program.bytecode(),
                vk: c.vk,
                witness: &c.solved.witness,
            })
            .collect();
        let proof = chonk::prove(&steps)?;
        let returned = done.circuits.last().map(|c| &c.solved.outputs);
        if Some(&proof.public_fields(<H::Outputs as FromFields>::FIELDS)?) != returned {
            return Err(Error::Proof(
                "proof's public fields differ from the hiding kernel's outputs".into(),
            ));
        }
        Ok((proof, done.prev))
    }
}

/// Verifies a proof folded under hiding kernel `H` (its key is pinned in
/// `H::VK_BYTES`) and key tree `vk_tree_root`, and returns its public outputs.
pub fn verify<H: Circuit + CircuitId>(
    proof: &FoldedProof,
    vk_tree_root: Field,
) -> Result<H::Outputs, Error> {
    let fields = proof.public_fields(<H::Outputs as FromFields>::FIELDS)?;
    let at = H::VK_TREE_ROOT_OUTPUT
        .ok_or_else(|| Error::Proof(format!("{} returns no vk_tree_root", H::LABEL)))?;
    if fields.get(at) != Some(&vk_tree_root) {
        return Err(Error::Proof(
            "proof uses another verification key tree".into(),
        ));
    }
    if !chonk::verify(proof, H::VK_BYTES)? {
        return Err(Error::Proof("proof does not verify".into()));
    }
    from_fields(&fields)
}
