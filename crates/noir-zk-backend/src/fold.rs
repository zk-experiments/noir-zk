//! Typed Chonk folding over generated circuit types.
//!
//! ```ignore
//! let (proof, out) = Folding::new(&artifacts)
//!     .app::<Dsc>(&dsc_witness)?
//!     .kernel::<KernelDsc>()?     // KernelDsc::Step must be Dsc::Outputs
//!     .app::<Sod>(&sod_witness)?
//!     .kernel::<KernelSod>()?     // Prev: KernelDsc::Outputs, Step: Sod::Outputs
//!     .hiding::<KernelHiding>()?; // proves; `out: KernelHiding::Outputs`
//! let out = verify::<KernelHiding>(&proof, vk_tree_root)?;
//! ```
//!
//! The chain type-checks at compile time: a kernel only follows the app and
//! kernel whose outputs its `step` and `prev` parameters take. Kernel inputs
//! (outputs, keys, key-tree paths, root) are filled by the builder
//! (`noir_zk_core::fold`'s kernel convention).

use noir_zk_core::fold::VkInput;
use noir_zk_core::{
    from_fields, App, AppDispatch, AppVisitor, Artifacts, Circuit, CircuitId, CircuitKind, Error,
    Field, FromFields, Kernel, KernelInputs,
};

use crate::chonk::{self, FoldedProof, Step};
use crate::witness::{Program, Solved};

struct Solving {
    label: &'static str,
    kind: CircuitKind,
    program: Program,
    vk: Vec<u8>,
    solved: Solved,
}

/// A folding chain in progress: `P` is the last kernel's outputs, `S` the
/// pending app's outputs (`()` when none).
pub struct Folding<'a, A: Artifacts, P, S> {
    artifacts: &'a A,
    circuits: Vec<Solving>,
    prev: P,
    step: S,
    prev_label: Option<&'static str>,
    step_label: Option<&'static str>,
}

impl<'a, A: Artifacts> Folding<'a, A, (), ()> {
    /// An empty chain over `artifacts`.
    pub fn new(artifacts: &'a A) -> Self {
        Self {
            artifacts,
            circuits: vec![],
            prev: (),
            step: (),
            prev_label: None,
            step_label: None,
        }
    }
}

impl<'a, A: Artifacts, P, S> Folding<'a, A, P, S> {
    fn solve<C: Circuit<PublicInputs = ()> + CircuitId>(
        &mut self,
        witness: &C::Witness,
    ) -> Result<C::Outputs, Error> {
        let program = self.program(C::LABEL)?;
        let solved =
            program.solve(program.inputs_from_fields(&C::witness_inputs(witness, &()))?)?;
        let outputs = from_fields(&solved.outputs)?;
        self.circuits.push(Solving {
            label: C::LABEL,
            kind: C::KIND,
            program,
            vk: C::VK_BYTES.to_vec(),
            solved,
        });
        Ok(outputs)
    }

    fn program(&self, label: &str) -> Result<Program, Error> {
        Program::from_parts(
            label,
            &self.artifacts.bytecode_b64(label)?,
            &self.artifacts.abi_json(label)?,
        )
    }

    fn vk_input(&self, label: Option<&str>) -> Result<Option<VkInput>, Error> {
        let Some(label) = label else { return Ok(None) };
        let c = self
            .circuits
            .iter()
            .find(|c| c.label == label)
            .ok_or_else(|| Error::Proof(format!("{label} is not in the chain")))?;
        Ok(Some(VkInput {
            key: chonk::vk_fields(&c.vk, c.kind)?,
            path: self.artifacts.vk_path(label)?,
        }))
    }

    /// Solves kernel `K` over the chain so far; the chain comes back empty
    /// of pending outputs.
    fn kernel_step<K: Kernel<Prev = P, Step = S>>(
        self,
    ) -> Result<(Folding<'a, A, (), ()>, K::Outputs), Error> {
        let Self {
            artifacts,
            circuits,
            prev,
            step,
            prev_label,
            step_label,
        } = self;
        let mut next = Folding {
            artifacts,
            circuits,
            prev: (),
            step: (),
            prev_label: None,
            step_label: None,
        };
        let witness = K::witness(KernelInputs {
            prev,
            step,
            prev_vk: next.vk_input(prev_label)?,
            step_vk: next.vk_input(step_label)?,
            vk_tree_root: artifacts.vk_tree_root(),
        })?;
        let out = next.solve::<K>(&witness)?;
        Ok((next, out))
    }

    /// Folds kernel `K`, which must take this chain's outputs.
    pub fn kernel<K: Kernel<Prev = P, Step = S>>(
        self,
    ) -> Result<Folding<'a, A, K::Outputs, ()>, Error> {
        if K::KIND != CircuitKind::Kernel {
            return Err(Error::Proof(format!("{} is not a kernel", K::LABEL)));
        }
        let (next, out) = self.kernel_step::<K>()?;
        Ok(Folding {
            artifacts: next.artifacts,
            circuits: next.circuits,
            prev: out,
            step: (),
            prev_label: Some(K::LABEL),
            step_label: None,
        })
    }

    /// Folds the hiding kernel `H` and proves the chain. Returns the proof and
    /// its public outputs.
    pub fn hiding<H: Kernel<Prev = P, Step = S>>(self) -> Result<(FoldedProof, H::Outputs), Error> {
        if H::KIND != CircuitKind::Hiding {
            return Err(Error::Proof(format!("{} is not a hiding kernel", H::LABEL)));
        }
        let (done, out) = self.kernel_step::<H>()?;
        let steps: Vec<Step<'_>> = done
            .circuits
            .iter()
            .map(|c| Step {
                name: c.label,
                kind: c.kind,
                bytecode: c.program.bytecode(),
                vk: &c.vk,
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
        Ok((proof, out))
    }
}

impl<'a, A: Artifacts, P> Folding<'a, A, P, ()> {
    /// Folds app `C` with its typed witness.
    pub fn app<C: App>(
        mut self,
        witness: &C::Witness,
    ) -> Result<Folding<'a, A, P, C::Outputs>, Error> {
        let out = self.solve::<C>(witness)?;
        Ok(Folding {
            artifacts: self.artifacts,
            circuits: self.circuits,
            prev: self.prev,
            step: out,
            prev_label: self.prev_label,
            step_label: Some(C::LABEL),
        })
    }

    /// Folds the app labelled `label` (chosen at runtime) with `Prover.toml`
    /// inputs: `R` (a generated `Registry`) dispatches the label to its
    /// circuit type statically, and the inputs decode into that circuit's
    /// `Witness`. Fails if no app returning `O` has the label.
    pub fn app_by_label<R: AppDispatch<O>, O>(
        self,
        label: &str,
        toml: &str,
    ) -> Result<Folding<'a, A, P, O>, Error> {
        R::visit_app(
            label,
            PushApp {
                folding: self,
                toml,
            },
        )
        .unwrap_or_else(|| {
            Err(Error::Artifact(format!(
                "no active app {label} with this output type"
            )))
        })
    }
}

struct PushApp<'a, 't, A: Artifacts, P> {
    folding: Folding<'a, A, P, ()>,
    toml: &'t str,
}

impl<'a, A: Artifacts, P, O> AppVisitor<O> for PushApp<'a, '_, A, P> {
    type Output = Result<Folding<'a, A, P, O>, Error>;
    fn visit<C: App<Outputs = O>>(self) -> Self::Output {
        let program = self.folding.program(C::LABEL)?;
        let witness: C::Witness = from_fields(&program.fields_from_toml(self.toml)?)?;
        self.folding.app::<C>(&witness)
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
