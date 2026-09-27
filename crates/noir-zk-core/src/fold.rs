//! Chonk folding, typed: a proof folds apps and kernels in a chain, and the
//! chain type-checks when each kernel's `Prev` is the previous kernel's
//! `Outputs` and its `Step` the preceding app's `Outputs`. Generated circuit
//! types implement [`App`] or [`Kernel`]; `noir-zk-backend`'s `Folding`
//! builds the chain.
//!
//! Kernel convention: a kernel's `main` parameters are a subset of `prev`
//! (the previous kernel's outputs), `step` (the app's outputs), `prev_vk` and
//! `step_vk` (their Chonk keys as fields plus their key-tree path), and
//! `vk_tree_root`. The backend fills them, so a kernel takes no user inputs.

use crate::artifacts::VkPath;
use crate::codec::FromFields;
use crate::error::Error;
use crate::zk::{Circuit, CircuitId, Field};

/// A step circuit (Chonk kind `app`).
pub trait App: Circuit<PublicInputs = ()> + CircuitId {}

/// A folded circuit's key as a kernel reads it: Chonk key fields and its
/// place in the key tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VkInput {
    /// The Chonk key as field elements.
    pub key: Vec<Field>,
    /// Its path in the key tree.
    pub path: VkPath,
}

impl VkInput {
    /// `key`, then the path's index and siblings: the order of a kernel's
    /// `Vk { key, path: { index, siblings } }` parameter.
    pub fn fields(&self) -> Vec<Field> {
        let mut v = self.key.clone();
        v.push(Field::from(self.path.index));
        v.extend_from_slice(&self.path.siblings);
        v
    }
}

/// What the backend hands a kernel (see the module docs).
pub struct KernelInputs<P, S> {
    /// The previous kernel's outputs (`()` for the first kernel).
    pub prev: P,
    /// The app's outputs (`()` for a kernel without a step).
    pub step: S,
    /// The previous kernel's key.
    pub prev_vk: Option<VkInput>,
    /// The app's key.
    pub step_vk: Option<VkInput>,
    /// The key tree root.
    pub vk_tree_root: Field,
}

impl<P, S> KernelInputs<P, S> {
    /// A `Vk` parameter decoded from `vk` (generated kernels use it).
    pub fn vk<T: FromFields>(vk: &Option<VkInput>, name: &str) -> Result<T, Error> {
        let vk = vk
            .as_ref()
            .ok_or_else(|| Error::Abi(format!("kernel parameter {name}: no such circuit")))?;
        crate::codec::from_fields(&vk.fields())
    }
}

/// A kernel (Chonk kind `kernel`, or `hiding` for the last).
pub trait Kernel: Circuit<PublicInputs = ()> + CircuitId {
    /// Type of its `prev` parameter, `()` if it has none.
    type Prev: FromFields;
    /// Type of its `step` parameter, `()` if it has none.
    type Step: FromFields;
    /// Its witness, from what the backend supplies.
    fn witness(k: KernelInputs<Self::Prev, Self::Step>) -> Result<Self::Witness, Error>;
}

/// Runs code for an app chosen at runtime (by label), statically typed: the
/// generated registry dispatches a label to [`AppVisitor::visit`] with the
/// concrete circuit type. `O` is the apps' output type, so the result links
/// into the kernel that follows.
pub trait AppVisitor<O> {
    /// What the visit returns.
    type Output;
    /// Called with the concrete circuit.
    fn visit<C: App<Outputs = O>>(self) -> Self::Output;
}

/// Static dispatch from an app label to its circuit type, for apps returning
/// `O`. Implemented by the generated `Registry`.
pub trait AppDispatch<O> {
    /// Calls `v.visit::<C>()` for the active app labelled `label`, or `None`
    /// when no app with that output type has the label.
    fn visit_app<V: AppVisitor<O>>(label: &str, v: V) -> Option<V::Output>;
}

/// An app resolved to its circuit: identity, key and inputs.
pub struct AppStep<'i> {
    /// Circuit package name.
    pub label: &'static str,
    /// Its Chonk key.
    pub vk: &'static [u8],
    /// Its inputs.
    pub inputs: StepInputs<'i>,
}

/// An app's inputs.
pub enum StepInputs<'i> {
    /// Witness fields from a typed `Inputs` struct.
    Fields(Vec<Field>),
    /// `Prover.toml` text. The backend encodes it with the ABI, and `check`
    /// decodes that into the circuit's own `Inputs` type and flattens it back.
    Toml {
        /// The text.
        toml: &'i str,
        /// The circuit's decode-and-flatten (monomorphised per circuit).
        check: fn(&[Field]) -> Result<Vec<Field>, Error>,
    },
}

fn check<C: App>(fields: &[Field]) -> Result<Vec<Field>, Error> {
    Ok(C::witness_inputs(
        &crate::codec::from_fields::<C::Witness>(fields)?,
        &(),
    ))
}

/// An app wrapped with the kernel `K` that folds it: its outputs are
/// `K::Step`, so wrapping type-checks the app against the kernel.
pub struct Wrapped<'i, K> {
    /// The app.
    pub app: AppStep<'i>,
    _kernel: std::marker::PhantomData<K>,
}

impl<'i, K: Kernel> Wrapped<'i, K> {
    /// Wraps app `C` with its typed witness.
    pub fn new<C: App<Outputs = K::Step>>(witness: &C::Witness) -> Self {
        Self {
            app: AppStep {
                label: C::LABEL,
                vk: C::VK_BYTES,
                inputs: StepInputs::Fields(C::witness_inputs(witness, &())),
            },
            _kernel: std::marker::PhantomData,
        }
    }

    /// Wraps the app labelled `label` (chosen at runtime) with its
    /// `Prover.toml` inputs. `R` (a generated `Registry`) dispatches the label
    /// statically to a circuit returning `K::Step`; any other label fails.
    pub fn select<R: AppDispatch<K::Step>>(label: &str, toml: &'i str) -> Result<Self, Error> {
        struct Resolve<'i>(&'i str);
        impl<'i, O> AppVisitor<O> for Resolve<'i> {
            type Output = AppStep<'i>;
            fn visit<C: App<Outputs = O>>(self) -> AppStep<'i> {
                AppStep {
                    label: C::LABEL,
                    vk: C::VK_BYTES,
                    inputs: StepInputs::Toml {
                        toml: self.0,
                        check: check::<C>,
                    },
                }
            }
        }
        let app = R::visit_app(label, Resolve(toml))
            .ok_or_else(|| Error::Artifact(format!("{label} is not an app {} folds", K::LABEL)))?;
        Ok(Self {
            app,
            _kernel: std::marker::PhantomData,
        })
    }
}
