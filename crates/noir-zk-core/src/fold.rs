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
    type Prev;
    /// Type of its `step` parameter, `()` if it has none.
    type Step;
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
