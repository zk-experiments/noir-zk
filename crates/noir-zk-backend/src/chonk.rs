//! Chonk, barretenberg's client-side IVC, over the FFI (`barretenberg-rs`,
//! static `libbb-external`: no `bb` process, so it runs on-device).
//!
//! A proof folds a stack of circuits (apps and the kernels that fold them)
//! into one proof verified under the last (hiding) kernel's key. bb's CRS and
//! prover are process-global C++ state and not reentrant, so every call is
//! serialised by one lock, as in psonet's backend.

use std::sync::{Mutex, MutexGuard};

use ark_ff::PrimeField;
use barretenberg_rs::api::BarretenbergApi;
use barretenberg_rs::backends::FfiBackend;
use barretenberg_rs::generated_types::{ChonkProof, CircuitInput, CircuitInputNoVK};

use noir_zk_core::{CircuitKind, Error, Field};

use crate::srs;

static BB_LOCK: Mutex<()> = Mutex::new(());

fn bb() -> Result<(MutexGuard<'static, ()>, BarretenbergApi<FfiBackend>), Error> {
    let guard = BB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let backend = FfiBackend::new().map_err(|e| Error::Proof(format!("bb init: {e}")))?;
    Ok((guard, BarretenbergApi::new(backend)))
}

fn bb_err(what: &str) -> impl Fn(barretenberg_rs::error::BarretenbergError) -> Error + '_ {
    move |e| Error::Proof(format!("bb {what}: {e}"))
}

/// One circuit of the stack, in folding order.
pub struct Step<'a> {
    /// Circuit name (diagnostics only).
    pub name: &'a str,
    /// How Chonk folds it.
    pub kind: CircuitKind,
    /// Uncompressed bytecode (`witness::Program::bytecode`).
    pub bytecode: &'a [u8],
    /// Its Chonk verification key.
    pub vk: &'a [u8],
    /// Its solved witness (`witness::Solved::witness`).
    pub witness: &'a [u8],
}

/// A folded proof as 32-byte field elements, in the order `bb prove --scheme
/// chonk` writes them. The hiding kernel's public outputs are the first ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoldedProof {
    /// The proof's field elements.
    pub fields: Vec<[u8; 32]>,
}

impl FoldedProof {
    fn from_chonk(p: ChonkProof) -> Result<Self, Error> {
        let fields = [
            p.hiding_oink_proof,
            p.merge_proof,
            p.eccvm_proof,
            p.ipa_proof,
            p.joint_proof,
        ]
        .into_iter()
        .flatten()
        .map(|f| {
            <[u8; 32]>::try_from(f.as_slice())
                .map_err(|_| Error::Proof(format!("proof field of {} bytes", f.len())))
        })
        .collect::<Result<_, _>>()?;
        Ok(Self { fields })
    }

    /// The proof as bytes (`bb prove --scheme chonk`'s `proof` file).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.fields.concat()
    }

    /// A proof from bytes; the length must be a whole number of fields.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (fields, rest) = bytes.as_chunks::<32>();
        if !rest.is_empty() {
            return Err(Error::Proof(format!(
                "proof of {} bytes is not whole fields",
                bytes.len()
            )));
        }
        Ok(Self {
            fields: fields.to_vec(),
        })
    }

    /// The first `n` fields: the hiding kernel's public outputs.
    pub fn public_fields(&self, n: usize) -> Result<Vec<Field>, Error> {
        let head = self
            .fields
            .get(..n)
            .ok_or_else(|| Error::Proof(format!("proof shorter than {n} public fields")))?;
        Ok(head
            .iter()
            .map(|b| Field::from_be_bytes_mod_order(b))
            .collect())
    }
}

/// Folds `steps` (apps and kernels in order, ending with the hiding kernel)
/// into one proof.
pub fn prove(steps: &[Step<'_>]) -> Result<FoldedProof, Error> {
    let (_guard, mut api) = bb()?;
    srs::ensure(&mut api)?;
    api.chonk_start(steps.iter().map(|s| s.kind.code()).collect())
        .map_err(bb_err("chonk start"))?;
    for s in steps {
        let circuit = CircuitInput {
            name: s.name.to_string(),
            bytecode: s.bytecode.to_vec(),
            verification_key: s.vk.to_vec(),
        };
        api.chonk_load(circuit, s.kind.code())
            .map_err(|e| Error::Proof(format!("bb chonk load {}: {e}", s.name)))?;
        api.chonk_accumulate(s.witness)
            .map_err(|e| Error::Proof(format!("bb chonk accumulate {}: {e}", s.name)))?;
    }
    let proof = api.chonk_prove().map_err(bb_err("chonk prove"))?.proof;
    FoldedProof::from_chonk(proof)
}

/// Verifies a folded proof against the hiding kernel's key.
pub fn verify(proof: &FoldedProof, hiding_vk: &[u8]) -> Result<bool, Error> {
    let (_guard, mut api) = bb()?;
    srs::ensure(&mut api)?;
    let fields = proof.fields.iter().map(|f| f.to_vec()).collect();
    Ok(api
        .chonk_verify_from_fields(fields, hiding_vk)
        .map_err(bb_err("chonk verify"))?
        .valid)
}

/// A circuit's Chonk verification key: (bb's bytes, its field elements).
pub fn compute_vk(
    name: &str,
    bytecode: &[u8],
    kind: CircuitKind,
) -> Result<(Vec<u8>, Vec<Field>), Error> {
    let (_guard, mut api) = bb()?;
    srs::ensure(&mut api)?;
    let r = api
        .chonk_compute_vk(
            CircuitInputNoVK {
                name: name.to_string(),
                bytecode: bytecode.to_vec(),
            },
            kind.code(),
        )
        .map_err(|e| Error::Proof(format!("bb chonk vk {name}: {e}")))?;
    Ok((
        r.bytes,
        r.fields
            .iter()
            .map(|f| Field::from_be_bytes_mod_order(f))
            .collect(),
    ))
}

/// The field elements of an app or kernel verification key: what a kernel
/// takes as input (and hashes into the key tree).
pub fn vk_fields(vk: &[u8], kind: CircuitKind) -> Result<Vec<Field>, Error> {
    let (_guard, mut api) = bb()?;
    let fields = match kind {
        CircuitKind::App => {
            api.mega_app_vk_as_fields(vk)
                .map_err(bb_err("vk as fields"))?
                .fields
        }
        CircuitKind::Kernel => {
            api.mega_kernel_vk_as_fields(vk)
                .map_err(bb_err("vk as fields"))?
                .fields
        }
        CircuitKind::Hiding => {
            api.mega_z_k_vk_as_fields(vk)
                .map_err(bb_err("vk as fields"))?
                .fields
        }
    };
    Ok(fields
        .iter()
        .map(|f| Field::from_be_bytes_mod_order(f))
        .collect())
}
