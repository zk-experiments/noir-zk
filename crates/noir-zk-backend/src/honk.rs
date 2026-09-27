//! Standalone UltraHonk proofs over the FFI, typed by generated `Honk`
//! circuits:
//!
//! ```ignore
//! let proof = UltraHonk::new(&artifacts).prove::<Square>(&square::Inputs { x }, &square::PublicInputs { y })?;
//! assert!(HonkVerifier.verify::<Square>(&square::PublicInputs { y }, &proof)?);
//! let out: square::Outputs = outputs::<Square>(&proof)?;
//! ```
//!
//! The proof's public inputs are the circuit's `pub` parameters, then its
//! `pub` return values. Proofs are zero-knowledge; the transcript hash is the
//! circuit's [`Oracle`], frozen with it.

use ark_ff::{BigInteger, PrimeField};
use barretenberg_rs::generated_types::{CircuitInput, CircuitInputNoVK, ProofSystemSettings};

use noir_zk_core::{
    from_fields, Artifacts, CircuitId, Error, Field, FromFields, Honk, Oracle, ProofGenerator,
    ProofSystem, ProofVerifier,
};

use crate::bb::{bb, bb_err};
use crate::srs;
use crate::witness::Program;

fn settings(oracle: Oracle) -> ProofSystemSettings {
    ProofSystemSettings {
        ipa_accumulation: false,
        oracle_hash_type: oracle.name().to_string(),
        disable_zk: false,
        optimized_solidity_verifier: false,
    }
}

fn to_field(b: &[u8]) -> Field {
    Field::from_be_bytes_mod_order(b)
}

fn to_bytes(f: &Field) -> Vec<u8> {
    f.into_bigint().to_bytes_be()
}

fn oracle_of<C: CircuitId>() -> Result<Oracle, Error> {
    match C::SYSTEM {
        ProofSystem::UltraHonk(o) => Ok(o),
        ProofSystem::Chonk(_) => Err(Error::Proof(format!("{} is a Chonk circuit", C::LABEL))),
    }
}

/// An UltraHonk proof and the public inputs it proves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HonkProof {
    /// `pub` parameters, then `pub` return values.
    pub public_inputs: Vec<Field>,
    /// The proof's field elements (`bb prove`'s `proof` file, 32 bytes each).
    pub proof: Vec<[u8; 32]>,
}

/// Proves a solved circuit.
pub fn prove(
    name: &str,
    bytecode: &[u8],
    vk: &[u8],
    witness: &[u8],
    oracle: Oracle,
) -> Result<HonkProof, Error> {
    let (_guard, mut api) = bb()?;
    srs::ensure(&mut api)?;
    let r = api
        .circuit_prove(
            CircuitInput {
                name: name.to_string(),
                bytecode: bytecode.to_vec(),
                verification_key: vk.to_vec(),
            },
            witness,
            settings(oracle),
        )
        .map_err(|e| Error::Proof(format!("bb prove {name}: {e}")))?;
    Ok(HonkProof {
        public_inputs: r.public_inputs.iter().map(|f| to_field(f)).collect(),
        proof: r
            .proof
            .iter()
            .map(|f| {
                <[u8; 32]>::try_from(f.as_slice())
                    .map_err(|_| Error::Proof(format!("proof field of {} bytes", f.len())))
            })
            .collect::<Result<_, _>>()?,
    })
}

/// Verifies `proof` against a verification key.
pub fn verify(vk: &[u8], proof: &HonkProof, oracle: Oracle) -> Result<bool, Error> {
    let (_guard, mut api) = bb()?;
    srs::ensure(&mut api)?;
    Ok(api
        .circuit_verify(
            vk,
            proof.public_inputs.iter().map(to_bytes).collect(),
            proof.proof.iter().map(|f| f.to_vec()).collect(),
            settings(oracle),
        )
        .map_err(bb_err("verify"))?
        .verified)
}

/// A circuit's UltraHonk verification key: (bb's bytes, its field elements,
/// which a recursive verifier takes).
pub fn compute_vk(
    name: &str,
    bytecode: &[u8],
    oracle: Oracle,
) -> Result<(Vec<u8>, Vec<Field>), Error> {
    let (_guard, mut api) = bb()?;
    srs::ensure(&mut api)?;
    let r = api
        .circuit_compute_vk(
            CircuitInputNoVK {
                name: name.to_string(),
                bytecode: bytecode.to_vec(),
            },
            settings(oracle),
        )
        .map_err(|e| Error::Proof(format!("bb vk {name}: {e}")))?;
    Ok((r.bytes, r.fields.iter().map(|f| to_field(f)).collect()))
}

/// Proves generated `Honk` circuits, bytecode from `A`.
pub struct UltraHonk<'a, A: Artifacts> {
    artifacts: &'a A,
}

impl<'a, A: Artifacts> UltraHonk<'a, A> {
    /// A prover over `artifacts`.
    pub fn new(artifacts: &'a A) -> Self {
        Self { artifacts }
    }

    /// Proves `public` for circuit `C` with `witness`.
    pub fn prove<C: Honk>(
        &self,
        witness: &C::Witness,
        public: &C::PublicInputs,
    ) -> Result<HonkProof, Error> {
        ProofGenerator::<C>::generate(self, witness, public)
    }
}

impl<C: Honk, A: Artifacts> ProofGenerator<C> for UltraHonk<'_, A> {
    type Proof = HonkProof;
    fn generate(&self, witness: &C::Witness, public: &C::PublicInputs) -> Result<HonkProof, Error> {
        let oracle = oracle_of::<C>()?;
        let program = Program::from_parts(
            C::LABEL,
            &self.artifacts.bytecode_b64(C::LABEL)?,
            &self.artifacts.abi_json(C::LABEL)?,
        )?;
        let solved =
            program.solve(program.inputs_from_fields(&C::witness_inputs(witness, public))?)?;
        prove(
            C::LABEL,
            program.bytecode(),
            C::VK_BYTES,
            &solved.witness,
            oracle,
        )
    }
}

/// Verifies generated `Honk` circuits against their embedded keys; needs no
/// artifacts.
pub struct HonkVerifier;

impl HonkVerifier {
    /// Whether `proof` proves `public` for circuit `C`.
    pub fn verify<C: Honk>(
        &self,
        public: &C::PublicInputs,
        proof: &HonkProof,
    ) -> Result<bool, Error> {
        ProofVerifier::<C>::verify(self, public, proof)
    }
}

impl<C: Honk> ProofVerifier<C> for HonkVerifier {
    type Proof = HonkProof;
    fn verify(&self, public: &C::PublicInputs, proof: &HonkProof) -> Result<bool, Error> {
        let expected = C::public_inputs(public);
        let n = expected.len() + <C::Outputs as FromFields>::FIELDS;
        if proof.public_inputs.len() != n || !proof.public_inputs.starts_with(&expected) {
            return Ok(false);
        }
        verify(C::VK_BYTES, proof, oracle_of::<C>()?)
    }
}

/// The typed return values a proof of `C` carries (after its `pub`
/// parameters). Check the proof first.
pub fn outputs<C: Honk>(proof: &HonkProof) -> Result<C::Outputs, Error> {
    let n = <C::Outputs as FromFields>::FIELDS;
    let tail = proof
        .public_inputs
        .len()
        .checked_sub(n)
        .ok_or_else(|| Error::Proof("fewer public inputs than outputs".into()))?;
    from_fields(&proof.public_inputs[tail..])
}

/// `C`'s verification key as field elements (for recursive verification).
pub fn vk_fields<C: Honk>() -> Result<Vec<Field>, Error> {
    let (_guard, mut api) = bb()?;
    Ok(api
        .vk_as_fields(C::VK_BYTES)
        .map_err(bb_err("vk as fields"))?
        .fields
        .iter()
        .map(|f| to_field(f))
        .collect())
}
