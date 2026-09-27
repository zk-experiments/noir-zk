//! The eid document proof: the DSC, SOD and envelope steps of eid-circuits,
//! folded with Chonk through five kernels (eid-circuits `docs/FOLDING.md`):
//!
//! ```text
//! DSC -> kernel_dsc -> SOD -> kernel_sod -> envelope -> kernel_envelope -> kernel_tail -> kernel_hiding
//! ```
//!
//! [`prove_document`] solves the three steps from the prover's inputs, builds
//! each kernel's inputs (the previous outputs, the verification keys and their
//! key tree paths) and solves it, then folds all eight. [`verify_document`]
//! checks a proof against the hiding kernel's key and the published key tree
//! root and returns the public outputs.

use ark_ff::{BigInteger, PrimeField};

use noir_zk_core::{Artifacts, CircuitKind, Error, Field, VkPath};

use crate::chonk::{self, FoldedProof, Step};
use crate::witness::{Program, Solved};

/// The five kernels, in folding order.
pub const KERNELS: [&str; 5] = [
    "kernel_dsc",
    "kernel_sod",
    "kernel_envelope",
    "kernel_tail",
    "kernel_hiding",
];
/// Public outputs of the hiding kernel (`eid_kernel::PublicOutputs`).
pub const PUBLIC_FIELDS: usize = 25;

/// A step's inputs.
pub enum Inputs<'a> {
    /// `Prover.toml` text (what eid-prover writes).
    Toml(&'a str),
    /// Field elements in witness-index order (a generated `Circuit` type).
    Fields(Vec<Field>),
}

/// The three steps of one document: which circuit each uses, and its inputs.
pub struct Document<'a> {
    /// DSC step circuit and inputs.
    pub dsc: (&'a str, Inputs<'a>),
    /// SOD step.
    pub sod: (&'a str, Inputs<'a>),
    /// Envelope step.
    pub envelope: (&'a str, Inputs<'a>),
}

/// What a document proof makes public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicOutputs {
    /// csca-registry root.
    pub registry_root: Field,
    /// Verification key tree root.
    pub vk_tree_root: Field,
    /// Whether any step hashed with SHA-1.
    pub uses_sha1: bool,
    /// Proof date, unix seconds.
    pub date: u64,
    /// The transfer the envelope is bound to.
    pub context: Field,
    /// Viewer keys (`(0, 0)` for an empty slot).
    pub viewers: [(Field, Field); 4],
    /// Envelope ephemeral key `E`.
    pub ephemeral: (Field, Field),
    /// Wrapped data keys.
    pub wrapped: [Field; 4],
    /// Ciphertext.
    pub ciphertext: [Field; 6],
}

impl PublicOutputs {
    /// From the proof's first [`PUBLIC_FIELDS`] fields.
    pub fn from_fields(f: &[Field]) -> Result<Self, Error> {
        if f.len() != PUBLIC_FIELDS {
            return Err(Error::Proof(format!(
                "{} public fields, expected {PUBLIC_FIELDS}",
                f.len()
            )));
        }
        let small = |x: &Field, what: &str| -> Result<u64, Error> {
            let be = x.into_bigint().to_bytes_be();
            if be[..be.len() - 8].iter().any(|b| *b != 0) {
                return Err(Error::Proof(format!("{what} does not fit 64 bits")));
            }
            Ok(u64::from_be_bytes(
                be[be.len() - 8..].try_into().unwrap_or([0; 8]),
            ))
        };
        let sha1 = small(&f[2], "uses_sha1")?;
        if sha1 > 1 {
            return Err(Error::Proof("uses_sha1 is not a bit".into()));
        }
        Ok(Self {
            registry_root: f[0],
            vk_tree_root: f[1],
            uses_sha1: sha1 == 1,
            date: small(&f[3], "date")?,
            context: f[4],
            viewers: [(f[5], f[6]), (f[7], f[8]), (f[9], f[10]), (f[11], f[12])],
            ephemeral: (f[13], f[14]),
            wrapped: [f[15], f[16], f[17], f[18]],
            ciphertext: [f[19], f[20], f[21], f[22], f[23], f[24]],
        })
    }
}

fn hex(f: &Field) -> String {
    format!("0x{}", ::hex::encode(f.into_bigint().to_bytes_be()))
}

fn list(fs: &[Field]) -> String {
    format!(
        "[{}]",
        fs.iter()
            .map(|f| format!("\"{}\"", hex(f)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// A kernel `Vk` input as TOML (`key` and its tree `path`).
fn vk_table(prefix: &str, key: &[Field], path: &VkPath) -> String {
    format!(
        "\n[{prefix}]\nkey = {}\n\n[{prefix}.path]\nindex = \"{}\"\nsiblings = {}\n",
        list(key),
        path.index,
        list(&path.siblings)
    )
}

struct Solving<'a, A: Artifacts> {
    artifacts: &'a A,
    circuits: Vec<(String, CircuitKind, Program, Vec<u8>, Solved)>,
}

impl<A: Artifacts> Solving<'_, A> {
    fn step(
        &mut self,
        name: &str,
        kind: CircuitKind,
        inputs: &Inputs<'_>,
    ) -> Result<Vec<Field>, Error> {
        let program = Program::from_parts(
            name,
            &self.artifacts.bytecode_b64(name)?,
            &self.artifacts.abi_json(name)?,
        )?;
        let map = match inputs {
            Inputs::Toml(t) => program.inputs_from_toml(t)?,
            Inputs::Fields(f) => program.inputs_from_fields(f)?,
        };
        let solved = program.solve(map)?;
        let outputs = solved.outputs.clone();
        let vk = self.artifacts.vk(name)?;
        self.circuits
            .push((name.to_string(), kind, program, vk, solved));
        Ok(outputs)
    }

    fn vk_input(&self, name: &str, kind: CircuitKind) -> Result<(Vec<Field>, VkPath), Error> {
        let vk = self.artifacts.vk(name)?;
        Ok((chonk::vk_fields(&vk, kind)?, self.artifacts.vk_path(name)?))
    }
}

/// Proves a document: solves its three steps, builds and solves the kernels,
/// and folds all eight circuits. Returns the proof and its public outputs.
pub fn prove_document<A: Artifacts>(
    artifacts: &A,
    doc: &Document<'_>,
) -> Result<(FoldedProof, PublicOutputs), Error> {
    let mut s = Solving {
        artifacts,
        circuits: vec![],
    };
    let root = artifacts.vk_tree_root();

    let dsc = s.step(doc.dsc.0, CircuitKind::App, &doc.dsc.1)?;
    let (key, path) = s.vk_input(doc.dsc.0, CircuitKind::App)?;
    let toml = format!(
        "step = {}\nvk_tree_root = \"{}\"\n{}",
        list(&dsc),
        hex(&root),
        vk_table("step_vk", &key, &path)
    );
    let state = s.step("kernel_dsc", CircuitKind::Kernel, &Inputs::Toml(&toml))?;

    let sod = s.step(doc.sod.0, CircuitKind::App, &doc.sod.1)?;
    let (pk, pp) = s.vk_input("kernel_dsc", CircuitKind::Kernel)?;
    let (sk, sp) = s.vk_input(doc.sod.0, CircuitKind::App)?;
    let toml = format!(
        "prev = {}\nstep = {}\n{}{}",
        list(&state),
        list(&sod),
        vk_table("prev_vk", &pk, &pp),
        vk_table("step_vk", &sk, &sp)
    );
    let state = s.step("kernel_sod", CircuitKind::Kernel, &Inputs::Toml(&toml))?;

    let env = s.step(doc.envelope.0, CircuitKind::App, &doc.envelope.1)?;
    let (pk, pp) = s.vk_input("kernel_sod", CircuitKind::Kernel)?;
    let (sk, sp) = s.vk_input(doc.envelope.0, CircuitKind::App)?;
    let toml = format!(
        "prev = {}\nstep = {}\n{}{}",
        list(&state),
        list(&env),
        vk_table("prev_vk", &pk, &pp),
        vk_table("step_vk", &sk, &sp)
    );
    let state = s.step("kernel_envelope", CircuitKind::Kernel, &Inputs::Toml(&toml))?;

    for (kernel, prev, kind) in [
        ("kernel_tail", "kernel_envelope", CircuitKind::Kernel),
        ("kernel_hiding", "kernel_tail", CircuitKind::Hiding),
    ] {
        let (pk, pp) = s.vk_input(prev, CircuitKind::Kernel)?;
        let toml = format!("prev = {}\n{}", list(&state), vk_table("prev_vk", &pk, &pp));
        let out = s.step(kernel, kind, &Inputs::Toml(&toml))?;
        if kernel == "kernel_hiding" {
            let steps: Vec<Step<'_>> = s
                .circuits
                .iter()
                .map(|(name, kind, program, vk, solved)| Step {
                    name,
                    kind: *kind,
                    bytecode: program.bytecode(),
                    vk,
                    witness: &solved.witness,
                })
                .collect();
            let proof = chonk::prove(&steps)?;
            let public = PublicOutputs::from_fields(&out)?;
            if proof.public_fields(PUBLIC_FIELDS)? != out {
                return Err(Error::Proof(
                    "proof's public fields differ from the hiding kernel's outputs".into(),
                ));
            }
            return Ok((proof, public));
        }
    }
    Err(Error::Proof("unreachable: no hiding kernel".into()))
}

/// Verifies a document proof against the pinned hiding kernel key and the
/// published key tree root, and returns its public outputs. The caller still
/// checks the registry root, date, context, viewers and hash policy
/// (eid-circuits `docs/VERIFY.md`).
pub fn verify_document(
    proof: &FoldedProof,
    hiding_vk: &[u8],
    vk_tree_root: Field,
) -> Result<PublicOutputs, Error> {
    let public = PublicOutputs::from_fields(&proof.public_fields(PUBLIC_FIELDS)?)?;
    if public.vk_tree_root != vk_tree_root {
        return Err(Error::Proof(
            "proof uses another verification key tree".into(),
        ));
    }
    if !chonk::verify(proof, hiding_vk)? {
        return Err(Error::Proof("document proof does not verify".into()));
    }
    Ok(public)
}
