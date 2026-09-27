//! ACVM witness core: load a circuit's artifact, encode its inputs, and solve
//! the bytecode into the full witness a prover consumes, plus the circuit's
//! return value (a step's databus outputs, which the next kernel reads).
//!
//! Ported from `pso-zk-backend`'s witness module. Inputs come either typed
//! ([`Program::inputs_from_fields`], from a generated circuit type's
//! `Circuit::witness_inputs`) or as `Prover.toml` text
//! ([`Program::inputs_from_toml`], what eid-prover writes), encoded by the
//! circuit's ABI.

use std::io::Read;

use acir::circuit::Program as AcirProgram;
use acir::native_types::{Witness, WitnessMap, WitnessStack};
use acir::FieldElement;
use acvm::pwg::{ACVMStatus, ACVM};
use base64::Engine;
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use flate2::read::GzDecoder;
use noirc_abi::input_parser::Format;
use noirc_abi::Abi;

use noir_zk_core::{Error, Field};

fn gunzip(bytes: &[u8], what: &str) -> Result<Vec<u8>, Error> {
    let mut raw = Vec::new();
    GzDecoder::new(bytes)
        .read_to_end(&mut raw)
        .map_err(|e| Error::Artifact(format!("{what}: gunzip: {e}")))?;
    Ok(raw)
}

/// A compiled circuit: its ACIR program, its ABI, and the raw bytecode bb takes.
pub struct Program {
    /// Circuit package name.
    pub name: String,
    acir: AcirProgram<FieldElement>,
    abi: Abi,
    bytecode: Vec<u8>,
}

/// A solved witness.
pub struct Solved {
    /// The full witness as bb consumes it (uncompressed msgpack witness stack).
    pub witness: Vec<u8>,
    /// The return value's field elements in order (a step's databus outputs).
    pub outputs: Vec<Field>,
}

impl Program {
    /// From nargo's artifact parts: the base64 (gzipped) bytecode and the ABI JSON.
    pub fn from_parts(name: &str, bytecode_b64: &str, abi_json: &str) -> Result<Self, Error> {
        let gz = base64::engine::general_purpose::STANDARD
            .decode(bytecode_b64.trim())
            .map_err(|e| Error::Artifact(format!("{name}: bytecode base64: {e}")))?;
        let acir = AcirProgram::deserialize_program(&gz)
            .map_err(|e| Error::Artifact(format!("{name}: ACIR: {e}")))?;
        let abi: Abi = serde_json::from_str(abi_json)
            .map_err(|e| Error::Artifact(format!("{name}: ABI: {e}")))?;
        Ok(Self {
            name: name.to_string(),
            acir,
            abi,
            bytecode: gunzip(&gz, name)?,
        })
    }

    /// From a whole nargo artifact (`target/<name>.json`).
    pub fn from_nargo_json(name: &str, json: &str) -> Result<Self, Error> {
        let v: serde_json::Value =
            serde_json::from_str(json).map_err(|e| Error::Artifact(format!("{name}: {e}")))?;
        let bytecode = v["bytecode"]
            .as_str()
            .ok_or_else(|| Error::Artifact(format!("{name}: artifact has no bytecode")))?;
        Self::from_parts(name, bytecode, &v["abi"].to_string())
    }

    /// The uncompressed bytecode bb consumes.
    pub fn bytecode(&self) -> &[u8] {
        &self.bytecode
    }

    /// The circuit's ABI.
    pub fn abi(&self) -> &Abi {
        &self.abi
    }

    /// Inputs from `Prover.toml` text, type-checked and encoded by the ABI.
    pub fn inputs_from_toml(&self, toml: &str) -> Result<WitnessMap<FieldElement>, Error> {
        let inputs = Format::Toml
            .parse(toml, &self.abi)
            .map_err(|e| Error::Abi(format!("{}: {e}", self.name)))?;
        self.abi
            .encode(&inputs, None)
            .map_err(|e| Error::Abi(format!("{}: {e}", self.name)))
    }

    /// Inputs already flattened in witness-index order (`Circuit::witness_inputs`).
    pub fn inputs_from_fields(&self, fields: &[Field]) -> Result<WitnessMap<FieldElement>, Error> {
        let expected = self.abi.field_count() as usize;
        if fields.len() != expected {
            return Err(Error::Abi(format!(
                "{}: {} input fields, the ABI has {expected}",
                self.name,
                fields.len()
            )));
        }
        let mut map = WitnessMap::new();
        for (i, f) in fields.iter().enumerate() {
            let index = u32::try_from(i).map_err(|_| Error::Abi("too many inputs".into()))?;
            map.insert(Witness(index), FieldElement::from_repr(*f));
        }
        Ok(map)
    }

    /// Solves the circuit for `inputs`. Fails with [`Error::Unsatisfied`] when
    /// the statement doesn't hold for them.
    pub fn solve(&self, inputs: WitnessMap<FieldElement>) -> Result<Solved, Error> {
        let circuit =
            self.acir.functions.first().ok_or_else(|| {
                Error::Artifact(format!("{}: program has no functions", self.name))
            })?;
        let solver = Bn254BlackBoxSolver;
        let mut acvm = ACVM::new(
            &solver,
            &circuit.opcodes,
            inputs,
            &self.acir.unconstrained_functions,
            &circuit.assert_messages,
        );
        match acvm.solve() {
            ACVMStatus::Solved => {}
            other => return Err(Error::Unsatisfied(format!("{}: {other}", self.name))),
        }
        let solved = acvm.finalize();

        // The return value's witnesses follow the parameters' (noirc_abi's layout).
        let start = self.abi.field_count();
        let count = self
            .abi
            .return_type
            .as_ref()
            .map_or(0, |r| r.abi_type.field_count());
        let outputs = (start..start + count)
            .map(|i| {
                solved
                    .get(&Witness(i))
                    .map(|f| f.into_repr())
                    .ok_or_else(|| {
                        Error::Unsatisfied(format!("{}: return witness {i} unsolved", self.name))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut stack = WitnessStack::default();
        stack.push(0, solved);
        let compressed = stack
            .serialize()
            .map_err(|e| Error::Proof(format!("{}: witness serialize: {e}", self.name)))?;
        Ok(Solved {
            witness: gunzip(&compressed, &self.name)?,
            outputs,
        })
    }
}
