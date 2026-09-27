//! Errors shared by the noir-zk crates.

use std::fmt;

/// Everything that can go wrong between typed inputs and a verified proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A value has no canonical field element (it is `>=` the field modulus).
    NonCanonical(&'static str),
    /// Inputs don't match a circuit's ABI (missing, extra or ill-typed values).
    Abi(String),
    /// A circuit artifact is missing, malformed, or fails its pinned hash.
    Artifact(String),
    /// The witness solver rejected the inputs: the statement is false for them.
    Unsatisfied(String),
    /// Proving or verification failed inside the proving backend.
    Proof(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonCanonical(what) => write!(f, "{what} is not a canonical field element"),
            Self::Abi(m) => write!(f, "ABI: {m}"),
            Self::Artifact(m) => write!(f, "artifact: {m}"),
            Self::Unsatisfied(m) => write!(f, "unsatisfied: {m}"),
            Self::Proof(m) => write!(f, "proof: {m}"),
        }
    }
}

impl std::error::Error for Error {}
