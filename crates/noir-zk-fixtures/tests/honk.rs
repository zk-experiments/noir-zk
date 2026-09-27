//! UltraHonk end to end: a circuit the ABI marks as UltraHonk, proved and
//! verified through its generated types. Proves, so it runs only with
//! `NOIR_ZK_PROVE` set (and bb's SRS in `~/.bb-crs` or `$BB_CRS_PATH`).

#![allow(clippy::unwrap_used)]

use noir_zk_backend::honk::{outputs, HonkVerifier, UltraHonk};
use noir_zk_backend::{DirStore, Frozen};
use noir_zk_core::{CircuitId, Field, Oracle, ProofSystem};
use noir_zk_fixtures::circuits::honk_square::{HonkSquare, Inputs, PublicInputs};
use noir_zk_fixtures::circuits::{REGISTRY, VK_TREE_ROOT};

#[test]
fn abi_selects_ultra_honk() {
    assert_eq!(
        HonkSquare::SYSTEM,
        ProofSystem::UltraHonk(Oracle::Poseidon2)
    );
}

#[test]
fn proves_and_verifies_typed() {
    if std::env::var_os("NOIR_ZK_PROVE").is_none() {
        return;
    }
    let artifacts = Frozen::new(
        REGISTRY,
        &VK_TREE_ROOT,
        DirStore(noir_zk_fixtures::ASSETS.into()),
    )
    .unwrap();
    let (x, y, salt) = (Field::from(3u64), Field::from(9u64), Field::from(100u64));
    let public = PublicInputs { y };
    let prover = UltraHonk::new(&artifacts);
    let proof = prover
        .prove::<HonkSquare>(&Inputs { x, salt }, &public)
        .unwrap();
    // Public inputs: `y`, then the return value `x + salt`.
    assert_eq!(proof.public_inputs, vec![y, x + salt]);
    assert!(HonkVerifier.verify::<HonkSquare>(&public, &proof).unwrap());
    assert_eq!(outputs::<HonkSquare>(&proof).unwrap(), x + salt);

    // Another claim, or a changed return value, doesn't verify.
    let other = PublicInputs {
        y: Field::from(16u64),
    };
    assert!(!HonkVerifier.verify::<HonkSquare>(&other, &proof).unwrap());
    let mut forged = proof.clone();
    forged.public_inputs[1] += Field::from(1u64);
    assert!(!HonkVerifier.verify::<HonkSquare>(&public, &forged).unwrap());

    // A false statement fails to solve.
    let wrong = Inputs {
        x: Field::from(4u64),
        salt,
    };
    assert!(prover.prove::<HonkSquare>(&wrong, &public).is_err());
}
