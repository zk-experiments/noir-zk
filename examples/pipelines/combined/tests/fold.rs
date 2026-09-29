//! Folds and verifies the three pipelines in-process. Proves, so it runs only
//! with `NOIR_ZK_PROVE` set (bb's SRS in `~/.bb-crs` or `$BB_CRS_PATH`).

use combined::circuits::families::{KernelStepCounter, KernelStepSeed, KernelStepSum, KernelStepTag};
use combined::circuits::pipelines::{seed_count, seed_count_sum, tag_only};
use combined::circuits::{DEPLOYMENT, DEPLOYMENT_ROOT, FAMILIES};
use noir_zk_core::{Field, StepFamily};

#[test]
fn roots_and_families() {
    assert_eq!(FAMILIES.len(), 4);
    assert_eq!(FAMILIES[1].members.len(), 2, "counter has two variants");
    assert_ne!(seed_count::ROOT, seed_count_sum::ROOT);
    assert_eq!(DEPLOYMENT.roots.len(), 3);
    assert_eq!(DEPLOYMENT.root, DEPLOYMENT_ROOT);
    assert!(KernelStepCounter::select("seed", "").is_err(), "not a counter");
}

#[test]
fn folds_and_verifies() {
    if std::env::var_os("NOIR_ZK_PROVE").is_none() {
        return;
    }
    let (a, b) = (lib_a::artifacts(), lib_b::artifacts());
    let pool = combined::pool(&a, &b);
    let (proof, _) = seed_count_sum::fold(&pool)
        .unwrap()
        .app(KernelStepSeed::select("seed", "s = \"7\"").unwrap())
        .unwrap()
        .app(KernelStepCounter::select("counter_big", "s = \"7\"\nn = \"5\"").unwrap())
        .unwrap()
        .app(KernelStepSum::select("sum", "c = \"12\"\nn = \"5\"").unwrap())
        .unwrap()
        .hiding(&DEPLOYMENT)
        .unwrap();
    let out = seed_count_sum::verify(&proof).unwrap();
    assert_eq!((out.length, out.seed_sq, out.n, out.total), (3, Field::from(49u64), Field::from(5u64), Field::from(17u64)));
    assert!(seed_count::verify(&proof).is_err(), "another pipeline's root");
    // A wrong link (the counter fed 8, the seed was 7) is refused by the kernel, not proven.
    let bad = seed_count::fold(&pool)
        .unwrap()
        .app(KernelStepSeed::select("seed", "s = \"7\"").unwrap())
        .unwrap()
        .app(KernelStepCounter::select("counter_small", "s = \"8\"\nn = \"1\"").unwrap());
    assert!(bad.is_err());
    // A wrong binding (sum given n = 6 while the counter published 5) too.
    let bad = seed_count_sum::fold(&pool)
        .unwrap()
        .app(KernelStepSeed::select("seed", "s = \"7\"").unwrap())
        .unwrap()
        .app(KernelStepCounter::select("counter_small", "s = \"7\"\nn = \"5\"").unwrap())
        .unwrap()
        .app(KernelStepSum::select("sum", "c = \"12\"\nn = \"6\"").unwrap());
    assert!(bad.is_err());
    // The one-app pipeline (padded with kernel_tail).
    let (proof, _) = tag_only::fold(&pool)
        .unwrap()
        .app(KernelStepTag::select("tag", "t = \"2\"").unwrap())
        .unwrap()
        .hiding(&DEPLOYMENT)
        .unwrap();
    assert_eq!(tag_only::verify(&proof).unwrap().tag, Field::from(6u64));
}
