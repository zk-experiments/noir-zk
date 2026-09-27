# noir-zk

Proving and verification for the [eid-circuits](https://github.com/zk-experiments/eid-circuits) Noir circuits, in Rust. It holds the circuit traits, field codec, generated circuit types and the frozen circuit registry, plus a Barretenberg backend that folds a document's circuits with Chonk and verifies the result. Ported from psonet's circuit layer without `pso-protocol`.

Toolchain: Noir `1.0.0-rc.3`, Barretenberg `7.0.0-nightly.20260927` (linked through `barretenberg-rs`, no `bb` binary needed). Proofs from other bb versions do not verify.

## Crates

| Crate | What it does |
| --- | --- |
| `noir-zk-core` | `Field` (BN254 `Fr`), the `Circuit` / `CircuitId` / `ProofGenerator` / `ProofVerifier` traits, `CircuitKind`, the `FieldEncode` codec, and the `Artifacts` trait (bytecode, ABI, key, key-tree path). |
| `noir-zk-codegen` | Build-time generator: typed inputs from nargo ABIs, and the frozen registry. Used as a build-dependency. |
| `noir-zk-canonical` | The frozen registry: every active circuit's generated types, `CircuitId`, embedded Chonk key and key-tree path, and `Canonical<S>`, an `Artifacts` that fetches bytecode from a store and checks its pinned SHA-256. |
| `noir-zk-backend` | ACVM witness solving, Chonk folding over the FFI, and the document API: `prove_document` / `verify_document`. |
| `xtask` | `freeze-circuits`: mints circuit versions from a compiled eid-circuits checkout. |

## Proving and verifying

```rust
use noir_zk_backend::fold::{prove_document, verify_document, Document, Inputs};
use noir_zk_canonical::{hiding_vk, vk_tree_root, Canonical, HttpStore};

let artifacts = Canonical::new(HttpStore(ASSETS_URL.into()));
let doc = Document {
    dsc: ("dsc_rsa_pkcs1v15_2048_sha1_tbs1000", Inputs::Toml(&dsc_toml)),
    sod: ("sod_ecdsa_p256_sha256_tbs1000", Inputs::Toml(&sod_toml)),
    envelope: ("envelope_sha256_sha256_lds1024", Inputs::Toml(&envelope_toml)),
};
let (proof, public) = prove_document(&artifacts, &doc)?;

// Verifier side: only the pinned key and root, no bytecode.
let public = verify_document(&proof, hiding_vk(), vk_tree_root())?;
```

The circuit labels come from the eid-circuits prover crate, which selects them from the NFC data. `verify_document` checks the proof, the key tree root and the output layout; the caller still checks the registry root, date, context, viewers and hash policy (eid-circuits `docs/VERIFY.md`).

The SRS is loaded once from `$BB_CRS_PATH` or `~/.bb-crs`, with no network fallback, and checked against pinned SHA-256 digests. It needs the BN254 file with 2^20+1 points and the Grumpkin file `grumpkin_g1_v2.flat.dat` with 2^15 points. Override with `srs::set_srs_paths`.

## Verification parameters

| | |
| --- | --- |
| Proof | 39,872 bytes (1,246 fields of 32 bytes) |
| Public inputs | the first 25 fields of the proof (`PUBLIC_FIELDS`); the envelope is fields 13–24 (384 bytes) |
| Hiding kernel key | embedded (`hiding_vk()`) |
| Key tree root | `0x25d3ee909adb8d8e13248248a121fbf63568234bc0498b18447cec69fc5605bd` |
| Native verification | about 20 ms |

A document proof takes about 2 s on an M-series laptop. Build with optimisations: ACVM is generic and compiles into your crate, and at `opt-level = 0` witness solving is about 8x slower. This workspace sets `opt-level = 3` for dev builds.

## Artifacts

Keys, ABIs and the key tree are committed under `crates/noir-zk-canonical/resources`. That is 5.8 MB for 301 circuits. The bytecode is about 730 MB, so it lives in the `circuits` GitHub release as `<label>@<version>.b64`. `circuits/manifest.toml` pins each asset's SHA-256, and `Canonical` rejects any asset that does not match. Stores:

- `DirStore(path)`: a local directory, such as a downloaded release or `target/release-assets`.
- `HttpStore(base_url)` (feature `http`): `<base_url>/<asset>`. The repository is private, so its release URLs need authentication. Mirror the assets somewhere public for unauthenticated clients.

Assets are immutable, so the one release accumulates every version. GitHub caps a release at 1,000 assets; move to one release per freeze if that becomes a limit.

## Freezing circuits

With a compiled eid-circuits checkout (`nargo compile --workspace` and a current `noir/circuits/vk-tree.json`):

```sh
mise run freeze            # EID_CIRCUITS defaults to ../eid-circuits
mise run freeze:check      # fails if the registry is behind the checkout
mise run assets:publish    # uploads new target/release-assets/*.b64
```

Versioning is per circuit. A new circuit starts at `1.0.0`. Changed bytecode with the same ABI gets a patch bump. An ABI change is refused without `--abi-change`, which makes a minor bump. The superseded version is marked `deprecated` and loses its ABI but keeps its key and asset, so old clients still find their bytecode. Each key's Poseidon2 hash is checked against the key tree before anything is written.

## Reusing the generator

Any crate with nargo output can generate typed circuit inputs at build time:

```toml
[dependencies]
noir-zk-core = { git = "https://github.com/zk-experiments/noir-zk" }

[build-dependencies]
noir-zk-codegen = { git = "https://github.com/zk-experiments/noir-zk" }
```

```rust
// build.rs
fn main() {
    let target = "../target";
    let abis = noir_zk_codegen::nargo_target_abis(target, |name| !name.starts_with("test_")).unwrap();
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("circuits.rs");
    std::fs::write(out, noir_zk_codegen::generate_types(&abis)).unwrap();
    println!("cargo:rerun-if-changed={target}");
}
```

```rust
pub mod circuits { include!(concat!(env!("OUT_DIR"), "/circuits.rs")); }
```

To use the frozen circuits rather than a local build, depend on `noir-zk-canonical`. Its `circuits` module is already generated.

## Tests

`cargo test` runs the unit tests. The proving tests skip unless they have inputs:

```sh
NOIR_ZK_EID_CIRCUITS=$PWD/../eid-circuits NOIR_ZK_ASSETS=$PWD/target/release-assets cargo test --release
# or: mise run test:heavy
```

They prove and verify every chain with the frozen registry, check that a proof made by the `bb` CLI verifies through the FFI (`NOIR_ZK_CLI_PROOF`), and check that a tampered asset is rejected. CI only runs the unit tests and never proves.
