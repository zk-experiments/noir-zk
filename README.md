# noir-zk

Tooling and a library for proving Noir circuits with barretenberg's Chonk folding, in Rust. A circuit repository freezes its compiled circuits with the `noir-zk` CLI, generates typed bindings with `noir-zk-codegen` from its `build.rs`, and proves and verifies through `noir-zk-backend`. Ported from psonet's circuit layer without `pso-protocol`. [eid-circuits](https://github.com/zk-experiments/eid-circuits) (crate `eid-circuits`) is the first consumer.

Toolchain: Noir `1.0.0-rc.3` (the linked ACVM), Barretenberg `7.0.0-nightly.20260927` (linked through `barretenberg-rs`, no `bb` binary needed). Proofs from other bb versions do not verify.

## Crates

| Crate | What it does |
| --- | --- |
| `noir-zk-core` | `Field` (BN254 `Fr`), the `Circuit` trait (typed `Witness` / `PublicInputs` / `Outputs`), `CircuitId`, the fold traits `App` / `Kernel` / `AppDispatch`, the `FieldEncode` / `FromFields` codec, `RegistryEntry` / `Status`, and the `Artifacts` trait (bytecode, ABI, key, key-tree path). |
| `noir-zk-codegen` | Build-dependency generator: typed inputs and outputs from nargo ABIs (`generate_types`), or a frozen registry (`generate_registry`) where every circuit also gets `CircuitId` with its embedded key, `App` or `Kernel`, and a `Registry` with static label dispatch. |
| `noir-zk-backend` | Typed folding (`fold::Folding`, `fold::verify`), ACVM witness solving (`witness`), Chonk prove / verify / key derivation (`chonk`), SRS loading (`srs`), and `Frozen<S>`: a generated registry as `Artifacts`, bytecode from an `ArtifactStore` checked against its pinned SHA-256. |
| `noir-zk-cli` | `noir-zk freeze`: mints circuit versions from nargo output and derives their Chonk keys. |

## Using it from a circuit repository

1. Compile the circuits (`nargo compile --workspace`) and build the Poseidon2 verification key tree the kernels check (`vk-tree.json`: `root`, and `leaves` with `package`, `vk_hash`, `index`, `siblings`).
2. Freeze them into a bindings crate:

   ```sh
   cargo install --locked --git https://github.com/zk-experiments/noir-zk noir-zk-cli
   noir-zk freeze --target target --vk-tree vk-tree.json --out rust/my-zk --assets target/release-assets
   ```

   The bindings crate then holds `circuits/manifest.toml` and `resources/` (ABIs, keys, the tree). The bytecode goes to `--assets` as `<label>@<version>.b64`, to be uploaded as release assets. It is too large for git.
3. Generate the bindings in that crate's `build.rs`:

   ```toml
   [dependencies]
   noir-zk-core = { git = "https://github.com/zk-experiments/noir-zk" }
   noir-zk-backend = { git = "https://github.com/zk-experiments/noir-zk" }

   [build-dependencies]
   noir-zk-codegen = { git = "https://github.com/zk-experiments/noir-zk" }
   ```

   ```rust
   // build.rs
   fn main() {
       let dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
       let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
       std::fs::write(out.join("circuits.rs"), noir_zk_codegen::generate_registry(&dir)).unwrap();
       println!("cargo:rerun-if-changed=circuits/manifest.toml");
   }
   ```

   ```rust
   pub mod circuits { include!(concat!(env!("OUT_DIR"), "/circuits.rs")); }
   ```

4. Prove and verify with the backend, passing the generated types:

   ```rust
   use noir_zk_backend::fold::{verify, Folding};

   let artifacts = noir_zk_backend::Frozen::new(circuits::REGISTRY, &circuits::VK_TREE_ROOT, DirStore(assets))?;
   let (proof, out) = Folding::new(&artifacts)
       .app::<MyStep>(&my_step::Inputs { .. })?        // typed witness
       .kernel::<KernelStep>()?                         // KernelStep::Step must be MyStep::Outputs
       .app_by_label::<circuits::Registry, _>(label, &prover_toml)?  // chosen at runtime, dispatched statically
       .kernel::<KernelNext>()?                         // KernelNext::Prev must be KernelStep::Outputs
       .hiding::<KernelHiding>()?;                      // proves; out: KernelHiding::Outputs
   let out = verify::<KernelHiding>(&proof, vk_tree_root)?;
   ```

   The chain is checked at compile time. Each kernel's `Prev` and `Step` types are the outputs of the kernel and app it folds, so a missing or misordered circuit doesn't compile. Kernels take no user inputs. By convention their `main` parameters are drawn from `prev`, `step`, `prev_vk`, `step_vk` and `vk_tree_root`, and the builder fills them. `verify` checks the hiding kernel's pinned key and its `vk_tree_root` output.

For typed inputs without freezing, `noir_zk_codegen::generate_types(&nargo_target_abis("target", |_| true)?)` works from any nargo output (`Inputs`, `Outputs` and `Circuit`; folding needs the frozen registry for the keys).

Versioning is per circuit. A new circuit starts at `1.0.0`. Changed bytecode with the same ABI gets a patch bump. An ABI change is refused without `--abi-change`, which makes a minor bump. The superseded version is marked `deprecated` and loses its ABI but keeps its key and asset. Each derived key's Poseidon2 hash is checked against the tree before anything is written. `--check` writes nothing and fails if the registry is behind the compiled circuits. Kinds: `--hiding LABEL` (default `kernel_hiding`) is the hiding kernel. Labels starting with `--kernel-prefix` (default `kernel_`) are kernels. Everything else is an app.

## Runtime

On Linux, `barretenberg-rs` needs libc++ (`apt install libc++-dev libc++abi-dev`).

The SRS is loaded once from `$BB_CRS_PATH` or `~/.bb-crs`, with no network fallback, and checked against pinned SHA-256 digests. It needs the BN254 file with 2^20+1 points and the Grumpkin file `grumpkin_g1_v2.flat.dat` with 2^15 points. Override with `srs::set_srs_paths`.

Build with optimisations. ACVM is generic and compiles into your crate, so at `opt-level = 0` witness solving is about 8x slower. Set `[profile.dev] opt-level = 3` in consumers too.

Stores: `DirStore(path)` is a local directory. `HttpStore(base_url)` (feature `http`) fetches `<base_url>/<asset>`.

## Proofs

A Chonk proof is fixed-size for a given bb version: 39,872 bytes (1,246 fields of 32 bytes) on bb 7, with the hiding kernel's public inputs first (`FoldedProof::public_fields`). Native verification takes about 20 ms.

## Tests

`cargo test` runs the unit tests. End-to-end proving tests (frozen registry, CLI-proof interop, tampered assets) live with the circuits in the `eid-circuits` crate. CI never proves.
