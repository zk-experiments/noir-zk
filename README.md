# noir-zk

Tooling and a library for proving Noir circuits with barretenberg, in Rust: standalone UltraHonk proofs and Chonk folding. A circuit repository freezes its compiled circuits with the `noir-zk` CLI, generates typed bindings with `noir-zk-codegen` from its `build.rs`, and proves and verifies through `noir-zk-backend`. [eid-circuits](https://github.com/zk-experiments/eid-circuits) (crate `eid-circuits`) is the first consumer.

Toolchain: Noir `1.0.0-rc.3` (the linked ACVM), Barretenberg `7.0.0-nightly.20260927` (linked through `barretenberg-rs`, no `bb` binary needed). Proofs from other bb versions do not verify.

## Crates

| Crate | What it does |
| --- | --- |
| `noir-zk-core` | `Field` (BN254 `Fr`), the `Circuit` trait (typed `Witness` / `PublicInputs` / `Outputs`), `CircuitId` with its `ProofSystem`, `Honk`, the fold traits `App` / `Kernel` / `Wrapped` / `AppDispatch`, the `FieldEncode` / `FromFields` codec, `RegistryEntry` / `Status`, and the `Artifacts` trait (bytecode, ABI, key, key-tree path). |
| `noir-zk-codegen` | Build-dependency generator: typed inputs and outputs from nargo ABIs (`generate_types`), or a frozen registry (`generate_registry`) where every circuit also gets `CircuitId` with its embedded key, `App` or `Kernel` (kernels also get `wrap` / `select`), and a `Registry` with static label dispatch. |
| `noir-zk-backend` | Typed UltraHonk (`honk::UltraHonk`, `honk::HonkVerifier`), typed folding (`fold::Folding`, `fold::verify`), ACVM witness solving (`witness`), Chonk prove / verify / key derivation (`chonk`), SRS loading (`srs`), and `Frozen<S>`: a generated registry as `Artifacts`, bytecode from an `ArtifactStore` checked against its pinned SHA-256. |
| `noir-zk-cli` | `noir-zk freeze`: mints circuit versions from nargo output, reads each circuit's proof system off its ABI, and derives its key. |
| `noir-zk-fixtures` | Test-only: a small UltraHonk circuit frozen and bound like a consumer's, proved end to end (`mise run fixtures` refreezes it). |

## Using it from a circuit repository

1. Compile the circuits (`nargo compile --workspace`). For Chonk, also build the Poseidon2 verification key tree the kernels check (`vk-tree.json`: `root`, and `leaves` with `package`, `vk_hash`, `index`, `siblings`).
2. Freeze them into a bindings crate:

   ```sh
   cargo install --locked --git https://github.com/zk-experiments/noir-zk noir-zk-cli
   noir-zk freeze --target target --out rust/my-zk --assets target/release-assets [--vk-tree vk-tree.json] [--exclude bench_]
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
       .app(KernelA::wrap::<StepA>(&step_a::Inputs { .. }))?   // typed app, folded by KernelA
       .app(KernelB::select(label, &prover_toml)?)?           // app chosen at runtime
       .kernel::<KernelTail>()?                               // a kernel without an app
       .hiding::<KernelHiding>()?;                            // proves; out: KernelHiding::Outputs
   let out = verify::<KernelHiding>(&proof, vk_tree_root)?;
   ```

   Each app is wrapped with the kernel that folds it. `KernelA::wrap::<C>` only compiles when `C`'s outputs are `KernelA`'s `step` type. `KernelB::select` dispatches a runtime label statically, through the generated `Registry`, to a circuit of that type, and rejects any other label. `.app(..)` and `.kernel::<K>()` only compile when `K`'s `prev` type is the previous kernel's outputs. A missing or misordered circuit is a compile error. Kernels take no user inputs. By convention their `main` parameters are drawn from `prev`, `step`, `prev_vk`, `step_vk` and `vk_tree_root`, and the builder fills them. `verify` checks the hiding kernel's pinned key and its `vk_tree_root` output.

For typed inputs without freezing, `noir_zk_codegen::generate_types(&nargo_target_abis("target", |_| true)?)` works from any nargo output (`Inputs`, `Outputs` and `Circuit`; folding needs the frozen registry for the keys).

The code carries the pins: every generated circuit has `BYTECODE_SHA256` and `VK_SHA256` (and the key itself, `VK_BYTES`), and `REGISTRY` lists both hashes for every version. freeze records them in the manifest; codegen fails the build if `vk_sha256` doesn't match the embedded key. So anything downloaded (a pack, a single asset) can be checked against the code, whatever host served it.

Versioning is per circuit. A new circuit starts at `1.0.0`. Changed bytecode with the same ABI gets a patch bump. An ABI change is refused without `--abi-change`, which makes a minor bump. The superseded version is marked `deprecated` and loses its ABI but keeps its key and asset. Each derived key's Poseidon2 hash is checked against the tree before anything is written. `--check` writes nothing and fails if the registry is behind the compiled circuits.

## Proof systems

`noir-zk freeze` reads each circuit's proof system off its ABI. Nothing is declared by hand:

| ABI | Proof system | Generated |
| --- | --- | --- |
| no `databus` parameter or return | UltraHonk (transcript hash from `--honk-oracle`, default `poseidon2`, `keccak` for EVM verifiers) | `impl Honk`; `pub` parameters become `PublicInputs` |
| returns via `databus` | Chonk app | `impl App` |
| kernel-convention parameters, returns via `databus` | Chonk kernel | `impl Kernel`, `wrap` / `select` |
| kernel-convention parameters, returns `pub` | Chonk hiding kernel | `impl Kernel` |

Chonk needs the databus to link circuits, and UltraHonk rejects databus circuits, so the ABI decides. freeze records the result in the manifest (`system`, plus `role` or `oracle`), and `--check` fails if the recorded system and the ABI disagree. It also refuses a Chonk circuit with `pub` parameters, a Chonk app returning `pub` values, and a Chonk app or kernel missing from `--vk-tree`.

UltraHonk circuits are proved and verified on their own, typed by the generated circuit:

```rust
use noir_zk_backend::honk::{outputs, HonkVerifier, UltraHonk};

let proof = UltraHonk::new(&artifacts).prove::<Square>(&square::Inputs { x, salt }, &square::PublicInputs { y })?;
assert!(HonkVerifier.verify::<Square>(&square::PublicInputs { y }, &proof)?);   // embedded key, no artifacts
let out: square::Outputs = outputs::<Square>(&proof)?;                          // the pub return values
```

A proof's public inputs are the `pub` parameters, then the `pub` return values. `honk::vk_fields::<C>()` gives a key as fields for verifying it inside another circuit.

## Circuit packs

A pack is a self-contained `.tar.gz` of a group of circuits that a prover fetches in one go. Fetching exactly one document's circuits would tell the host that document's configuration; a pack only tells it which pack. eid-circuits packs by key family, plus a `common` pack.

```sh
noir-zk pack --out rust/my-zk --assets target/release-assets --packs packs.toml --dest target/packs --version 0.3.0
```

Each table of `packs.toml` with a `circuits = [labels]` list becomes `<name>@<version>.tar.gz`; other tables (a country map, say) are ignored. A pack holds, per circuit, `<label>@<version>.b64` (bytecode, checked against the manifest's pin while packing), `.vk` and `.abi.json`, plus `vk-tree.json` and a `manifest.toml` with just its circuits' entries. Archives are deterministic: the same inputs give the same bytes. `pack` also writes `catalog@<version>.json`, the index a client reads first: each pack's file, SHA-256 and size and its circuits, the Noir and bb versions, the key tree root, and the packs file's other tables (eid-circuits' country map) as they are. Check an archive's SHA-256 against the catalog before unpacking it.

On the client, `pack::unpack` (feature `packs`) extracts a pack into a directory that `DirStore` reads. `frozen::verify_dir(REGISTRY, dir)` checks every `.b64` and `.vk` file in it against the pins compiled into the bindings, and `Frozen` checks each bytecode again when it loads it. Unpacking accepts only plain files with those names: no paths, directories or links.

## Runtime

On Linux, `barretenberg-rs` needs libc++ (`apt install libc++-dev libc++abi-dev`).

The SRS is loaded once from `$BB_CRS_PATH` or `~/.bb-crs`, with no network fallback, and checked against pinned SHA-256 digests. It needs the BN254 file with 2^20+1 points and the Grumpkin file `grumpkin_g1_v2.flat.dat` with 2^15 points. Override with `srs::set_srs_paths`.

Build with optimisations. ACVM is generic and compiles into your crate, so at `opt-level = 0` witness solving is about 8x slower. Set `[profile.dev] opt-level = 3` in consumers too.

Stores: `DirStore(path)` is a local directory. `HttpStore(base_url)` (feature `http`) fetches `<base_url>/<asset>`.

## Proof sizes

A Chonk proof is fixed-size for a given bb version: 39,872 bytes (1,246 fields of 32 bytes) on bb 7, with the hiding kernel's public inputs first (`FoldedProof::public_fields`). Native verification takes about 20 ms.

## Tests

`cargo test` runs the unit tests. `NOIR_ZK_PROVE=1 cargo test` also proves the UltraHonk fixture (needs bb's SRS). End-to-end proving tests (frozen registry, CLI-proof interop, tampered assets) live with the circuits in the `eid-circuits` crate. CI never proves.
