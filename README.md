# noir-zk

[![noir-zk-core](https://img.shields.io/crates/v/noir-zk-core?label=noir-zk-core)](https://crates.io/crates/noir-zk-core)
[![noir-zk-codegen](https://img.shields.io/crates/v/noir-zk-codegen?label=noir-zk-codegen)](https://crates.io/crates/noir-zk-codegen)
[![noir-zk-backend](https://img.shields.io/crates/v/noir-zk-backend?label=noir-zk-backend)](https://crates.io/crates/noir-zk-backend)
[![noir-zk-cli](https://img.shields.io/crates/v/noir-zk-cli?label=noir-zk-cli)](https://crates.io/crates/noir-zk-cli)

Tooling and a library for proving Noir circuits with barretenberg, in Rust: standalone UltraHonk proofs and Chonk folding. A circuit repository freezes its compiled circuits with the `noir-zk` CLI, generates typed bindings with `noir-zk-codegen` from its `build.rs`, and proves and verifies through `noir-zk-backend`. [eid-circuits](https://github.com/zk-experiments/eid-circuits) (crate `eid-circuits`) is the first consumer.

Toolchain: Noir `1.0.0-rc.3` (the linked ACVM), Barretenberg `7.0.0-nightly.20260927` (linked through `barretenberg-rs`, no `bb` binary needed). Proofs from other bb versions do not verify.

## Crates

| Crate | What it does |
| --- | --- |
| `noir-zk-core` | `Field` (BN254 `Fr`), the `Circuit` trait (typed `Witness` / `PublicInputs` / `Outputs`), `CircuitId` with its `ProofSystem`, `Honk`, the fold traits `App` / `Kernel` / `Wrapped` / `AppDispatch`, the `FieldEncode` / `FromFields` codec, `RegistryEntry` / `Status` / `Library`, the layered types (`FamilyEntry`, `PipelineEntry`, `DeploymentEntry`, `Layout`, `StepFamily`, the link traits), the key trees (`tree`) and the `Artifacts` trait with `Merged`. |
| `noir-zk-codegen` | Build-dependency generator: typed inputs and outputs from nargo ABIs (`generate_types`), or a frozen registry (`generate_registry`) where every circuit also gets `CircuitId` with its embedded key, `App` or `Kernel` (kernels also get `wrap` / `select`), a `Registry` with static label dispatch, and, for a layered registry, `FAMILIES` with a marker type per family, `pipelines::<name>` (root, typed `Outputs`, `fold`, `verify`), `DEPLOYMENT` and a test recomputing every root; `wrapped` exports a registry for another to wrap. |
| `noir-zk-backend` | Typed UltraHonk (`honk::UltraHonk`, `honk::HonkVerifier`), typed folding of hand-written kernels (`fold::Folding`, `fold::verify`), pipeline folding with the generic kernels (`pipeline::PipelineFold`, `pipeline::verify`), ACVM witness solving (`witness`), Chonk prove / verify / key derivation (`chonk`), SRS loading (`srs`), and `Frozen<S>`: a generated registry as `Artifacts`, bytecode from an `ArtifactStore` (`DirStore`, `BundledStore`, `LayerStore`, `HttpStore`) checked against its pinned SHA-256. |
| `noir-zk-kernels` | The generic pipeline kernels (`kernel_init`, `kernel_step`, `kernel_tail`, `kernel_hiding`): Noir source, frozen keys and bundled bytecode, versioned with noir-zk. |
| `noir-zk-cli` | `noir-zk freeze`: mints circuit versions from nargo output, reads each circuit's proof system off its ABI, derives its key and its key hash, and keeps the families and pipelines you declare. |
| `noir-zk-fixtures` | Test-only: a small UltraHonk circuit frozen and bound like a consumer's, proved end to end (`mise run fixtures` refreezes it). |

## Using it from a circuit repository

1. Compile the circuits (`nargo compile --workspace`). For hand-written Chonk kernels checking one key tree, also build that tree (`vk-tree.json`: `root`, and `leaves` with `package`, `vk_hash`, `index`, `siblings`); pipelines folded by the generic kernels need none (below).
2. Freeze them into a bindings crate:

   ```sh
   cargo install --locked noir-zk-cli
   noir-zk freeze --target target --out rust/my-zk --assets target/release-assets --library my-lib@1.0.0 [--vk-tree vk-tree.json] [--exclude bench_]
   ```

   The bindings crate then holds `circuits/manifest.toml` and `resources/` (ABIs, keys, the tree). The bytecode goes to `--assets` as `<label>@<version>.b64`, to be uploaded as release assets. It is too large for git.
3. Generate the bindings in that crate's `build.rs`:

   ```toml
   [dependencies]
   noir-zk-core = "0.2"
   noir-zk-backend = "0.2"   # features: "http" (HttpStore), "packs" (circuit packs)

   [build-dependencies]
   noir-zk-codegen = "0.2"
   ```

   Keep the three on one version: they pin each other exactly.

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

## Layers, families and pipelines

A circuit library that wants its circuits folded by others, or that folds circuits of others, declares them in its manifest as *layers* of *families* and *pipelines*, and folds them with the generic kernels of `noir-zk-kernels` instead of writing its own. No key tree file is involved: every root is computed from the pinned keys, in `build.rs` and again at run time.

**Families.** A family is one or more circuits that return the same record through the databus (a single-circuit family is normal). A `[[family]]` table in `circuits/manifest.toml` names it, lists its members (labels, or `prefix*` over the registry's active circuits), and declares its *kernel step*: which record index continues the pipeline's link and the link's type name (`link_in`), which index becomes the next link (`link_out`), which indices must equal public slots earlier positions published (`binds`, by slot name), and which contiguous range is public with its slot names (`public_from`, `slots`).

```toml
[library]            # written by `noir-zk freeze --library my-lib@1.0.0`
name = "my-lib"
version = "1.0.0"

[[family]]
layer = "base"
name = "counter"
members = ["counter_*"]
link_in = { index = 0, link = "Seed" }
link_out = { index = 1, link = "Count" }
public_from = 2
slots = ["n"]

[[family]]           # a family of another registry, wrapped
layer = "ext"
name = "sum"
source = "lib-b"     # a name passed to codegen, or a file written by `noir_zk_codegen::wrapped`
                     # (members, links, bindings and slots come with it)

[[pipeline]]
name = "seed_count_sum"
positions = ["my-lib/base/seed", "my-lib/base/counter", "lib-b/ext/sum"]
```

**Trees, domain-separated.** A family's root is `H("noir-zk/family/v1", H(library, version, layer, family), tree)` where `tree` is a Poseidon2 Merkle tree of height 8 over the sorted key hashes of its members: the same circuit in two libraries or versions gives different roots, and a one-circuit family is a one-leaf tree with that prefix. A pipeline's tree (height 4) has one leaf per position, `H("noir-zk/position/v1", position, family_root, H(layout))`, and the kernels' family at the last leaf; a registry's *deployment* tree (height 4) is over the pipeline roots it declares, in order. Limits: 256 circuits per family, 15 positions per pipeline, 16 pipelines per deployment; the kernels' state has 24 public slots, records at most 16 fields, a position at most 2 bindings.

**Kernels.** `kernel_step` folds the previous kernel and the app at the state's position: it checks the app's key in its family tree (with the family's identity, giving the family root) and the family at that position with that layout in the pipeline tree, then applies the layout (link check, bindings, the public range appended to the slots). `kernel_init` does the same for the first app (Chonk's first proof) and takes the pipeline root; `kernel_hiding` proves the pipeline root is a leaf of the deployment tree and publishes `deployment_root`, `pipeline_root`, `length` (the positions folded) and the slots; `kernel_tail` only pads a one-app pipeline to Chonk's minimum of four circuits. They are frozen in `noir-zk-kernels` (bytecode bundled), and every pipeline tree commits to their family.

**Codegen.** From the manifest, `generate_registry` emits, besides the per-circuit types: `LIBRARY`; `FAMILIES` and one marker type per family (`families::KernelStep<Name>`, a `StepFamily` with the family's record type and link types); `links` (unit types for the link names); `pipelines::<name>` with `ROOT`, `PIPELINE`, an `Outputs` struct with a field per slot, `fold(&dyn Artifacts)` and `verify(&FoldedProof) -> Outputs`; `DEPLOYMENT` and `DEPLOYMENT_ROOT`; and a test that recomputes every root at run time. Roots are computed in `build.rs` with the same Poseidon2 as the runtime (`noir_zk_core::tree`). A combining crate wraps other libraries' registries with `noir_zk_codegen::wrapped(LIBRARY, REGISTRY, FAMILIES)` from its `build.rs` (`Options::sources`), or from a file for a registry frozen with an older noir-zk (a tool derives the key hashes and commits it).

**Folding.** The pool a fold draws from is `Merged::new(&[&lib_a, &lib_b, &Kernels])`, a lookup taking the first store that has a circuit (so a registry whose labels shadow another's, or the kernels when a registry carries its own `kernel_*` circuits, goes first); the chain is typed by the families' links:

```rust
let (proof, _) = seed_count_sum::fold(&pool)?
    .app(KernelStepSeed::select("seed", seed_toml)?)?
    .app(KernelStepCounter::select("counter_big", counter_toml)?)?   // any member, chosen at run time
    .app(KernelStepSum::select("sum", sum_toml)?)?
    .hiding(&DEPLOYMENT)?;
let out = seed_count_sum::verify(&proof)?;   // out.n, out.total: the slots by name
```

`.app(..)` compiles only if the family's `LinkIn` accepts the link the previous position left (`Seed` after a seed, `Count` after a counter; `NoLink` accepts anything); a wrong family for the position, a member outside the family, a wrong link value or binding value is refused at run time (the kernel's witness is unsatisfiable, so no proof exists). `examples/pipelines` is a workspace of two toy libraries and a combining crate with three pipelines, folded and verified in-process (`NOIR_ZK_PROVE=1 cargo test`), with the compile-fail cases as doctests.

**Loading strategies.** A registry's bytecode comes from an `ArtifactStore`: `BundledStore(ASSETS)` (codegen's `Options::bundle` includes the bytecode of the named layers with `include_bytes!`), `DirStore` (a directory of assets or an unpacked pack), `HttpStore` (feature `http`) or packs from a catalog host (`pack::ensure`, features `packs` + `http`, checked against the catalog and then the pins), a `LayerStore` routing each layer to its own store, or any type implementing `ArtifactStore` (runtime injection).

**Verifier contract.** A verifier pins one deployment root and the hiding kernel's key. A proof's first public field is the deployment root, the second the pipeline root (which identifies the slot layout: `pipelines::<name>::verify` checks it against the pipeline's constant), the third the length, then the slots. Adding a variant to a family changes that family's root and every pipeline root using it; adding a pipeline changes the deployment root only.

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
