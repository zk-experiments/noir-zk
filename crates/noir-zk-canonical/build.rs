//! Generates the frozen registry with `noir-zk-codegen`. Read-only: it never
//! runs nargo or bb; `cargo xtask freeze-circuits` mints versions.

fn main() {
    let dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("out dir"));
    for p in [
        "circuits/manifest.toml",
        "resources/vk-tree.json",
        "resources/circuits",
    ] {
        println!("cargo:rerun-if-changed={p}");
    }
    let code = noir_zk_codegen::generate_registry(&dir);
    std::fs::write(out.join("circuits.rs"), code).expect("write circuits.rs");
}
