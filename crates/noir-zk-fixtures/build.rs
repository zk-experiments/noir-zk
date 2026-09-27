//! Bindings of the frozen fixtures (`mise run fixtures` refreezes them).
fn main() {
    let dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    std::fs::write(
        out.join("circuits.rs"),
        noir_zk_codegen::generate_registry(&dir),
    )
    .unwrap_or_else(|e| panic!("circuits.rs: {e}"));
    println!("cargo:rerun-if-changed=circuits/manifest.toml");
    println!("cargo:rerun-if-changed=resources");
}
