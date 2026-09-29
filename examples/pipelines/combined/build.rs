//! The combining crate wraps the two libraries' registries (their circuits'
//! key hashes and their families) straight from their generated code, and
//! declares the pipelines in `circuits/manifest.toml`.
fn main() {
    let dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let options = noir_zk_codegen::Options {
        bundle: vec![],
        sources: vec![
            ("lib-a".into(), noir_zk_codegen::wrapped(lib_a::circuits::LIBRARY, lib_a::circuits::REGISTRY, lib_a::circuits::FAMILIES)),
            ("lib-b".into(), noir_zk_codegen::wrapped(lib_b::circuits::LIBRARY, lib_b::circuits::REGISTRY, lib_b::circuits::FAMILIES)),
        ],
    };
    std::fs::write(out.join("circuits.rs"), noir_zk_codegen::generate_registry_with(&dir, &options)).unwrap();
    println!("cargo:rerun-if-changed=circuits/manifest.toml");
}
