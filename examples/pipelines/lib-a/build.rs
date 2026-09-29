fn main() {
    let dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    // Bundle every layer's bytecode: the circuits are tiny.
    let options = noir_zk_codegen::Options { bundle: vec!["*".into()], sources: vec![] };
    std::fs::write(out.join("circuits.rs"), noir_zk_codegen::generate_registry_with(&dir, &options)).unwrap();
    println!("cargo:rerun-if-changed=circuits/manifest.toml");
    println!("cargo:rerun-if-changed=resources");
    println!("cargo:rerun-if-changed=assets");
}
