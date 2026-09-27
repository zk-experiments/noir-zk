//! Records the toolchain pins from `mise.toml` for the manifest.
fn main() {
    let mise = std::fs::read_to_string("../mise.toml").unwrap_or_default();
    let pin = |key: &str| {
        mise.lines()
            .find_map(|l| {
                l.strip_prefix(&format!("{key} = \""))
                    .and_then(|v| v.strip_suffix('"'))
            })
            .unwrap_or("unknown")
            .to_string()
    };
    println!("cargo:rustc-env=NOIR_VERSION_PIN={}", pin("NOIR_VERSION"));
    println!("cargo:rustc-env=BB_VERSION_PIN={}", pin("BB_VERSION"));
    println!("cargo:rerun-if-changed=../mise.toml");
}
