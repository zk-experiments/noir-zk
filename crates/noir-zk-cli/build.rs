//! Records the bb version (the linked barretenberg-rs) for the manifest.
fn main() {
    let mise = std::fs::read_to_string("../../mise.toml").unwrap_or_default();
    let bb = mise
        .lines()
        .find_map(|l| l.strip_prefix("BB_VERSION = \"")?.strip_suffix('"'))
        .unwrap_or("unknown");
    println!("cargo:rustc-env=BB_VERSION_PIN={bb}");
    println!("cargo:rerun-if-changed=../../mise.toml");
}
