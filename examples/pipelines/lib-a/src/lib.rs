//! `lib-a`: a toy circuit library frozen with `noir-zk freeze` and bound by
//! `noir-zk-codegen`; its families are declared in `circuits/manifest.toml`.

#[allow(missing_docs, clippy::all)]
pub mod circuits {
    include!(concat!(env!("OUT_DIR"), "/circuits.rs"));
}

/// This library's circuits as artifacts, bytecode bundled.
pub fn artifacts() -> noir_zk_backend::Frozen<noir_zk_backend::BundledStore> {
    noir_zk_backend::Frozen::layered(circuits::REGISTRY, circuits::FAMILIES, noir_zk_backend::BundledStore(circuits::ASSETS))
}
