//! Fixtures for noir-zk's own end-to-end tests: `noir/` compiled with the
//! pinned nargo, frozen into `circuits/`, `resources/` and `assets/` by
//! `noir-zk freeze`, and bound by `noir-zk-codegen` below.

/// Generated from the frozen fixtures.
#[allow(missing_docs, clippy::all)]
pub mod circuits {
    include!(concat!(env!("OUT_DIR"), "/circuits.rs"));
}

/// The frozen bytecode assets.
pub const ASSETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/assets");
