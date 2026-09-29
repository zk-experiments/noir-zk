//! Turns `circuits/manifest.toml` (written by `noir-zk freeze`, with the
//! `[[family]]` of the kernels) into the `KERNELS` table and the kernels'
//! family root, computed with the same Poseidon2 the runtime uses.

use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    println!("cargo:rerun-if-changed=circuits/manifest.toml");
    println!("cargo:rerun-if-changed=resources");
    println!("cargo:rerun-if-changed=assets");
    // Before the first freeze (the CLI that writes the manifest depends on
    // this crate through the backend) the tables are empty.
    let Ok(text) = std::fs::read_to_string(dir.join("circuits/manifest.toml")) else {
        std::fs::write(
            out.join("kernels.rs"),
            "pub const LIBRARY: noir_zk_core::Library = noir_zk_core::Library { name: \"noir-zk-kernels\", version: \"\" };\npub const KERNELS: &[noir_zk_core::RegistryEntry] = &[];\npub const ASSETS: &[(&str, &[u8])] = &[];\npub static FAMILY: noir_zk_core::FamilyEntry = noir_zk_core::FamilyEntry { id: noir_zk_core::FamilyRef { library: \"noir-zk-kernels\", layer: \"kernels\", family: \"step\" }, version: \"\", members: &[], record_fields: 0, link_in: None, link_out: None, binds: &[], consts: &[], public_from: 0, slots: &[], root: [0; 32] };\n",
        )
        .expect("kernels.rs");
        return;
    };
    let manifest: toml::Value = toml::from_str(&text).expect("manifest.toml");
    let library = &manifest["library"];
    let (name, version) = (
        library["name"].as_str().expect("library.name"),
        library["version"].as_str().expect("library.version"),
    );
    let hex32 = |s: &str| -> String {
        let s = s.trim_start_matches("0x");
        let s = format!("{s:0>64}");
        (0..32)
            .map(|i| format!("0x{}", &s[2 * i..2 * i + 2]))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut code = format!(
        "/// The library the kernels are frozen as.\npub const LIBRARY: noir_zk_core::Library = noir_zk_core::Library {{ name: {name:?}, version: {version:?} }};\n/// Every kernel version.\npub const KERNELS: &[noir_zk_core::RegistryEntry] = &[\n"
    );
    let mut hashes = vec![];
    let mut family_members = String::new();
    for c in manifest["circuit"].as_array().expect("[[circuit]]") {
        let label = c["label"].as_str().expect("label");
        let version = c["version"].as_str().expect("version");
        let status = c["status"].as_str().expect("status");
        let role = match c["role"].as_str().expect("role") {
            "kernel" => "Kernel",
            "hiding" => "Hiding",
            r => panic!("{label}: role {r}"),
        };
        let rel = format!("resources/circuits/{label}/{version}");
        let vk_hash = c["vk_hash"].as_str().expect("vk_hash");
        let active = status == "active";
        if active && role == "Kernel" {
            hashes.push(vk_hash.to_string());
            family_members.push_str(&format!("({label:?}, [{}]), ", hex32(vk_hash)));
        }
        code.push_str(&format!(
            "    noir_zk_core::RegistryEntry {{\n        label: {label:?},\n        version: {version:?},\n        system: noir_zk_core::ProofSystem::Chonk(noir_zk_core::ChonkRole::{role}),\n        status: noir_zk_core::Status::{},\n        bytecode_sha256: [{}],\n        vk_sha256: [{}],\n        vk_hash: [{}],\n        layer: \"kernels\",\n        family: {:?},\n        abi: {},\n        vk: include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{rel}/circuit.vk\")),\n        vk_index: None,\n        vk_siblings: &[],\n    }},\n",
            if active { "Active" } else { "Deprecated" },
            hex32(c["bytecode_sha256"].as_str().expect("sha")),
            hex32(c["vk_sha256"].as_str().expect("vk_sha")),
            hex32(vk_hash),
            if role == "Kernel" { "step" } else { "hiding" },
            if active { format!("Some(include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{rel}/abi.json\")))") } else { "None".into() },
        ));
    }
    code.push_str("];\n");
    // The bundled bytecode of the active versions.
    code.push_str("/// The active kernels' bytecode (`<label>@<version>.b64`).\npub const ASSETS: &[(&str, &[u8])] = &[\n");
    for c in manifest["circuit"].as_array().expect("[[circuit]]") {
        if c["status"].as_str() != Some("active") {
            continue;
        }
        let asset = format!(
            "{}@{}.b64",
            c["label"].as_str().expect("label"),
            c["version"].as_str().expect("version")
        );
        code.push_str(&format!("    ({asset:?}, include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/assets/{asset}\"))),\n"));
    }
    code.push_str("];\n");
    // The kernels' family: kernel_init, kernel_step, kernel_tail (the hiding
    // kernel's key is pinned by the verifier instead).
    let fields: Vec<noir_zk_core::Field> = hashes
        .iter()
        .map(|h| {
            noir_zk_core::codec::field_from_be_bytes(
                &hex::decode(h.trim_start_matches("0x")).expect("hex"),
            )
        })
        .collect();
    let id = noir_zk_core::tree::family_id(name, version, "kernels", "step");
    let root =
        noir_zk_core::codec::field_to_be_bytes32(&noir_zk_core::tree::family_root(id, &fields));
    code.push_str(&format!(
        "/// The kernels' family: `{name}/kernels/step` at version {version}.\npub static FAMILY: noir_zk_core::FamilyEntry = noir_zk_core::FamilyEntry {{\n    id: noir_zk_core::FamilyRef {{ library: {name:?}, layer: \"kernels\", family: \"step\" }},\n    version: {version:?},\n    members: &[{family_members}],\n    record_fields: 0,\n    link_in: None,\n    link_out: None,\n    binds: &[],\n    consts: &[],\n    public_from: 0,\n    slots: &[],\n    root: [{}],\n}};\n",
        hex32(&hex::encode(root)),
    ));
    std::fs::write(out.join("kernels.rs"), code).expect("kernels.rs");
}
