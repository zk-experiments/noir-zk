//! Circuit packs: self-contained `.tar.gz` archives of a group of circuits,
//! so a prover fetches them at once (`noir-zk pack` writes them). Per
//! circuit: `<label>@<version>.b64` (bytecode), `.vk` (verification key) and
//! `.abi.json`; plus `vk-tree.json` (the key tree) and `manifest.toml` (the
//! included entries with their pinned hashes). A pack is only transport:
//! unpack it into a directory and read it with
//! [`DirStore`](crate::store::DirStore); `Frozen` still checks every asset
//! against its pinned hash. Feature `packs`.

use std::io::{Read, Write};
use std::path::Path;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

#[cfg(feature = "http")]
use crate::store::ArtifactStore as _;
use noir_zk_core::Error;

fn io(what: &str) -> impl Fn(std::io::Error) -> Error + '_ {
    move |e| Error::Artifact(format!("{what}: {e}"))
}

/// Whether `name` may be a pack entry: a bare file name, either
/// `<label>@<version>` with `.b64`, `.vk` or `.abi.json`, or `vk-tree.json` /
/// `manifest.toml`.
fn is_pack_entry(name: &str) -> bool {
    if name == "vk-tree.json" || name == "manifest.toml" {
        return true;
    }
    [".b64", ".vk", ".abi.json"]
        .iter()
        .any(|e| name.ends_with(e))
        && name.contains('@')
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.@".contains(&b))
}

/// Writes `entries` (name, bytes) as a pack. The archive is deterministic:
/// sorted, with fixed metadata, so the same assets give the same bytes.
pub fn write_pack(entries: &[(String, Vec<u8>)], out: impl Write) -> Result<(), Error> {
    let mut sorted: Vec<&(String, Vec<u8>)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut tar = tar::Builder::new(GzEncoder::new(out, Compression::best()));
    for (name, bytes) in sorted {
        if !is_pack_entry(name) {
            return Err(Error::Artifact(format!("{name}: not a pack entry name")));
        }
        let mut h = tar::Header::new_gnu();
        h.set_size(bytes.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut h, name, bytes.as_slice())
            .map_err(io(name))?;
    }
    tar.into_inner()
        .map_err(io("pack"))?
        .finish()
        .map_err(io("pack"))?;
    Ok(())
}

/// Unpacks a pack into `dir` and returns the entry names written. Only plain
/// files with pack entry names are accepted: no directories, links or paths.
pub fn unpack(pack: impl Read, dir: &Path) -> Result<Vec<String>, Error> {
    std::fs::create_dir_all(dir).map_err(io("unpack"))?;
    let mut names = vec![];
    let mut tar = tar::Archive::new(GzDecoder::new(pack));
    for entry in tar.entries().map_err(io("pack"))? {
        let mut entry = entry.map_err(io("pack"))?;
        let name = entry
            .path()
            .map_err(io("pack"))?
            .to_str()
            .map(str::to_string)
            .unwrap_or_default();
        if entry.header().entry_type() != tar::EntryType::Regular || !is_pack_entry(&name) {
            return Err(Error::Artifact(format!(
                "pack entry {name:?} is not a plain pack file"
            )));
        }
        let mut bytes = vec![];
        entry.read_to_end(&mut bytes).map_err(io(&name))?;
        std::fs::write(dir.join(&name), bytes).map_err(io(&name))?;
        names.push(name);
    }
    Ok(names)
}

/// Fetches the packs `wanted` of release `version` from `base` (a catalog
/// host: `<base>/catalog@<version>.json` lists each pack's file and SHA-256;
/// `<base>/<file>` is the archive), checks each archive against the catalog,
/// unpacks it into `dest` and marks it done (`.<pack>@<version>.ok`), so a
/// pack is downloaded once. Returns the packs fetched this time. The host is
/// a mirror, not a trust anchor: check the unpacked files against the
/// registry's pins with [`verify_dir`](crate::frozen::verify_dir). Feature
/// `http`.
#[cfg(feature = "http")]
pub fn ensure(
    base: &str,
    version: &str,
    dest: &Path,
    wanted: &[&str],
) -> Result<Vec<String>, Error> {
    use sha2::{Digest, Sha256};
    std::fs::create_dir_all(dest).map_err(io("packs dir"))?;
    let fetch = |file: &str| crate::store::HttpStore(base.to_string()).fetch(file);
    let mut downloaded = vec![];
    let mut catalog: Option<serde_json::Value> = None;
    for pack in wanted {
        if dest.join(format!(".{pack}@{version}.ok")).exists() {
            continue;
        }
        if catalog.is_none() {
            let bytes = fetch(&format!("catalog@{version}.json"))?;
            catalog = Some(
                serde_json::from_slice(&bytes)
                    .map_err(|e| Error::Artifact(format!("catalog@{version}.json: {e}")))?,
            );
        }
        let cat = catalog.as_ref().unwrap_or(&serde_json::Value::Null);
        let entry = &cat["packs"][*pack];
        let file = entry["file"]
            .as_str()
            .ok_or_else(|| Error::Artifact(format!("no pack {pack} in the catalog")))?;
        let sha = entry["sha256"].as_str().unwrap_or_default();
        let bytes = fetch(file)?;
        if hex::encode(Sha256::digest(&bytes)) != sha {
            return Err(Error::Artifact(format!(
                "{file}: SHA-256 differs from the catalog"
            )));
        }
        unpack(bytes.as_slice(), dest)?;
        std::fs::write(dest.join(format!(".{pack}@{version}.ok")), sha).map_err(io("marker"))?;
        downloaded.push(format!("{file} ({} MB)", bytes.len() / 1_000_000));
    }
    Ok(downloaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_deterministically() {
        let assets = vec![
            ("b@1.0.0.b64".to_string(), b"BBB".to_vec()),
            ("a@1.0.0.b64".to_string(), b"AAA".to_vec()),
        ];
        let (mut one, mut two) = (vec![], vec![]);
        write_pack(&assets, &mut one).unwrap();
        write_pack(&assets.iter().rev().cloned().collect::<Vec<_>>(), &mut two).unwrap();
        assert_eq!(one, two);

        let dir = std::env::temp_dir().join(format!("noir-zk-pack-{}", std::process::id()));
        let names = unpack(one.as_slice(), &dir).unwrap();
        assert_eq!(names, ["a@1.0.0.b64", "b@1.0.0.b64"]);
        assert_eq!(std::fs::read(dir.join("b@1.0.0.b64")).unwrap(), b"BBB");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rejects_paths_and_other_names() {
        for bad in [
            "../x@1.b64",
            "d/x@1.b64",
            "x.b64",
            ".x@1.b64",
            "x@1.txt",
            "vk-tree.json.b64x",
            "../manifest.toml",
        ] {
            assert!(!is_pack_entry(bad), "{bad}");
        }
        for good in [
            "x@1.0.0.b64",
            "x@1.0.0.vk",
            "x@1.0.0.abi.json",
            "vk-tree.json",
            "manifest.toml",
        ] {
            assert!(is_pack_entry(good), "{good}");
        }
        // An archive with a path entry is refused on unpack.
        let mut raw = vec![];
        {
            let mut tar = tar::Builder::new(GzEncoder::new(&mut raw, Compression::fast()));
            let mut h = tar::Header::new_gnu();
            h.set_size(1);
            h.set_mode(0o644);
            h.set_entry_type(tar::EntryType::Regular);
            tar.append_data(&mut h, "sub/x@1.0.0.b64", &b"x"[..])
                .unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }
        let dir = std::env::temp_dir().join(format!("noir-zk-pack-bad-{}", std::process::id()));
        assert!(unpack(raw.as_slice(), &dir).is_err());
        assert!(!dir.join("sub").exists());
        let _ = std::fs::remove_dir_all(dir);
    }
}
