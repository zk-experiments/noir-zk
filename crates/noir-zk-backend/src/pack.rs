//! Circuit packs: `.tar.gz` archives of bytecode assets
//! (`<label>@<version>.b64`), so a prover fetches a group of circuits at once
//! (`noir-zk pack` writes them). A pack is only transport: unpack it into a
//! directory and read it with [`DirStore`](crate::store::DirStore); `Frozen`
//! still checks every asset against its pinned hash. Feature `packs`.

use std::io::{Read, Write};
use std::path::Path;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;

use noir_zk_core::Error;

fn io(what: &str) -> impl Fn(std::io::Error) -> Error + '_ {
    move |e| Error::Artifact(format!("{what}: {e}"))
}

/// Whether `name` is an asset name a pack may hold: `<label>@<version>.b64`,
/// a bare file name.
fn is_asset_name(name: &str) -> bool {
    name.ends_with(".b64")
        && name.contains('@')
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.@".contains(&b))
}

/// Writes `assets` (name, bytes) as a pack. The archive is deterministic:
/// sorted, with fixed metadata, so the same assets give the same bytes.
pub fn write_pack(assets: &[(String, Vec<u8>)], out: impl Write) -> Result<(), Error> {
    let mut sorted: Vec<&(String, Vec<u8>)> = assets.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut tar = tar::Builder::new(GzEncoder::new(out, Compression::best()));
    for (name, bytes) in sorted {
        if !is_asset_name(name) {
            return Err(Error::Artifact(format!("{name}: not an asset name")));
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

/// Unpacks a pack into `dir` and returns the asset names written. Only plain
/// asset files with bare names are accepted: no directories, links or paths.
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
        if entry.header().entry_type() != tar::EntryType::Regular || !is_asset_name(&name) {
            return Err(Error::Artifact(format!(
                "pack entry {name:?} is not a plain asset file"
            )));
        }
        let mut bytes = vec![];
        entry.read_to_end(&mut bytes).map_err(io(&name))?;
        std::fs::write(dir.join(&name), bytes).map_err(io(&name))?;
        names.push(name);
    }
    Ok(names)
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
        for bad in ["../x@1.b64", "d/x@1.b64", "x.b64", ".x@1.b64", "x@1.txt"] {
            assert!(!is_asset_name(bad), "{bad}");
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
