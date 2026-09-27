//! Where frozen bytecode comes from. Every fetch is checked against the
//! registry's pinned hash by [`Canonical`](crate::Canonical), so a store only
//! has to return bytes.

use std::path::PathBuf;

use noir_zk_core::Error;

/// A source of release assets (`<label>@<version>.b64`).
pub trait ArtifactStore {
    /// The asset's bytes.
    fn fetch(&self, asset: &str) -> Result<Vec<u8>, Error>;
}

/// A local directory of release assets (a download of a release, or
/// `target/release-assets` after `cargo xtask freeze-circuits`).
pub struct DirStore(pub PathBuf);

impl ArtifactStore for DirStore {
    fn fetch(&self, asset: &str) -> Result<Vec<u8>, Error> {
        std::fs::read(self.0.join(asset)).map_err(|e| Error::Artifact(format!("{asset}: {e}")))
    }
}

/// Release assets over HTTPS: `<base>/<asset>` (for example a GitHub release's
/// download URL). Feature `http`.
#[cfg(feature = "http")]
pub struct HttpStore(pub String);

#[cfg(feature = "http")]
impl ArtifactStore for HttpStore {
    fn fetch(&self, asset: &str) -> Result<Vec<u8>, Error> {
        let url = format!("{}/{asset}", self.0.trim_end_matches('/'));
        let mut resp = ureq::get(&url)
            .call()
            .map_err(|e| Error::Artifact(format!("{url}: {e}")))?;
        resp.body_mut()
            .with_config()
            .limit(64 << 20)
            .read_to_vec()
            .map_err(|e| Error::Artifact(format!("{url}: {e}")))
    }
}
