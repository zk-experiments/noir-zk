//! Where frozen bytecode comes from. Every fetch is checked against the
//! registry's pinned hash by [`Frozen`](crate::frozen::Frozen), so a store only
//! has to return bytes.

use std::path::PathBuf;

use noir_zk_core::Error;

/// A source of release assets (`<label>@<version>.b64`).
pub trait ArtifactStore {
    /// The asset's bytes.
    fn fetch(&self, asset: &str) -> Result<Vec<u8>, Error>;
}

/// Assets compiled into the binary: `(asset name, bytes)` pairs, as
/// `include_bytes!` gives them (codegen's `bundled` option writes the table).
pub struct BundledStore(pub &'static [(&'static str, &'static [u8])]);

impl ArtifactStore for BundledStore {
    fn fetch(&self, asset: &str) -> Result<Vec<u8>, Error> {
        self.0
            .iter()
            .find(|(name, _)| *name == asset)
            .map(|(_, bytes)| bytes.to_vec())
            .ok_or_else(|| Error::Artifact(format!("{asset} is not bundled")))
    }
}

/// One store per layer: an asset is looked up in the store of the layer its
/// circuit belongs to (by label, through `layers`), so a registry can bundle
/// one layer, read another from a directory and fetch a third.
pub struct LayerStore {
    layers: Vec<(String, Box<dyn ArtifactStore>)>,
    /// `label -> layer`.
    of: fn(&str) -> Option<&'static str>,
}

impl LayerStore {
    /// `of` maps a circuit label to its layer (codegen generates `layer_of`).
    pub fn new(of: fn(&str) -> Option<&'static str>) -> Self {
        Self { layers: vec![], of }
    }

    /// Adds `store` for `layer`.
    #[must_use]
    pub fn layer(mut self, layer: &str, store: impl ArtifactStore + 'static) -> Self {
        self.layers.push((layer.to_string(), Box::new(store)));
        self
    }
}

impl ArtifactStore for LayerStore {
    fn fetch(&self, asset: &str) -> Result<Vec<u8>, Error> {
        let label = asset.split('@').next().unwrap_or(asset);
        let layer = (self.of)(label)
            .ok_or_else(|| Error::Artifact(format!("{asset}: not a circuit of any layer")))?;
        self.layers
            .iter()
            .find(|(l, _)| l == layer)
            .ok_or_else(|| Error::Artifact(format!("{asset}: no store for layer {layer}")))?
            .1
            .fetch(asset)
    }
}

/// A local directory of release assets (a download of a release, or
/// the `--assets` directory of `noir-zk freeze`).
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
