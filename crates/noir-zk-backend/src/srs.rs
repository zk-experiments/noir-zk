//! The structured reference strings bb needs for Chonk: BN254 G1 points (for
//! the circuits, up to 2^20 + 1 points) and Grumpkin points (for the ECCVM).
//!
//! Ported from `pso-zk-backend`'s SRS loader: points come from a local file
//! (an explicit path, `$BB_CRS_PATH`, or bb's own cache `~/.bb-crs`), and the
//! exact prefix handed to bb is checked against a pinned SHA-256 first, so a
//! poisoned cache can't seed a setup that accepts forged proofs. Unlike the
//! psonet loader there is no network fallback: provision the files (bb
//! downloads them on first use; a mobile app bundles them).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use barretenberg_rs::api::BarretenbergApi;
use barretenberg_rs::backends::FfiBackend;
use sha2::{Digest, Sha256};

use noir_zk_core::Error;

/// BN254 G1 points: the largest circuit's dyadic size (2^20) plus one.
pub const BN254_POINTS: u32 = (1 << 20) + 1;
/// Grumpkin points for the ECCVM.
pub const GRUMPKIN_POINTS: u32 = 1 << 15;

/// SHA-256 of the first `BN254_POINTS` points of Aztec's `g1.dat` (the same
/// digest psonet pins).
const BN254_SHA256: &str = "0f238856e55722f15a4d64ef0de12b4260e218245590bd3a6c900aee188de8e5";
/// SHA-256 of the first `GRUMPKIN_POINTS` points of bb's `grumpkin_g1_v2.flat.dat`.
const GRUMPKIN_SHA256: &str = "72b8cdad9da82b666987e5fe6f5a0804e3a9b5ba750aa5d451b514442fe157b2";

/// The BN254 G2 point (fixed; Aztec's `g2.dat`).
const G2: [u8; 128] = [
    1, 24, 196, 213, 184, 55, 188, 194, 188, 137, 181, 179, 152, 181, 151, 78, 159, 89, 68, 7, 59,
    50, 7, 139, 126, 35, 31, 236, 147, 136, 131, 176, 38, 14, 1, 178, 81, 246, 241, 199, 231, 255,
    78, 88, 7, 145, 222, 232, 234, 81, 216, 122, 53, 142, 3, 139, 78, 254, 48, 250, 192, 147, 131,
    193, 34, 254, 189, 163, 192, 192, 99, 42, 86, 71, 91, 66, 20, 229, 97, 94, 17, 230, 221, 63,
    150, 230, 206, 162, 133, 74, 135, 212, 218, 204, 94, 85, 4, 252, 99, 105, 247, 17, 15, 227,
    210, 81, 86, 193, 187, 154, 114, 133, 156, 242, 160, 70, 65, 249, 155, 164, 238, 65, 60, 128,
    218, 106, 95, 228,
];

/// Where the two point files are.
#[derive(Clone, Debug)]
pub struct SrsPaths {
    /// BN254 G1 points (`bn254_g1.dat`).
    pub bn254: PathBuf,
    /// Grumpkin points (`grumpkin_g1_v2.flat.dat`).
    pub grumpkin: PathBuf,
}

impl SrsPaths {
    /// `$BB_CRS_PATH` if set, else bb's cache `~/.bb-crs`.
    pub fn default_location() -> Self {
        let dir = std::env::var_os("BB_CRS_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(&std::env::var_os("HOME").unwrap_or_default()).join(".bb-crs")
            });
        Self {
            bn254: dir.join("bn254_g1.dat"),
            grumpkin: dir.join("grumpkin_g1_v2.flat.dat"),
        }
    }
}

static PATHS: OnceLock<SrsPaths> = OnceLock::new();
static LOADED: OnceLock<()> = OnceLock::new();

/// Point the loader at explicit files (a mobile app's bundled assets). Call
/// once before the first proof or verification; later calls are ignored.
pub fn set_srs_paths(paths: SrsPaths) {
    let _ = PATHS.set(paths);
}

fn read_prefix(path: &Path, points: u32, pinned: &str) -> Result<Vec<u8>, Error> {
    let need = points as usize * 64;
    let bytes =
        std::fs::read(path).map_err(|e| Error::Artifact(format!("SRS {}: {e}", path.display())))?;
    let prefix = bytes.get(..need).ok_or_else(|| {
        Error::Artifact(format!(
            "SRS {} has {} bytes, need {need}",
            path.display(),
            bytes.len()
        ))
    })?;
    let digest = hex::encode(Sha256::digest(prefix));
    if digest != pinned {
        return Err(Error::Artifact(format!(
            "SRS {} does not match its pinned hash (tampered?): {digest}",
            path.display()
        )));
    }
    Ok(prefix.to_vec())
}

/// Loads both setups into bb, once per process (bb's CRS is process-global
/// and one-shot). The caller holds the backend lock.
pub(crate) fn ensure(api: &mut BarretenbergApi<FfiBackend>) -> Result<(), Error> {
    if LOADED.get().is_some() {
        return Ok(());
    }
    let paths = PATHS
        .get()
        .cloned()
        .unwrap_or_else(SrsPaths::default_location);
    let g1 = read_prefix(&paths.bn254, BN254_POINTS, BN254_SHA256)?;
    api.srs_init_srs(&g1, BN254_POINTS, &G2)
        .map_err(|e| Error::Proof(format!("bb SRS init: {e}")))?;
    let grumpkin = read_prefix(&paths.grumpkin, GRUMPKIN_POINTS, GRUMPKIN_SHA256)?;
    api.srs_init_grumpkin_srs(&grumpkin, GRUMPKIN_POINTS)
        .map_err(|e| Error::Proof(format!("bb Grumpkin SRS init: {e}")))?;
    let _ = LOADED.set(());
    Ok(())
}
