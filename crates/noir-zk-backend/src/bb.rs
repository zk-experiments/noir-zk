//! The one bb instance: bb's CRS and prover are process-global C++ state and
//! not reentrant, so every call is serialised by one lock, as in psonet's
//! backend.

use std::sync::{Mutex, MutexGuard};

use barretenberg_rs::api::BarretenbergApi;
use barretenberg_rs::backends::FfiBackend;

use noir_zk_core::Error;

static BB_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn bb() -> Result<(MutexGuard<'static, ()>, BarretenbergApi<FfiBackend>), Error> {
    let guard = BB_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let backend = FfiBackend::new().map_err(|e| Error::Proof(format!("bb init: {e}")))?;
    Ok((guard, BarretenbergApi::new(backend)))
}

pub(crate) fn bb_err(
    what: &str,
) -> impl Fn(barretenberg_rs::error::BarretenbergError) -> Error + '_ {
    move |e| Error::Proof(format!("bb {what}: {e}"))
}
