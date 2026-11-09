//! NBT-AAD Manager safety core.
//!
//! Platform-independent and sans-IO: no network, process or filesystem side
//! effects. Transports and storage are traits implemented by adapters
//! (desktop CLI now, Android later). NOT READY FOR VEHICLE USE beyond the
//! read-only probe.

pub mod guard;
pub mod inspect;
pub mod journal;
pub mod kexinit;
pub mod plan;
pub mod probe;
pub mod profile;
pub mod redact;
pub mod release;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod transport;
