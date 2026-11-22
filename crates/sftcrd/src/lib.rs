//! Software smartcard server presenting PIV and `OpenPGP` applets via
//! direct PC/SC (IFD Unix socket) or `VSmartCard` (TCP).
//!
//! This crate provides the `sftcrd` binary and its transport-agnostic
//! [`CardSession`] abstraction.
//!
//! # Architecture
//!
//! This crate contains the server infrastructure:
//!
//! - `sftcrd pcscd`: Unix domain socket listener speaking [`sftcrd_ifd_proto`]
//!   (with systemd socket activation support)
//! - `sftcrd vpcd`: TCP listener speaking the `VSmartCard` protocol
//! - APDU dispatch between the host and the [`sftcrd_piv`] / [`sftcrd_pgp`]
//!   applets
//! - Power state management

pub mod pcscd;
pub mod session;
pub mod vpcd;

use serde::Deserialize;
pub use session::{CardChannels, CardSession, TransmitError};
use sftcrd_pgp::PgpConfig;
pub use sftcrd_pgp::PgpApplet;
use sftcrd_piv::PivConfig;
pub use sftcrd_piv::{DEFAULT_SERIAL, PivApplet};
use toml_example::TomlExample;

/// Top-level card configuration holding applet namespaces.
#[derive(TomlExample, Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct CardConfig {
    /// Card serial number.
    #[toml_example(default = 87_654_321, require)]
    pub serial: Option<u32>,
    /// PIV applet configuration.
    #[toml_example(nesting, require)]
    pub piv: Option<PivConfig>,
    /// `OpenPGP` Card applet configuration.
    #[toml_example(nesting, require)]
    pub pgp: Option<PgpConfig>,
}
