//! Smartcard server for PIV applet via `VSmartCard` protocol.
//!
//! This crate provides the `sftcrd` binary that acts as a `VSmartCard` server,
//! presenting a PIV applet as a PC/SC card. It listens on a TCP port and
//! handles the low-level APDU protocol for the [`sftcrd_piv`] applet.
//!
//! # Architecture
//!
//! This crate contains only the server infrastructure:
//!
//! - TCP listener for `VSmartCard` protocol
//! - APDU dispatch between the host and the PIV applet
//! - Power state management
//!
//! The PIV applet implementation lives in the [`sftcrd_piv`] crate.

pub mod session;

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
