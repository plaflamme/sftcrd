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

pub use sftcrd_piv::{DEFAULT_SERIAL, PivApplet};
