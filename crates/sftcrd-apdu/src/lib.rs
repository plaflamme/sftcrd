//! Shared APDU command, response, and tracing utilities for `sftcrd` applets.

mod apdu;
mod trace;

pub use apdu::{CommandView, Response};
pub use trace::Trace;
