//! PC/SC-Lite [IFD Handler](https://pcsclite.apdu.fr/api/group__IFDHandler.html#details) v3 shared library (`libsftcrd_ifd.so`) connecting
//! `pcscd` directly to the `sftcrd` daemon over a Unix domain socket.
//!
//! # Architecture
//!
//! `pcscd` loads this shared library via `reader.conf` (`LIBPATH`) and passes
//! the Unix socket path via `DEVICENAME` to [`IFDHCreateChannelByName`]. Each
//! IFD handler call maps to a single synchronous [`sftcrd_ifd_proto`] TLV
//! request/response round-trip over the Unix stream.
//!
//! If the `sftcrd` daemon is unavailable or restarts, [`IFDHICCPresence`]
//! reports [`abi::IFD_ICC_NOT_PRESENT`] and drops any stale socket handle so
//! `pcscd` observes card removal and cleanly reconnects and re-powers the card
//! once the daemon returns.

pub mod abi;
mod channel;
pub mod ffi;

pub use channel::DEFAULT_SOCKET_PATH;
pub use ffi::*;
