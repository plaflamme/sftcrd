//! PC/SC-Lite [IFD Handler](https://pcsclite.apdu.fr/api/group__IFDHandler.html#details) v3 C ABI types and constants.
//!
//! Matches `<PCSC/wintypes.h>`, `<PCSC/pcsclite.h>`, and `<PCSC/ifdhandler.h>`
//! from `pcsc-lite`.

use std::ffi::c_char;
#[cfg(not(target_os = "macos"))]
use std::ffi::{c_long, c_ulong};

/// PC/SC-Lite `DWORD` type (`unsigned long` on Linux, `uint32_t` on macOS).
#[cfg(not(target_os = "macos"))]
pub type Dword = c_ulong;

/// PC/SC-Lite `DWORD` type (`uint32_t` on macOS).
#[cfg(target_os = "macos")]
pub type Dword = u32;

/// PC/SC-Lite `RESPONSECODE` type (`long` on Linux, `int32_t` on macOS).
#[cfg(not(target_os = "macos"))]
pub type ResponseCode = c_long;

/// PC/SC-Lite `RESPONSECODE` type (`int32_t` on macOS).
#[cfg(target_os = "macos")]
pub type ResponseCode = i32;

/// PC/SC-Lite `UCHAR` type.
pub type Uchar = u8;

/// PC/SC-Lite `LPCSTR` / `LPSTR` pointer type for read-only C strings.
pub type Lpcstr = *const c_char;

/// Maximum ATR length defined by `pcsc-lite` (`MAX_ATR_SIZE`).
pub const MAX_ATR_SIZE: usize = 33;

/// `SCARD_IO_HEADER` passed to `IFDHTransmitToICC`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SCardIoHeader {
    /// Active protocol (`SCARD_PROTOCOL_T0`, `SCARD_PROTOCOL_T1`, etc.).
    pub protocol: Dword,
    /// Header length (unused by `pcsc-lite` IFD handlers).
    pub length: Dword,
}

// Capability tags (`IFDHGetCapabilities` / `IFDHSetCapabilities`).
/// Request the card's ATR (`TAG_IFD_ATR`).
pub const TAG_IFD_ATR: Dword = 0x0303;
/// Microsoft PC/SC `SCARD_ATTR_ATR_STRING` alias for ATR.
pub const SCARD_ATTR_ATR_STRING: Dword = 0x0009_0303;
/// Whether slots of the same reader can be accessed concurrently.
pub const TAG_IFD_SLOT_THREAD_SAFE: Dword = 0x0FAC;
/// Whether multiple readers can be accessed concurrently.
pub const TAG_IFD_THREAD_SAFE: Dword = 0x0FAD;
/// Number of card slots in this reader.
pub const TAG_IFD_SLOTS_NUMBER: Dword = 0x0FAE;
/// Number of simultaneous reader instances supported by the driver.
pub const TAG_IFD_SIMULTANEOUS_ACCESS: Dword = 0x0FAF;

// Power actions (`IFDHPowerICC`).
/// Cold power-up of the card.
pub const IFD_POWER_UP: Dword = 500;
/// Power-down of the card.
pub const IFD_POWER_DOWN: Dword = 501;
/// Warm reset of the card.
pub const IFD_RESET: Dword = 502;

// Protocol identifiers (`IFDHSetProtocolParameters` / `SCARD_IO_HEADER`).
/// T=0 protocol.
pub const SCARD_PROTOCOL_T0: Dword = 0x0001;
/// T=1 protocol.
pub const SCARD_PROTOCOL_T1: Dword = 0x0002;

// IFD handler return codes (`RESPONSECODE`).
/// Operation succeeded.
pub const IFD_SUCCESS: ResponseCode = 0;
/// Requested capability tag is unknown.
pub const IFD_ERROR_TAG: ResponseCode = 600;
/// Requested protocol is not supported.
pub const IFD_PROTOCOL_NOT_SUPPORTED: ResponseCode = 607;
/// Error powering up or resetting the card.
pub const IFD_ERROR_POWER_ACTION: ResponseCode = 608;
/// Generic communication error with the reader or daemon.
pub const IFD_COMMUNICATION_ERROR: ResponseCode = 612;
/// Requested operation is not supported.
pub const IFD_NOT_SUPPORTED: ResponseCode = 614;
/// Card is present in the reader.
pub const IFD_ICC_PRESENT: ResponseCode = 615;
/// Card is absent from the reader.
pub const IFD_ICC_NOT_PRESENT: ResponseCode = 616;
/// Caller-provided output buffer is too small.
pub const IFD_ERROR_INSUFFICIENT_BUFFER: ResponseCode = 618;
