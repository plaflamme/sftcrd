//! Thin PC/SC-Lite IFD Handler v3 `extern "C"` entrypoints.
//!
//! Each exported `IFDH*` symbol validates caller pointers and buffer lengths,
//! wraps execution in a panic guard, and delegates to the internal channel
//! manager.

use std::ffi::CStr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::sync::Once;

use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::EnvFilter;

use crate::abi::{
    Dword, IFD_COMMUNICATION_ERROR, IFD_ERROR_INSUFFICIENT_BUFFER, IFD_ERROR_POWER_ACTION,
    IFD_ERROR_TAG, IFD_NOT_SUPPORTED, IFD_POWER_DOWN, IFD_POWER_UP, IFD_RESET, IFD_SUCCESS, Lpcstr,
    ResponseCode, SCARD_ATTR_ATR_STRING, SCardIoHeader, TAG_IFD_ATR, TAG_IFD_SIMULTANEOUS_ACCESS,
    TAG_IFD_SLOT_THREAD_SAFE, TAG_IFD_SLOTS_NUMBER, TAG_IFD_THREAD_SAFE, Uchar,
};
use crate::channel::{ChannelState, channels, resolve_socket_path};

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("sftcrd_ifd=warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init();
    });
}

fn ffi_guard(f: impl FnOnce() -> ResponseCode) -> ResponseCode {
    init_tracing();
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| {
        error!("panic caught across IFD FFI boundary");
        IFD_COMMUNICATION_ERROR
    })
}

fn usize_to_dword(len: usize) -> Option<Dword> {
    Dword::try_from(len).ok()
}

fn dword_to_usize(len: Dword) -> Option<usize> {
    usize::try_from(len).ok()
}

/// Open a channel for `lun` using the `DEVICENAME` from `reader.conf`.
///
/// # Safety
///
/// `device_name` must either be null or point to a valid NUL-terminated C
/// string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn IFDHCreateChannelByName(
    lun: Dword,
    device_name: Lpcstr,
) -> ResponseCode {
    ffi_guard(|| {
        let name = if device_name.is_null() {
            None
        } else {
            // SAFETY: caller guarantees `device_name` is a valid NUL-terminated C string.
            unsafe { CStr::from_ptr(device_name) }.to_str().ok()
        };

        let socket_path = resolve_socket_path(name);
        info!(lun, socket = %socket_path.display(), "IFDHCreateChannelByName");
        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        map.insert(lun, ChannelState::new(socket_path));
        IFD_SUCCESS
    })
}

/// Open a channel for `lun` using the default or `SFTCRD_SOCKET` Unix socket.
#[unsafe(no_mangle)]
pub extern "C" fn IFDHCreateChannel(lun: Dword, channel: Dword) -> ResponseCode {
    ffi_guard(|| {
        let socket_path = resolve_socket_path(None);
        info!(lun, channel, socket = %socket_path.display(), "IFDHCreateChannel");
        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        map.insert(lun, ChannelState::new(socket_path));
        IFD_SUCCESS
    })
}

/// Close the channel for `lun`, powering off the card if connected.
#[unsafe(no_mangle)]
pub extern "C" fn IFDHCloseChannel(lun: Dword) -> ResponseCode {
    ffi_guard(|| {
        info!(lun, "IFDHCloseChannel");
        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        if let Some(state) = map.remove(&lun) {
            state.close();
        }
        IFD_SUCCESS
    })
}

/// Query reader or card capabilities for `lun`.
///
/// # Safety
///
/// `length` must be a valid pointer to a writable `DWORD`, and `value` must
/// point to a writable buffer of at least `*length` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn IFDHGetCapabilities(
    lun: Dword,
    tag: Dword,
    length: *mut Dword,
    value: *mut Uchar,
) -> ResponseCode {
    ffi_guard(|| {
        if length.is_null() || value.is_null() {
            warn!(
                lun,
                tag = format_args!("0x{tag:04x}"),
                "IFDHGetCapabilities: null pointer"
            );
            return IFD_COMMUNICATION_ERROR;
        }

        debug!(lun, tag = format_args!("0x{tag:04x}"), "IFDHGetCapabilities");

        // SAFETY: caller guarantees `length` is valid for reads and writes.
        let Some(cap) = dword_to_usize(unsafe { *length }) else {
            return IFD_COMMUNICATION_ERROR;
        };

        match tag {
            TAG_IFD_SIMULTANEOUS_ACCESS | TAG_IFD_THREAD_SAFE | TAG_IFD_SLOTS_NUMBER => {
                if cap < 1 {
                    return IFD_ERROR_INSUFFICIENT_BUFFER;
                }
                // SAFETY: `value` is non-null and `cap >= 1`.
                unsafe {
                    *value = 1;
                    *length = 1;
                }
                IFD_SUCCESS
            }
            TAG_IFD_SLOT_THREAD_SAFE => {
                if cap < 1 {
                    return IFD_ERROR_INSUFFICIENT_BUFFER;
                }
                // SAFETY: `value` is non-null and `cap >= 1`.
                unsafe {
                    *value = 0;
                    *length = 1;
                }
                IFD_SUCCESS
            }
            TAG_IFD_ATR | SCARD_ATTR_ATR_STRING => {
                let Ok(mut map) = channels().lock() else {
                    return IFD_COMMUNICATION_ERROR;
                };
                let Some(state) = map.get_mut(&lun) else {
                    return IFD_COMMUNICATION_ERROR;
                };

                let atr = match state.get_atr() {
                    Ok(atr) => atr,
                    Err(code) => return code,
                };

                if atr.len() > cap {
                    return IFD_ERROR_INSUFFICIENT_BUFFER;
                }
                let Some(out_len) = usize_to_dword(atr.len()) else {
                    return IFD_COMMUNICATION_ERROR;
                };

                // SAFETY: `value` has at least `cap >= atr.len()` writable bytes.
                unsafe {
                    let out = slice::from_raw_parts_mut(value, atr.len());
                    out.copy_from_slice(atr);
                    *length = out_len;
                }
                IFD_SUCCESS
            }
            _ => IFD_ERROR_TAG,
        }
    })
}

/// Set reader or card capabilities for `lun` (none are writable).
///
/// # Safety
///
/// Matches the PC/SC-Lite `IFDHSetCapabilities` C ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn IFDHSetCapabilities(
    lun: Dword,
    tag: Dword,
    length: Dword,
    _value: *mut Uchar,
) -> ResponseCode {
    ffi_guard(|| {
        debug!(
            lun,
            tag = format_args!("0x{tag:04x}"),
            length,
            "IFDHSetCapabilities (unsupported)"
        );
        IFD_ERROR_TAG
    })
}

/// Negotiate card communication protocol (T=1 or T=0) for `lun`.
#[unsafe(no_mangle)]
pub extern "C" fn IFDHSetProtocolParameters(
    lun: Dword,
    protocol: Dword,
    flags: Uchar,
    _pts1: Uchar,
    _pts2: Uchar,
    _pts3: Uchar,
) -> ResponseCode {
    ffi_guard(|| {
        debug!(lun, protocol, flags, "IFDHSetProtocolParameters");
        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        let Some(state) = map.get_mut(&lun) else {
            return IFD_COMMUNICATION_ERROR;
        };
        state.set_protocol(lun, protocol)
    })
}

/// Power up, power down, or warm-reset the card in `lun`.
///
/// # Safety
///
/// For `IFD_POWER_UP` and `IFD_RESET`, `atr` must point to a writable buffer
/// of at least [`crate::abi::MAX_ATR_SIZE`] bytes and `atr_length` must be a
/// valid writable `DWORD` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn IFDHPowerICC(
    lun: Dword,
    action: Dword,
    atr: *mut Uchar,
    atr_length: *mut Dword,
) -> ResponseCode {
    ffi_guard(|| {
        debug!(lun, action, "IFDHPowerICC");
        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        let Some(state) = map.get_mut(&lun) else {
            return IFD_COMMUNICATION_ERROR;
        };

        match action {
            IFD_POWER_UP | IFD_RESET => {
                if atr.is_null() || atr_length.is_null() {
                    return IFD_ERROR_POWER_ACTION;
                }
                // SAFETY: `atr_length` was checked non-null above.
                unsafe { *atr_length = 0 };

                let bytes = match state.power_up_or_reset(action) {
                    Ok(bytes) => bytes,
                    Err(code) => return code,
                };
                let Some(out_len) = usize_to_dword(bytes.len()) else {
                    return IFD_ERROR_POWER_ACTION;
                };
                // SAFETY: caller guarantees `atr` holds at least `MAX_ATR_SIZE` bytes.
                unsafe {
                    let out = slice::from_raw_parts_mut(atr, bytes.len());
                    out.copy_from_slice(bytes);
                    *atr_length = out_len;
                }
                IFD_SUCCESS
            }
            IFD_POWER_DOWN => {
                state.power_down();
                if !atr_length.is_null() {
                    // SAFETY: `atr_length` was checked non-null.
                    unsafe { *atr_length = 0 };
                }
                IFD_SUCCESS
            }
            _ => IFD_NOT_SUPPORTED,
        }
    })
}

/// Transmit a command APDU to the card in `lun` and receive the response APDU.
///
/// # Safety
///
/// `tx_buffer` must be readable for `tx_length` bytes (when `tx_length > 0`),
/// `rx_length` must be a valid readable/writable `DWORD` pointer, `rx_buffer`
/// must be writable for `*rx_length` bytes (when `*rx_length > 0`), and
/// `recv_pci` must either be null or point to a writable [`SCardIoHeader`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn IFDHTransmitToICC(
    lun: Dword,
    send_pci: SCardIoHeader,
    tx_buffer: *mut Uchar,
    tx_length: Dword,
    rx_buffer: *mut Uchar,
    rx_length: *mut Dword,
    recv_pci: *mut SCardIoHeader,
) -> ResponseCode {
    ffi_guard(|| {
        if rx_length.is_null() {
            return IFD_COMMUNICATION_ERROR;
        }

        // SAFETY: `rx_length` was checked non-null above. Read the caller's
        // capacity and zero it up front so every error path returns 0 bytes.
        let raw_rx_len = unsafe {
            let cap = *rx_length;
            *rx_length = 0;
            cap
        };

        let Some(max_rx) = dword_to_usize(raw_rx_len) else {
            return IFD_COMMUNICATION_ERROR;
        };
        let Some(tx_len) = dword_to_usize(tx_length) else {
            return IFD_COMMUNICATION_ERROR;
        };

        if (tx_len > 0 && tx_buffer.is_null()) || (max_rx > 0 && rx_buffer.is_null()) {
            return IFD_COMMUNICATION_ERROR;
        }

        trace!(
            lun,
            protocol = send_pci.protocol,
            tx_len,
            max_rx,
            "IFDHTransmitToICC"
        );

        let tx_apdu = if tx_len == 0 {
            Vec::new()
        } else {
            // SAFETY: caller guarantees `tx_buffer` is readable for `tx_len` bytes.
            unsafe { slice::from_raw_parts(tx_buffer, tx_len) }.to_vec()
        };

        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        let Some(state) = map.get_mut(&lun) else {
            return IFD_COMMUNICATION_ERROR;
        };

        let resp = match state.transmit(lun, tx_apdu) {
            Ok(resp) => resp,
            Err(code) => return code,
        };

        if resp.len() > max_rx {
            warn!(
                lun,
                resp_len = resp.len(),
                max_rx,
                "IFDHTransmitToICC: insufficient buffer"
            );
            return IFD_ERROR_INSUFFICIENT_BUFFER;
        }
        let Some(out_len) = usize_to_dword(resp.len()) else {
            return IFD_COMMUNICATION_ERROR;
        };
        if !resp.is_empty() {
            // SAFETY: `rx_buffer` is non-null and writable for `max_rx >= resp.len()`.
            unsafe {
                let out = slice::from_raw_parts_mut(rx_buffer, resp.len());
                out.copy_from_slice(&resp);
            }
        }
        // SAFETY: `rx_length` was checked non-null above.
        unsafe { *rx_length = out_len };
        if !recv_pci.is_null() {
            // SAFETY: `recv_pci` was checked non-null.
            unsafe {
                (*recv_pci).protocol = send_pci.protocol;
                (*recv_pci).length = 0;
            }
        }
        trace!(lun, rx_len = resp.len(), "IFDHTransmitToICC: success");
        IFD_SUCCESS
    })
}

/// Perform a reader-specific control exchange (not supported).
///
/// # Safety
///
/// `bytes_returned` must either be null or point to a writable `DWORD`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn IFDHControl(
    lun: Dword,
    control_code: Dword,
    _tx_buffer: *mut Uchar,
    _tx_length: Dword,
    _rx_buffer: *mut Uchar,
    _rx_length: Dword,
    bytes_returned: *mut Dword,
) -> ResponseCode {
    ffi_guard(|| {
        debug!(lun, control_code, "IFDHControl (unsupported)");
        if !bytes_returned.is_null() {
            // SAFETY: `bytes_returned` was checked non-null.
            unsafe { *bytes_returned = 0 };
        }
        IFD_NOT_SUPPORTED
    })
}

/// Check whether a virtual card is present on `lun`.
///
/// When an existing daemon connection breaks (for instance because `sftcrd`
/// stopped or restarted), this drops the stale socket and returns
/// [`crate::abi::IFD_ICC_NOT_PRESENT`] so `pcscd` observes card removal. On
/// the next poll once `sftcrd` is reachable again, this reconnects and returns
/// [`crate::abi::IFD_ICC_PRESENT`].
#[unsafe(no_mangle)]
pub extern "C" fn IFDHICCPresence(lun: Dword) -> ResponseCode {
    ffi_guard(|| {
        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        let Some(state) = map.get_mut(&lun) else {
            return IFD_COMMUNICATION_ERROR;
        };
        state.presence(lun)
    })
}
