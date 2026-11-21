//! PC/SC-Lite IFD Handler v3 shared library (`libsftcrd_ifd.so`) connecting
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
//! reports [`IFD_ICC_NOT_PRESENT`] and drops any stale socket handle so
//! `pcscd` observes card removal and cleanly reconnects and re-powers the card
//! once the daemon returns.

pub mod abi;

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::unix::net::UnixStream;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::slice;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use sftcrd_ifd_proto::{ErrorCode, Request, Response, exchange};

use crate::abi::{
    Dword, IFD_COMMUNICATION_ERROR, IFD_ERROR_INSUFFICIENT_BUFFER, IFD_ERROR_POWER_ACTION,
    IFD_ERROR_TAG, IFD_ICC_NOT_PRESENT, IFD_ICC_PRESENT, IFD_NOT_SUPPORTED, IFD_POWER_DOWN,
    IFD_POWER_UP, IFD_PROTOCOL_NOT_SUPPORTED, IFD_RESET, IFD_SUCCESS, Lpcstr, MAX_ATR_SIZE,
    ResponseCode, SCARD_ATTR_ATR_STRING, SCARD_PROTOCOL_T0, SCARD_PROTOCOL_T1, SCardIoHeader,
    TAG_IFD_ATR, TAG_IFD_SIMULTANEOUS_ACCESS, TAG_IFD_SLOT_THREAD_SAFE, TAG_IFD_SLOTS_NUMBER,
    TAG_IFD_THREAD_SAFE, Uchar,
};

/// Default Unix domain socket path when neither `DEVICENAME` nor
/// `SFTCRD_SOCKET` is provided.
pub const DEFAULT_SOCKET_PATH: &str = "/run/sftcrd/sftcrd.sock";

/// Environment variable checked as a fallback when `DEVICENAME` is absent.
const SOCKET_ENV_VAR: &str = "SFTCRD_SOCKET";

/// I/O timeout applied to daemon socket operations.
///
/// Generous enough to allow slow on-card operations such as RSA key generation
/// while preventing `pcscd` from hanging indefinitely on a wedged peer.
const IO_TIMEOUT: Duration = Duration::from_secs(60);

struct ChannelState {
    socket_path: PathBuf,
    stream: Option<UnixStream>,
    atr: Vec<u8>,
    protocol: Dword,
}

impl ChannelState {
    fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            stream: None,
            atr: Vec::new(),
            protocol: SCARD_PROTOCOL_T1,
        }
    }

    fn disconnect(&mut self) {
        self.stream = None;
        self.atr.clear();
    }

    fn connect(&mut self) -> std::io::Result<()> {
        let stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        self.stream = Some(stream);
        Ok(())
    }

    fn exchange_connected(&mut self, request: &Request) -> Option<Response> {
        let stream = self.stream.as_mut()?;
        if let Ok(resp) = exchange(stream, request) {
            Some(resp)
        } else {
            self.disconnect();
            None
        }
    }

    fn ensure_connected_and_exchange(&mut self, request: &Request) -> Option<Response> {
        if self.stream.is_none() && self.connect().is_err() {
            return None;
        }
        self.exchange_connected(request)
    }
}

fn channels() -> &'static Mutex<HashMap<Dword, ChannelState>> {
    static CHANNELS: OnceLock<Mutex<HashMap<Dword, ChannelState>>> = OnceLock::new();
    CHANNELS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn resolve_socket_path(device_name: Option<&str>) -> PathBuf {
    if let Some(name) = device_name {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            let path = trimmed.strip_prefix("unix:").unwrap_or(trimmed);
            if !path.is_empty() {
                return PathBuf::from(path);
            }
        }
    }

    if let Ok(env_path) = std::env::var(SOCKET_ENV_VAR) {
        let trimmed = env_path.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }

    PathBuf::from(DEFAULT_SOCKET_PATH)
}

fn ffi_guard(f: impl FnOnce() -> ResponseCode) -> ResponseCode {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(IFD_COMMUNICATION_ERROR)
}

fn map_error_code(code: ErrorCode) -> ResponseCode {
    match code {
        ErrorCode::CardAbsent => IFD_ICC_NOT_PRESENT,
        ErrorCode::ApduTooLarge => IFD_ERROR_INSUFFICIENT_BUFFER,
        ErrorCode::Unsupported => IFD_NOT_SUPPORTED,
        ErrorCode::NotPowered | ErrorCode::InvalidRequest | ErrorCode::Internal => {
            IFD_COMMUNICATION_ERROR
        }
    }
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
        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        map.insert(lun, ChannelState::new(socket_path));
        IFD_SUCCESS
    })
}

/// Open a channel for `lun` using the default or `SFTCRD_SOCKET` Unix socket.
#[unsafe(no_mangle)]
pub extern "C" fn IFDHCreateChannel(lun: Dword, _channel: Dword) -> ResponseCode {
    ffi_guard(|| {
        let socket_path = resolve_socket_path(None);
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
        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        if let Some(mut state) = map.remove(&lun) {
            if state.stream.is_some() {
                let _ = state.exchange_connected(&Request::PowerOff);
            }
            state.disconnect();
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
            return IFD_COMMUNICATION_ERROR;
        }

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

                if state.atr.is_empty() {
                    match state.ensure_connected_and_exchange(&Request::GetAtr) {
                        Some(Response::Atr(atr)) if atr.len() <= MAX_ATR_SIZE => {
                            state.atr = atr;
                        }
                        Some(Response::Error { code, .. }) => return map_error_code(code),
                        _ => return IFD_COMMUNICATION_ERROR,
                    }
                }

                if state.atr.len() > cap {
                    return IFD_ERROR_INSUFFICIENT_BUFFER;
                }

                let Some(out_len) = usize_to_dword(state.atr.len()) else {
                    return IFD_COMMUNICATION_ERROR;
                };

                // SAFETY: `value` has at least `cap >= state.atr.len()` writable bytes.
                unsafe {
                    let out = slice::from_raw_parts_mut(value, state.atr.len());
                    out.copy_from_slice(&state.atr);
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
    _lun: Dword,
    _tag: Dword,
    _length: Dword,
    _value: *mut Uchar,
) -> ResponseCode {
    IFD_ERROR_TAG
}

/// Negotiate card communication protocol (T=1 or T=0) for `lun`.
#[unsafe(no_mangle)]
pub extern "C" fn IFDHSetProtocolParameters(
    lun: Dword,
    protocol: Dword,
    _flags: Uchar,
    _pts1: Uchar,
    _pts2: Uchar,
    _pts3: Uchar,
) -> ResponseCode {
    ffi_guard(|| {
        if protocol != SCARD_PROTOCOL_T1 && protocol != SCARD_PROTOCOL_T0 {
            return IFD_PROTOCOL_NOT_SUPPORTED;
        }
        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        let Some(state) = map.get_mut(&lun) else {
            return IFD_COMMUNICATION_ERROR;
        };
        state.protocol = protocol;
        IFD_SUCCESS
    })
}

/// Power up, power down, or warm-reset the card in `lun`.
///
/// # Safety
///
/// For `IFD_POWER_UP` and `IFD_RESET`, `atr` must point to a writable buffer
/// of at least [`MAX_ATR_SIZE`] bytes and `atr_length` must be a valid
/// writable `DWORD` pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn IFDHPowerICC(
    lun: Dword,
    action: Dword,
    atr: *mut Uchar,
    atr_length: *mut Dword,
) -> ResponseCode {
    ffi_guard(|| {
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
                let req = if action == IFD_POWER_UP {
                    Request::PowerOn
                } else {
                    Request::Reset
                };

                match state.ensure_connected_and_exchange(&req) {
                    Some(Response::Atr(bytes)) if bytes.len() <= MAX_ATR_SIZE => {
                        let Some(out_len) = usize_to_dword(bytes.len()) else {
                            // SAFETY: `atr_length` was checked non-null above.
                            unsafe { *atr_length = 0 };
                            return IFD_ERROR_POWER_ACTION;
                        };
                        // SAFETY: caller guarantees `atr` holds at least `MAX_ATR_SIZE` bytes.
                        unsafe {
                            let out = slice::from_raw_parts_mut(atr, bytes.len());
                            out.copy_from_slice(&bytes);
                            *atr_length = out_len;
                        }
                        state.atr = bytes;
                        IFD_SUCCESS
                    }
                    Some(Response::Error {
                        code: ErrorCode::CardAbsent,
                        ..
                    }) => {
                        // SAFETY: `atr_length` was checked non-null above.
                        unsafe { *atr_length = 0 };
                        IFD_ICC_NOT_PRESENT
                    }
                    _ => {
                        // SAFETY: `atr_length` was checked non-null above.
                        unsafe { *atr_length = 0 };
                        IFD_ERROR_POWER_ACTION
                    }
                }
            }
            IFD_POWER_DOWN => {
                if state.stream.is_some() {
                    let _ = state.exchange_connected(&Request::PowerOff);
                }
                state.atr.clear();
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

        if state.stream.is_none() {
            return IFD_ICC_NOT_PRESENT;
        }

        match state.exchange_connected(&Request::Transmit(tx_apdu)) {
            Some(Response::Apdu(resp)) => {
                if resp.len() > max_rx {
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
                IFD_SUCCESS
            }
            Some(Response::Error { code, .. }) => map_error_code(code),
            _ => IFD_COMMUNICATION_ERROR,
        }
    })
}

/// Perform a reader-specific control exchange (not supported).
///
/// # Safety
///
/// `bytes_returned` must either be null or point to a writable `DWORD`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn IFDHControl(
    _lun: Dword,
    _control_code: Dword,
    _tx_buffer: *mut Uchar,
    _tx_length: Dword,
    _rx_buffer: *mut Uchar,
    _rx_length: Dword,
    bytes_returned: *mut Dword,
) -> ResponseCode {
    ffi_guard(|| {
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
/// [`IFD_ICC_NOT_PRESENT`] so `pcscd` observes card removal. On the next poll
/// once `sftcrd` is reachable again, this reconnects and returns
/// [`IFD_ICC_PRESENT`].
#[unsafe(no_mangle)]
pub extern "C" fn IFDHICCPresence(lun: Dword) -> ResponseCode {
    ffi_guard(|| {
        let Ok(mut map) = channels().lock() else {
            return IFD_COMMUNICATION_ERROR;
        };
        let Some(state) = map.get_mut(&lun) else {
            return IFD_COMMUNICATION_ERROR;
        };

        let resp = if state.stream.is_some() {
            // Existing connection: if it broke, report absence now and let the
            // next poll reconnect so pcscd detects the removal/reinsertion.
            state.exchange_connected(&Request::Presence)
        } else {
            state.ensure_connected_and_exchange(&Request::Presence)
        };

        match resp {
            Some(Response::Presence(true)) => IFD_ICC_PRESENT,
            _ => IFD_ICC_NOT_PRESENT,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::net::UnixListener;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;

    use sftcrd_ifd_proto::{read_request, write_response};

    const MOCK_ATR: &[u8] = &[0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31];

    fn unique_socket_path(label: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("sftcrd-ifd-test-{label}-{}-{n}.sock", std::process::id()))
    }

    fn spawn_mock_server(
        sock_path: &PathBuf,
        max_connections: usize,
        present: Arc<AtomicBool>,
    ) -> thread::JoinHandle<()> {
        let _ = std::fs::remove_file(sock_path);
        let listener = UnixListener::bind(sock_path).expect("bind mock socket");
        thread::spawn(move || {
            for _ in 0..max_connections {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut powered = false;
                while let Ok(Some(req)) = read_request(&mut stream) {
                    let resp = match req {
                        Request::Presence => Response::Presence(present.load(Ordering::SeqCst)),
                        Request::PowerOn | Request::Reset => {
                            powered = true;
                            Response::Atr(MOCK_ATR.to_vec())
                        }
                        Request::PowerOff => {
                            powered = false;
                            Response::Ok
                        }
                        Request::GetAtr => Response::Atr(MOCK_ATR.to_vec()),
                        Request::Transmit(apdu) => {
                            if powered {
                                // Echo payload + 90 00, or return 512 bytes for extended test.
                                if apdu.len() > 256 {
                                    let mut out = vec![0xAB; 512];
                                    out.extend_from_slice(&[0x90, 0x00]);
                                    Response::Apdu(out)
                                } else {
                                    let mut out = apdu;
                                    out.extend_from_slice(&[0x90, 0x00]);
                                    Response::Apdu(out)
                                }
                            } else {
                                Response::error(ErrorCode::NotPowered, "card not powered")
                            }
                        }
                    };
                    if write_response(&mut stream, &resp).is_err() {
                        break;
                    }
                }
            }
        })
    }

    #[test]
    fn ifdh_lifecycle_and_capabilities() {
        let sock_path = unique_socket_path("lifecycle");
        let present = Arc::new(AtomicBool::new(true));
        let server = spawn_mock_server(&sock_path, 1, Arc::clone(&present));
        let lun: Dword = 0x0001_0000;

        let dev = CString::new(sock_path.to_str().expect("utf8 path")).expect("CString");
        assert_eq!(
            unsafe { IFDHCreateChannelByName(lun, dev.as_ptr()) },
            IFD_SUCCESS
        );
        assert_eq!(IFDHICCPresence(lun), IFD_ICC_PRESENT);

        let mut val = [0u8; MAX_ATR_SIZE];
        let mut len: Dword = 1;
        assert_eq!(
            unsafe { IFDHGetCapabilities(lun, TAG_IFD_SLOTS_NUMBER, &raw mut len, val.as_mut_ptr()) },
            IFD_SUCCESS
        );
        assert_eq!((len, val[0]), (1, 1));
        assert_eq!(
            unsafe { IFDHGetCapabilities(lun, 0x9999, &raw mut len, val.as_mut_ptr()) },
            IFD_ERROR_TAG
        );
        assert_eq!(
            unsafe { IFDHSetCapabilities(lun, TAG_IFD_ATR, 0, ptr::null_mut()) },
            IFD_ERROR_TAG
        );

        assert_eq!(
            IFDHSetProtocolParameters(lun, SCARD_PROTOCOL_T1, 0, 0, 0, 0),
            IFD_SUCCESS
        );
        assert_eq!(
            IFDHSetProtocolParameters(lun, 0x0008, 0, 0, 0, 0),
            IFD_PROTOCOL_NOT_SUPPORTED
        );

        let mut atr = [0u8; MAX_ATR_SIZE];
        let mut atr_len: Dword = 0;
        assert_eq!(
            unsafe { IFDHPowerICC(lun, IFD_POWER_UP, atr.as_mut_ptr(), &raw mut atr_len) },
            IFD_SUCCESS
        );
        assert_eq!(&atr[..usize::try_from(atr_len).unwrap()], MOCK_ATR);

        let mut small_len: Dword = 2;
        assert_eq!(
            unsafe { IFDHGetCapabilities(lun, TAG_IFD_ATR, &raw mut small_len, val.as_mut_ptr()) },
            IFD_ERROR_INSUFFICIENT_BUFFER
        );
        let mut atr_cap: Dword = Dword::try_from(MAX_ATR_SIZE).unwrap();
        assert_eq!(
            unsafe { IFDHGetCapabilities(lun, TAG_IFD_ATR, &raw mut atr_cap, val.as_mut_ptr()) },
            IFD_SUCCESS
        );
        assert_eq!(&val[..usize::try_from(atr_cap).unwrap()], MOCK_ATR);

        let mut ctrl_ret: Dword = 99;
        assert_eq!(
            unsafe {
                IFDHControl(lun, 0, ptr::null_mut(), 0, ptr::null_mut(), 0, &raw mut ctrl_ret)
            },
            IFD_NOT_SUPPORTED
        );
        assert_eq!(ctrl_ret, 0);

        assert_eq!(
            unsafe { IFDHPowerICC(lun, IFD_POWER_DOWN, atr.as_mut_ptr(), &raw mut atr_len) },
            IFD_SUCCESS
        );
        assert_eq!(atr_len, 0);
        assert_eq!(
            unsafe { IFDHPowerICC(lun, IFD_RESET, atr.as_mut_ptr(), &raw mut atr_len) },
            IFD_SUCCESS
        );
        assert_eq!(&atr[..usize::try_from(atr_len).unwrap()], MOCK_ATR);

        assert_eq!(IFDHCloseChannel(lun), IFD_SUCCESS);
        server.join().expect("mock server thread");
        let _ = std::fs::remove_file(&sock_path);
    }

    #[test]
    fn ifdh_transmit_short_extended_and_bounds() {
        let sock_path = unique_socket_path("transmit");
        let present = Arc::new(AtomicBool::new(true));
        let server = spawn_mock_server(&sock_path, 1, Arc::clone(&present));
        let lun: Dword = 0x0003_0000;

        let dev = CString::new(sock_path.to_str().expect("utf8 path")).expect("CString");
        assert_eq!(
            unsafe { IFDHCreateChannelByName(lun, dev.as_ptr()) },
            IFD_SUCCESS
        );
        let mut atr = [0u8; MAX_ATR_SIZE];
        let mut atr_len: Dword = 0;
        assert_eq!(
            unsafe { IFDHPowerICC(lun, IFD_POWER_UP, atr.as_mut_ptr(), &raw mut atr_len) },
            IFD_SUCCESS
        );

        let send_pci = SCardIoHeader {
            protocol: SCARD_PROTOCOL_T1,
            length: 0,
        };
        let mut tx = [0x00u8, 0xA4, 0x04, 0x00];
        let mut rx = [0u8; 64];
        let mut rx_len: Dword = 64;
        let mut recv_pci = SCardIoHeader::default();
        assert_eq!(
            unsafe {
                IFDHTransmitToICC(
                    lun,
                    send_pci,
                    tx.as_mut_ptr(),
                    Dword::try_from(tx.len()).unwrap(),
                    rx.as_mut_ptr(),
                    &raw mut rx_len,
                    &raw mut recv_pci,
                )
            },
            IFD_SUCCESS
        );
        assert_eq!(
            &rx[..usize::try_from(rx_len).unwrap()],
            &[0x00, 0xA4, 0x04, 0x00, 0x90, 0x00]
        );
        assert_eq!(recv_pci.protocol, SCARD_PROTOCOL_T1);

        // Extended-length APDU: insufficient buffer fails cleanly with *rx_length = 0.
        let mut big_tx = vec![0x42u8; 400];
        let mut tiny_rx = [0u8; 4];
        let mut tiny_len: Dword = 4;
        assert_eq!(
            unsafe {
                IFDHTransmitToICC(
                    lun,
                    send_pci,
                    big_tx.as_mut_ptr(),
                    Dword::try_from(big_tx.len()).unwrap(),
                    tiny_rx.as_mut_ptr(),
                    &raw mut tiny_len,
                    ptr::null_mut(),
                )
            },
            IFD_ERROR_INSUFFICIENT_BUFFER
        );
        assert_eq!(tiny_len, 0);

        let mut big_rx = vec![0u8; 1024];
        let mut big_rx_len: Dword = 1024;
        assert_eq!(
            unsafe {
                IFDHTransmitToICC(
                    lun,
                    send_pci,
                    big_tx.as_mut_ptr(),
                    Dword::try_from(big_tx.len()).unwrap(),
                    big_rx.as_mut_ptr(),
                    &raw mut big_rx_len,
                    ptr::null_mut(),
                )
            },
            IFD_SUCCESS
        );
        assert_eq!(big_rx_len, 514);
        assert!(big_rx[..514].ends_with(&[0x90, 0x00]));

        assert_eq!(IFDHCloseChannel(lun), IFD_SUCCESS);
        server.join().expect("mock server thread");
        let _ = std::fs::remove_file(&sock_path);
    }

    #[test]
    fn reconnects_cleanly_across_daemon_restart() {
        let sock_path = unique_socket_path("reconnect");
        let lun: Dword = 0x0002_0000;
        let dev = CString::new(sock_path.to_str().expect("utf8 path")).expect("CString");

        // Channel creation succeeds even when daemon socket does not exist yet.
        assert_eq!(
            unsafe { IFDHCreateChannelByName(lun, dev.as_ptr()) },
            IFD_SUCCESS
        );
        assert_eq!(IFDHICCPresence(lun), IFD_ICC_NOT_PRESENT);

        // Start daemon instance #1.
        let present = Arc::new(AtomicBool::new(true));
        let server1 = spawn_mock_server(&sock_path, 1, Arc::clone(&present));
        assert_eq!(IFDHICCPresence(lun), IFD_ICC_PRESENT);

        // Power on and close server1 by dropping its single-connection handler after power off
        // — simulate abrupt daemon death by spawning a one-shot server that closes after 1 req.
        assert_eq!(IFDHCloseChannel(lun), IFD_SUCCESS);
        server1.join().expect("server1");
        let _ = std::fs::remove_file(&sock_path);

        // Re-open channel, connect to a server that drops the connection after one presence check.
        assert_eq!(
            unsafe { IFDHCreateChannelByName(lun, dev.as_ptr()) },
            IFD_SUCCESS
        );
        let listener = UnixListener::bind(&sock_path).expect("bind one-shot");
        let one_shot = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let req = read_request(&mut stream).expect("read").expect("req");
            assert_eq!(req, Request::Presence);
            write_response(&mut stream, &Response::Presence(true)).expect("write");
            // Drop stream + listener to simulate daemon stop.
        });
        assert_eq!(IFDHICCPresence(lun), IFD_ICC_PRESENT);
        one_shot.join().expect("one_shot");

        // Next presence poll detects the broken connection and reports absence.
        assert_eq!(IFDHICCPresence(lun), IFD_ICC_NOT_PRESENT);

        // Start daemon instance #2 on the same socket path.
        let server2 = spawn_mock_server(&sock_path, 1, Arc::clone(&present));

        // Next presence poll reconnects automatically and reports present.
        assert_eq!(IFDHICCPresence(lun), IFD_ICC_PRESENT);

        let mut atr = [0u8; MAX_ATR_SIZE];
        let mut atr_len: Dword = 0;
        assert_eq!(
            unsafe { IFDHPowerICC(lun, IFD_POWER_UP, atr.as_mut_ptr(), &raw mut atr_len) },
            IFD_SUCCESS
        );
        assert_eq!(&atr[..usize::try_from(atr_len).unwrap()], MOCK_ATR);

        assert_eq!(IFDHCloseChannel(lun), IFD_SUCCESS);
        server2.join().expect("server2");
        let _ = std::fs::remove_file(&sock_path);
    }
}
