//! Safe Rust channel state, daemon socket lifecycle, and protocol mapping.

use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use sftcrd_ifd_proto::{ErrorCode, Request, Response, exchange};
use tracing::{debug, trace, warn};

use crate::abi::{
    Dword, IFD_COMMUNICATION_ERROR, IFD_ERROR_INSUFFICIENT_BUFFER, IFD_ERROR_POWER_ACTION,
    IFD_ICC_NOT_PRESENT, IFD_ICC_PRESENT, IFD_NOT_SUPPORTED, IFD_POWER_UP,
    IFD_PROTOCOL_NOT_SUPPORTED, IFD_SUCCESS, MAX_ATR_SIZE, ResponseCode, SCARD_PROTOCOL_T0,
    SCARD_PROTOCOL_T1,
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

/// Per-LUN state for a single reader channel connected to `sftcrd`.
pub struct ChannelState {
    socket_path: PathBuf,
    stream: Option<UnixStream>,
    atr: Vec<u8>,
    protocol: Dword,
    /// Set when an active daemon connection drops so the next
    /// `IFDHICCPresence` call always reports `IFD_ICC_NOT_PRESENT` to `pcscd`
    /// before reconnecting, ensuring `pcscd` re-powers the new card session.
    pending_removal: bool,
}

impl ChannelState {
    /// Create a new, lazily connected channel targeting `socket_path`.
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            stream: None,
            atr: Vec::new(),
            protocol: SCARD_PROTOCOL_T1,
            pending_removal: false,
        }
    }

    /// Power off the card (best-effort) and close the daemon socket.
    pub fn close(mut self) {
        if self.stream.is_some() {
            let _ = self.exchange_connected(&Request::PowerOff);
        }
        self.disconnect();
    }

    /// Return the cached ATR, querying the daemon if not yet cached.
    pub fn get_atr(&mut self) -> Result<&[u8], ResponseCode> {
        if self.atr.is_empty() {
            match self.ensure_connected_and_exchange(&Request::GetAtr) {
                Some(Response::Atr(atr)) if atr.len() <= MAX_ATR_SIZE => {
                    self.atr = atr;
                }
                Some(Response::Error { code, .. }) => return Err(map_error_code(code)),
                _ => return Err(IFD_COMMUNICATION_ERROR),
            }
        }
        Ok(&self.atr)
    }

    /// Record the negotiated protocol (`SCARD_PROTOCOL_T0` or `SCARD_PROTOCOL_T1`).
    pub fn set_protocol(&mut self, lun: Dword, protocol: Dword) -> ResponseCode {
        if protocol != SCARD_PROTOCOL_T1 && protocol != SCARD_PROTOCOL_T0 {
            warn!(
                lun,
                protocol, "IFDHSetProtocolParameters: unsupported protocol"
            );
            return IFD_PROTOCOL_NOT_SUPPORTED;
        }
        self.protocol = protocol;
        IFD_SUCCESS
    }

    /// Power up (`IFD_POWER_UP`) or warm-reset (`IFD_RESET`) the card and cache its ATR.
    pub fn power_up_or_reset(&mut self, action: Dword) -> Result<&[u8], ResponseCode> {
        let req = if action == IFD_POWER_UP {
            Request::PowerOn
        } else {
            Request::Reset
        };

        match self.ensure_connected_and_exchange(&req) {
            Some(Response::Atr(bytes)) if bytes.len() <= MAX_ATR_SIZE => {
                self.atr = bytes;
                Ok(&self.atr)
            }
            Some(Response::Error {
                code: ErrorCode::CardAbsent,
                ..
            }) => Err(IFD_ICC_NOT_PRESENT),
            _ => Err(IFD_ERROR_POWER_ACTION),
        }
    }

    /// Power down the card and clear the cached ATR.
    pub fn power_down(&mut self) {
        if self.stream.is_some() {
            let _ = self.exchange_connected(&Request::PowerOff);
        }
        self.atr.clear();
    }

    /// Transmit a command APDU to the daemon and return the response APDU bytes.
    pub fn transmit(&mut self, lun: Dword, tx_apdu: Vec<u8>) -> Result<Vec<u8>, ResponseCode> {
        if self.stream.is_none() {
            debug!(lun, "IFDHTransmitToICC: not connected");
            return Err(IFD_ICC_NOT_PRESENT);
        }

        match self.exchange_connected(&Request::Transmit(tx_apdu)) {
            Some(Response::Apdu(resp)) => Ok(resp),
            Some(Response::Error { code, message }) => {
                warn!(lun, %code, ?message, "IFDHTransmitToICC: daemon returned error");
                Err(map_error_code(code))
            }
            _ => Err(IFD_COMMUNICATION_ERROR),
        }
    }

    /// Poll card presence, reporting a removal transition after any disconnect.
    pub fn presence(&mut self, lun: Dword) -> ResponseCode {
        if self.pending_removal {
            debug!(lun, "IFDHICCPresence: reporting card removal after disconnect");
            self.pending_removal = false;
            return IFD_ICC_NOT_PRESENT;
        }

        let resp = if self.stream.is_some() {
            // Existing connection: if it broke, report absence now and let the
            // next poll reconnect so pcscd detects the removal/reinsertion.
            let resp = self.exchange_connected(&Request::Presence);
            if resp.is_none() {
                // Already reporting absence on this poll; don't report twice.
                self.pending_removal = false;
            }
            resp
        } else {
            self.ensure_connected_and_exchange(&Request::Presence)
        };

        let status = match resp {
            Some(Response::Presence(true)) => IFD_ICC_PRESENT,
            _ => IFD_ICC_NOT_PRESENT,
        };
        trace!(lun, present = (status == IFD_ICC_PRESENT), "IFDHICCPresence");
        status
    }

    fn disconnect(&mut self) {
        if self.stream.take().is_some() {
            debug!(socket = %self.socket_path.display(), "disconnected from sftcrd daemon");
            self.pending_removal = true;
        }
        self.atr.clear();
    }

    fn connect(&mut self) -> std::io::Result<()> {
        let stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        debug!(socket = %self.socket_path.display(), "connected to sftcrd daemon");
        self.stream = Some(stream);
        Ok(())
    }

    fn exchange_connected(&mut self, request: &Request) -> Option<Response> {
        let stream = self.stream.as_mut()?;
        match exchange(stream, request) {
            Ok(resp) => Some(resp),
            Err(err) => {
                warn!(socket = %self.socket_path.display(), %err, "daemon exchange failed");
                self.disconnect();
                None
            }
        }
    }

    fn ensure_connected_and_exchange(&mut self, request: &Request) -> Option<Response> {
        if self.stream.is_none() && self.connect().is_err() {
            return None;
        }
        self.exchange_connected(request)
    }
}

/// Global map of open reader channels keyed by `Lun`.
pub fn channels() -> &'static Mutex<HashMap<Dword, ChannelState>> {
    static CHANNELS: OnceLock<Mutex<HashMap<Dword, ChannelState>>> = OnceLock::new();
    CHANNELS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Resolve the `sftcrd` Unix socket path from `DEVICENAME`, `SFTCRD_SOCKET`,
/// or [`DEFAULT_SOCKET_PATH`].
pub fn resolve_socket_path(device_name: Option<&str>) -> PathBuf {
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
