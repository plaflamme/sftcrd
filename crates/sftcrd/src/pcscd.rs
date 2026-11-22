//! Direct `pcscd` IFD Unix domain socket transport speaking
//! [`sftcrd_ifd_proto`].

use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::ExitCode;

use sftcrd_ifd_proto::{ErrorCode, Request, Response, read_request, write_response};
use tracing::{info, warn};

use crate::{CardChannels, PgpApplet, PivApplet, TransmitError};

/// Default Unix domain socket path for `sftcrd pcscd`.
pub const DEFAULT_SOCKET_PATH: &str = "/run/sftcrd/sftcrd.sock";

/// First file descriptor passed by systemd socket activation (`SD_LISTEN_FDS_START`).
const SD_LISTEN_FDS_START: i32 = 3;

/// Run the direct `pcscd` IFD Unix domain socket listener loop.
pub fn run(
    socket_path: &Path,
    atr: &[u8],
    piv_applet: &mut PivApplet,
    pgp_applet: &mut PgpApplet,
) -> ExitCode {
    let listener = match acquire_listener(socket_path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(socket = %socket_path.display(), "cannot bind Unix socket: {e}");
            return ExitCode::FAILURE;
        }
    };

    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                info!("pcscd IFD client connected");
                if let Err(e) = serve_connection(stream, atr, piv_applet, pgp_applet) {
                    warn!("pcscd connection failed: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
}

/// Serve one direct `pcscd` IFD Unix socket connection until it drops.
///
/// # Errors
///
/// Returns an [`io::Error`] if reading requests, writing responses, or
/// initializing the [`CardChannels`] fails.
pub fn serve_connection(
    mut stream: UnixStream,
    atr: &[u8],
    piv_applet: &mut PivApplet,
    pgp_applet: &mut PgpApplet,
) -> io::Result<()> {
    let mut channels = CardChannels::new();
    let mut session = channels.session(atr, piv_applet, pgp_applet)?;

    loop {
        let Some(req) = read_request(&mut stream).map_err(io::Error::other)? else {
            info!("pcscd IFD client disconnected");
            return Ok(());
        };

        let resp = match req {
            Request::Presence => Response::Presence(true),
            Request::PowerOn => {
                session.power_on();
                Response::Atr(session.atr().to_vec())
            }
            Request::PowerOff => {
                session.power_off();
                Response::Ok
            }
            Request::Reset => {
                session.reset();
                Response::Atr(session.atr().to_vec())
            }
            Request::GetAtr => Response::Atr(session.atr().to_vec()),
            Request::Transmit(apdu) => match session.transmit(&apdu) {
                Ok(Some(response)) => Response::Apdu(response),
                Ok(None) => Response::error(ErrorCode::Internal, "no response APDU from applet"),
                Err(TransmitError::NotPowered) => {
                    Response::error(ErrorCode::NotPowered, "card is powered off")
                }
                Err(TransmitError::ApduTooLarge { len, max }) => Response::error(
                    ErrorCode::ApduTooLarge,
                    format!("APDU length {len} exceeds maximum {max} bytes"),
                ),
                Err(TransmitError::Internal(msg)) => Response::error(ErrorCode::Internal, msg),
            },
        };

        write_response(&mut stream, &resp).map_err(io::Error::other)?;
    }
}

/// Acquire a [`UnixListener`] either from systemd socket activation
/// (`LISTEN_PID` / `LISTEN_FDS`, fd 3) or by binding `socket_path` directly.
fn acquire_listener(socket_path: &Path) -> io::Result<UnixListener> {
    if let Some(listener) = take_systemd_unix_listener() {
        info!("listening for pcscd IFD via systemd socket activation (fd 3)");
        return Ok(listener);
    }

    let listener = bind_unix_socket(socket_path)?;
    info!(socket = %socket_path.display(), "listening for pcscd IFD");
    Ok(listener)
}

/// Check `LISTEN_PID` and `LISTEN_FDS` per the systemd socket activation
/// protocol and take ownership of fd 3 if activated for this process.
fn take_systemd_unix_listener() -> Option<UnixListener> {
    let listen_pid: u32 = std::env::var("LISTEN_PID").ok()?.parse().ok()?;
    if listen_pid != std::process::id() {
        return None;
    }

    let listen_fds: usize = std::env::var("LISTEN_FDS").ok()?.parse().ok()?;
    if listen_fds == 0 {
        return None;
    }
    if listen_fds > 1 {
        warn!(
            listen_fds,
            "systemd passed multiple listening sockets; using fd 3 only"
        );
    }

    // SAFETY: systemd passes open, bound listening sockets starting at fd 3
    // when LISTEN_PID matches our PID and LISTEN_FDS >= 1. We consume it once
    // during startup so no other code aliases this descriptor.
    Some(unsafe { UnixListener::from_raw_fd(SD_LISTEN_FDS_START) })
}

/// Bind a Unix domain socket at `path`, removing a stale socket file if no
/// active server is listening on it.
fn bind_unix_socket(path: &Path) -> io::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a Unix socket", path.display()),
                ));
            }

            match UnixStream::connect(path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("socket {} is already in use", path.display()),
                    ));
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                    ) =>
                {
                    info!(socket = %path.display(), "removing stale Unix socket");
                    std::fs::remove_file(path)?;
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    UnixListener::bind(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use sftcrd_ifd_proto::exchange;

    const DEFAULT_ATR: &str = "3BFD1300008131FE158073C021C057597562694B657940";
    const SW_OK: [u8; 2] = [0x90, 0x00];
    const OPENPGP_SELECT: &[u8] = &[
        0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    ];

    fn unique_socket_path(label: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sftcrd-test-{label}-{}-{n}.sock",
            std::process::id()
        ))
    }

    fn send_apdu(stream: &mut UnixStream, apdu: Vec<u8>) -> Vec<u8> {
        let Response::Apdu(resp) =
            exchange(stream, &Request::Transmit(apdu)).expect("pcscd transmit")
        else {
            panic!("expected Response::Apdu");
        };
        resp
    }

    #[test]
    fn power_cycle_atr_apdus_and_state_persistence() {
        let sock_path = unique_socket_path("pcscd-state");
        let listener = bind_unix_socket(&sock_path).expect("bind unix socket");
        let atr = hex::decode(DEFAULT_ATR).expect("valid default ATR");
        let expected_atr = atr.clone();

        let server = thread::spawn(move || {
            let mut piv_applet = PivApplet::new();
            let mut pgp_applet = PgpApplet::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().expect("accept");
                serve_connection(stream, &atr, &mut piv_applet, &mut pgp_applet)
                    .expect("serve pcscd connection");
            }
        });

        // Connection 1: test presence, NotPowered error, power cycle, ATR, PIV, and PGP mutations.
        {
            let mut client = UnixStream::connect(&sock_path).expect("connect 1");

            assert_eq!(
                exchange(&mut client, &Request::Presence).expect("presence"),
                Response::Presence(true)
            );
            assert_eq!(
                exchange(&mut client, &Request::GetAtr).expect("get atr"),
                Response::Atr(expected_atr.clone())
            );
            assert!(matches!(
                exchange(&mut client, &Request::Transmit(keyroost_piv::select()))
                    .expect("transmit while off"),
                Response::Error {
                    code: ErrorCode::NotPowered,
                    ..
                }
            ));
            assert_eq!(
                exchange(&mut client, &Request::PowerOn).expect("power on"),
                Response::Atr(expected_atr.clone())
            );
            assert!(matches!(
                exchange(&mut client, &Request::Transmit(vec![0u8; 4096]))
                    .expect("oversized apdu"),
                Response::Error {
                    code: ErrorCode::ApduTooLarge,
                    ..
                }
            ));

            // Select PIV and change PIN from 123456 to 654321.
            let resp = send_apdu(&mut client, keyroost_piv::select());
            assert!(resp.ends_with(&SW_OK), "PIV select failed: {resp:02X?}");

            let change_pin = keyroost_piv::change_reference(0x80, b"123456", b"654321")
                .expect("change_reference apdu");
            assert_eq!(send_apdu(&mut client, change_pin), SW_OK);

            // Power off -> transmit fails -> warm reset powers back on and returns ATR.
            assert_eq!(
                exchange(&mut client, &Request::PowerOff).expect("power off"),
                Response::Ok
            );
            assert!(matches!(
                exchange(&mut client, &Request::Transmit(OPENPGP_SELECT.to_vec()))
                    .expect("transmit after power off"),
                Response::Error {
                    code: ErrorCode::NotPowered,
                    ..
                }
            ));
            assert_eq!(
                exchange(&mut client, &Request::Reset).expect("reset"),
                Response::Atr(expected_atr.clone())
            );

            // Select OpenPGP and fail PW1 verification once (retries 3 -> 2).
            let resp = send_apdu(&mut client, OPENPGP_SELECT.to_vec());
            assert!(resp.ends_with(&SW_OK), "PGP select failed: {resp:02X?}");

            let wrong_pw1 = vec![
                0x00, 0x20, 0x00, 0x81, 0x06, b'0', b'0', b'0', b'0', b'0', b'0',
            ];
            assert_eq!(send_apdu(&mut client, wrong_pw1), [0x63, 0xC2]);
        }

        // Connection 2: verify both PIV and OpenPGP mutations persisted across reconnect.
        {
            let mut client = UnixStream::connect(&sock_path).expect("connect 2");

            assert_eq!(
                exchange(&mut client, &Request::PowerOn).expect("power on 2"),
                Response::Atr(expected_atr)
            );
            assert!(send_apdu(&mut client, keyroost_piv::select()).ends_with(&SW_OK));

            let verify_pin = keyroost_piv::verify_pin(b"654321").expect("verify_pin apdu");
            assert_eq!(send_apdu(&mut client, verify_pin), SW_OK);

            assert!(send_apdu(&mut client, OPENPGP_SELECT.to_vec()).ends_with(&SW_OK));
            assert_eq!(
                send_apdu(&mut client, vec![0x00, 0x20, 0x00, 0x81]),
                [0x63, 0xC2]
            );
        }

        server.join().expect("server thread");
        let _ = std::fs::remove_file(&sock_path);
    }

    #[test]
    fn bind_unix_socket_cleans_stale_and_rejects_active() {
        let sock_path = unique_socket_path("stale");

        // Bind, then drop to leave a stale socket file behind.
        let listener = bind_unix_socket(&sock_path).expect("initial bind");
        drop(listener);
        assert!(sock_path.exists());

        // Re-binding removes the stale socket and succeeds.
        let active_listener = bind_unix_socket(&sock_path).expect("rebind stale socket");

        // Binding while another listener is active must fail with AddrInUse.
        let err = bind_unix_socket(&sock_path).expect_err("active socket must fail");
        assert_eq!(err.kind(), io::ErrorKind::AddrInUse);

        drop(active_listener);
        let _ = std::fs::remove_file(&sock_path);
    }
}
