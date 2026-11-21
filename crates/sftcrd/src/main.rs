//! Software smartcard daemon presenting PIV and `OpenPGP` applets over
//! either a direct PC/SC IFD Unix domain socket (`sftcrd pcsc`) or the
//! `VSmartCard` TCP protocol (`sftcrd vpcd`).

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::FromRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use figment::Figment;
use figment::providers::{Format, Toml};
use sftcrd_ifd_proto::{ErrorCode, Request, Response, read_request, write_response};
use toml_example::TomlExample;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use sftcrd::{CardChannels, CardConfig, DEFAULT_SERIAL, PgpApplet, PivApplet, TransmitError};

/// The ATR of a `YubiKey` 5.7
const DEFAULT_ATR: &str = "3BFD1300008131FE158073C021C057597562694B657940";

/// Default Unix domain socket path for `sftcrd pcsc`.
const DEFAULT_SOCKET_PATH: &str = "/run/sftcrd/sftcrd.sock";

/// First file descriptor passed by systemd socket activation (`SD_LISTEN_FDS_START`).
const SD_LISTEN_FDS_START: i32 = 3;

// VSmartCard control commands (driver -> card, one-byte payload).
const CTRL_POWER_OFF: u8 = 0x00;
const CTRL_POWER_ON: u8 = 0x01;
const CTRL_RESET: u8 = 0x02;
const CTRL_GET_ATR: u8 = 0x04;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "sftcrd",
    version,
    about = "Software smartcard daemon presenting PIV and OpenPGP applets"
)]
struct Args {
    /// ATR presented to PC/SC clients, as a hex string.
    #[arg(long, global = true, default_value = DEFAULT_ATR)]
    atr: String,

    /// Path to a TOML configuration file to initialize the card state.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Listen on a TCP socket for `VSmartCard` (`vpcd`) connections.
    Vpcd {
        /// Host to bind the listener on.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Port to listen on.
        #[arg(long, default_value_t = 35963u16)]
        port: u16,
    },

    /// Listen on a Unix domain socket for direct PC/SC IFD handler connections.
    Pcsc {
        /// Unix domain socket path to bind (ignored when systemd socket activation is used).
        #[arg(long, default_value = DEFAULT_SOCKET_PATH)]
        socket: PathBuf,
    },

    /// Print the reference TOML configuration wrapped in a Markdown code block.
    #[command(hide = true)]
    ConfigReference,
}

fn main() -> ExitCode {
    let args = Args::parse();

    if matches!(args.command, Command::ConfigReference) {
        println!("```toml");
        println!("{}", CardConfig::toml_example());
        println!("```");
        return ExitCode::SUCCESS;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let atr = match hex::decode(&args.atr) {
        Ok(atr) => atr,
        Err(e) => {
            tracing::error!("invalid --atr: {e}");
            return ExitCode::FAILURE;
        }
    };

    let (mut piv_applet, mut pgp_applet) = match init_applets(args.config.as_deref()) {
        Ok(applets) => applets,
        Err(e) => {
            tracing::error!("cannot initialize card state: {e}");
            return ExitCode::FAILURE;
        }
    };

    match args.command {
        Command::Vpcd { host, port } => run_vpcd(&host, port, &atr, &mut piv_applet, &mut pgp_applet),
        Command::Pcsc { socket } => run_pcsc(&socket, &atr, &mut piv_applet, &mut pgp_applet),
        Command::ConfigReference => unreachable!("handled above"),
    }
}

/// Run the `VSmartCard` (`vpcd`) TCP listener loop.
fn run_vpcd(
    host: &str,
    port: u16,
    atr: &[u8],
    piv_applet: &mut PivApplet,
    pgp_applet: &mut PgpApplet,
) -> ExitCode {
    // We are the vpicc listener: vpcd is configured in connect mode and dials us.
    let listener = match TcpListener::bind((host, port)) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(host = %host, port, "cannot bind: {e}");
            return ExitCode::FAILURE;
        }
    };

    info!(host = %host, port, "listening for vpcd");

    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                info!(%addr, "vpcd connected");
                if let Err(e) = serve_vpcd_connection(stream, atr, piv_applet, pgp_applet) {
                    warn!("connection with {addr} failed: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
}

/// Run the direct PC/SC IFD Unix domain socket listener loop.
fn run_pcsc(
    socket_path: &Path,
    atr: &[u8],
    piv_applet: &mut PivApplet,
    pgp_applet: &mut PgpApplet,
) -> ExitCode {
    let listener = match acquire_pcsc_listener(socket_path) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(socket = %socket_path.display(), "cannot bind Unix socket: {e}");
            return ExitCode::FAILURE;
        }
    };

    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                info!("pcsc IFD client connected");
                if let Err(e) = serve_pcsc_connection(stream, atr, piv_applet, pgp_applet) {
                    warn!("pcsc connection failed: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
}

/// Acquire a [`UnixListener`] either from systemd socket activation
/// (`LISTEN_PID` / `LISTEN_FDS`, fd 3) or by binding `socket_path` directly.
fn acquire_pcsc_listener(socket_path: &Path) -> io::Result<UnixListener> {
    if let Some(listener) = take_systemd_unix_listener() {
        info!("listening for pcsc IFD via systemd socket activation (fd 3)");
        return Ok(listener);
    }

    let listener = bind_unix_socket(socket_path)?;
    info!(socket = %socket_path.display(), "listening for pcsc IFD");
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

/// Initialize the PIV and `OpenPGP` applets from an optional TOML config file.
fn init_applets(config_path: Option<&Path>) -> io::Result<(PivApplet, PgpApplet)> {
    match config_path {
        Some(path) => {
            let card_config: CardConfig = Figment::new()
                .merge(Toml::file(path))
                .extract()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let serial = card_config.serial.unwrap_or(DEFAULT_SERIAL);
            let piv = PivApplet::from_config(&card_config.piv.unwrap_or_default(), serial)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let pgp = PgpApplet::from_config(&card_config.pgp.unwrap_or_default(), serial)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            Ok((piv, pgp))
        }
        None => Ok((PivApplet::new(), PgpApplet::new())),
    }
}

/// Serve one `VSmartCard` (`vpcd`) TCP connection until it drops.
fn serve_vpcd_connection(
    mut stream: TcpStream,
    atr: &[u8],
    piv_applet: &mut PivApplet,
    pgp_applet: &mut PgpApplet,
) -> io::Result<()> {
    let mut channels = CardChannels::new();
    let mut session = channels.session(atr, piv_applet, pgp_applet)?;

    loop {
        let Some(msg) = read_msg(&mut stream)? else {
            info!("vpcd disconnected");
            return Ok(());
        };

        if msg.len() == 1 {
            // A control command: answered, at most, with an ATR.
            match msg[0] {
                CTRL_POWER_OFF => session.power_off(),
                CTRL_POWER_ON => session.power_on(),
                CTRL_RESET => session.reset(),
                CTRL_GET_ATR => write_msg(&mut stream, session.atr())?,
                other => warn!("unknown control command 0x{other:02x}"),
            }
            continue;
        }

        match session.transmit(&msg) {
            Ok(Some(response)) => write_msg(&mut stream, &response)?,
            Ok(None) => {}
            Err(e) => warn!("{e}"),
        }
    }
}

/// Serve one direct PC/SC IFD Unix socket connection until it drops.
fn serve_pcsc_connection(
    mut stream: UnixStream,
    atr: &[u8],
    piv_applet: &mut PivApplet,
    pgp_applet: &mut PgpApplet,
) -> io::Result<()> {
    let mut channels = CardChannels::new();
    let mut session = channels.session(atr, piv_applet, pgp_applet)?;

    loop {
        let Some(req) = read_request(&mut stream).map_err(io::Error::other)? else {
            info!("pcsc IFD client disconnected");
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

/// Read one length-prefixed `VSmartCard` message; `None` on a clean close.
fn read_msg(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Write one length-prefixed `VSmartCard` message.
fn write_msg(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    let len = u16::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "message exceeds 65535 bytes"))?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sftcrd_ifd_proto::exchange;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    const SW_OK: [u8; 2] = [0x90, 0x00];
    const OPENPGP_SELECT: &[u8] = &[
        0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    ];

    fn unique_socket_path(label: &str) -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("sftcrd-test-{label}-{}-{n}.sock", std::process::id()))
    }

    fn send_apdu(stream: &mut TcpStream, apdu: &[u8]) -> Vec<u8> {
        write_msg(stream, apdu).expect("write APDU");
        read_msg(stream)
            .expect("read response")
            .expect("non-empty response")
    }

    #[test]
    fn cli_parses_vpcd_and_pcsc_subcommands() {
        let vpcd = Args::try_parse_from([
            "sftcrd",
            "vpcd",
            "--host",
            "0.0.0.0",
            "--port",
            "12345",
            "--atr",
            "3B00",
        ])
        .expect("parse vpcd");
        assert_eq!(vpcd.atr, "3B00");
        assert!(matches!(
            vpcd.command,
            Command::Vpcd { ref host, port: 12345 } if host == "0.0.0.0"
        ));

        let pcsc = Args::try_parse_from([
            "sftcrd",
            "--config",
            "/etc/sftcrd.toml",
            "pcsc",
            "--socket",
            "/tmp/test.sock",
        ])
        .expect("parse pcsc");
        assert_eq!(pcsc.config, Some(PathBuf::from("/etc/sftcrd.toml")));
        assert!(matches!(
            pcsc.command,
            Command::Pcsc { ref socket } if socket == Path::new("/tmp/test.sock")
        ));

        let cfg_ref = Args::try_parse_from(["sftcrd", "config-reference"])
            .expect("parse config-reference");
        assert!(matches!(cfg_ref.command, Command::ConfigReference));
    }

    #[test]
    fn vpcd_state_persists_across_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let atr = hex::decode(DEFAULT_ATR).expect("valid default ATR");

        let server = thread::spawn(move || {
            let (mut piv_applet, mut pgp_applet) = init_applets(None).expect("init applets");
            for _ in 0..2 {
                let (stream, _) = listener.accept().expect("accept");
                serve_vpcd_connection(stream, &atr, &mut piv_applet, &mut pgp_applet)
                    .expect("serve vpcd connection");
            }
        });

        // Connection 1: mutate both PIV and OpenPGP applet state.
        {
            let mut client = TcpStream::connect(addr).expect("connect 1");
            write_msg(&mut client, &[CTRL_POWER_ON]).expect("power on");

            let resp = send_apdu(&mut client, &keyroost_piv::select());
            assert!(resp.ends_with(&SW_OK), "PIV select failed: {resp:02X?}");

            let resp = send_apdu(
                &mut client,
                &keyroost_piv::change_reference(0x80, b"123456", b"654321")
                    .expect("change_reference apdu"),
            );
            assert_eq!(resp, SW_OK);

            let resp = send_apdu(&mut client, OPENPGP_SELECT);
            assert!(resp.ends_with(&SW_OK), "PGP select failed: {resp:02X?}");

            let wrong_pw1 = [
                0x00, 0x20, 0x00, 0x81, 0x06, b'0', b'0', b'0', b'0', b'0', b'0',
            ];
            let resp = send_apdu(&mut client, &wrong_pw1);
            assert_eq!(resp, [0x63, 0xC2]);
        }

        // Connection 2: verify mutations from connection 1 are still present.
        {
            let mut client = TcpStream::connect(addr).expect("connect 2");
            write_msg(&mut client, &[CTRL_POWER_ON]).expect("power on");

            let resp = send_apdu(&mut client, &keyroost_piv::select());
            assert!(resp.ends_with(&SW_OK), "PIV select failed: {resp:02X?}");

            let resp = send_apdu(
                &mut client,
                &keyroost_piv::verify_pin(b"654321").expect("verify_pin apdu"),
            );
            assert_eq!(resp, SW_OK);

            let resp = send_apdu(&mut client, OPENPGP_SELECT);
            assert!(resp.ends_with(&SW_OK), "PGP select failed: {resp:02X?}");

            let check_pw1_retries = [0x00, 0x20, 0x00, 0x81];
            let resp = send_apdu(&mut client, &check_pw1_retries);
            assert_eq!(resp, [0x63, 0xC2]);
        }

        server.join().expect("server thread");
    }

    fn send_pcsc_apdu(stream: &mut UnixStream, apdu: Vec<u8>) -> Vec<u8> {
        let Response::Apdu(resp) =
            exchange(stream, &Request::Transmit(apdu)).expect("pcsc transmit")
        else {
            panic!("expected Response::Apdu");
        };
        resp
    }

    #[test]
    fn pcsc_power_cycle_atr_apdus_and_state_persistence() {
        let sock_path = unique_socket_path("pcsc-state");
        let listener = bind_unix_socket(&sock_path).expect("bind unix socket");
        let atr = hex::decode(DEFAULT_ATR).expect("valid default ATR");
        let expected_atr = atr.clone();

        let server = thread::spawn(move || {
            let (mut piv_applet, mut pgp_applet) = init_applets(None).expect("init applets");
            for _ in 0..2 {
                let (stream, _) = listener.accept().expect("accept");
                serve_pcsc_connection(stream, &atr, &mut piv_applet, &mut pgp_applet)
                    .expect("serve pcsc connection");
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
                Response::Error { code: ErrorCode::NotPowered, .. }
            ));
            assert_eq!(
                exchange(&mut client, &Request::PowerOn).expect("power on"),
                Response::Atr(expected_atr.clone())
            );
            assert!(matches!(
                exchange(&mut client, &Request::Transmit(vec![0u8; 4096]))
                    .expect("oversized apdu"),
                Response::Error { code: ErrorCode::ApduTooLarge, .. }
            ));

            // Select PIV and change PIN from 123456 to 654321.
            let resp = send_pcsc_apdu(&mut client, keyroost_piv::select());
            assert!(resp.ends_with(&SW_OK), "PIV select failed: {resp:02X?}");

            let change_pin = keyroost_piv::change_reference(0x80, b"123456", b"654321")
                .expect("change_reference apdu");
            assert_eq!(send_pcsc_apdu(&mut client, change_pin), SW_OK);

            // Power off -> transmit fails -> warm reset powers back on and returns ATR.
            assert_eq!(
                exchange(&mut client, &Request::PowerOff).expect("power off"),
                Response::Ok
            );
            assert!(matches!(
                exchange(&mut client, &Request::Transmit(OPENPGP_SELECT.to_vec()))
                    .expect("transmit after power off"),
                Response::Error { code: ErrorCode::NotPowered, .. }
            ));
            assert_eq!(
                exchange(&mut client, &Request::Reset).expect("reset"),
                Response::Atr(expected_atr.clone())
            );

            // Select OpenPGP and fail PW1 verification once (retries 3 -> 2).
            let resp = send_pcsc_apdu(&mut client, OPENPGP_SELECT.to_vec());
            assert!(resp.ends_with(&SW_OK), "PGP select failed: {resp:02X?}");

            let wrong_pw1 = vec![
                0x00, 0x20, 0x00, 0x81, 0x06, b'0', b'0', b'0', b'0', b'0', b'0',
            ];
            assert_eq!(send_pcsc_apdu(&mut client, wrong_pw1), [0x63, 0xC2]);
        }

        // Connection 2: verify both PIV and OpenPGP mutations persisted across reconnect.
        {
            let mut client = UnixStream::connect(&sock_path).expect("connect 2");

            assert_eq!(
                exchange(&mut client, &Request::PowerOn).expect("power on 2"),
                Response::Atr(expected_atr)
            );
            assert!(send_pcsc_apdu(&mut client, keyroost_piv::select()).ends_with(&SW_OK));

            let verify_pin = keyroost_piv::verify_pin(b"654321").expect("verify_pin apdu");
            assert_eq!(send_pcsc_apdu(&mut client, verify_pin), SW_OK);

            assert!(send_pcsc_apdu(&mut client, OPENPGP_SELECT.to_vec()).ends_with(&SW_OK));
            assert_eq!(
                send_pcsc_apdu(&mut client, vec![0x00, 0x20, 0x00, 0x81]),
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
