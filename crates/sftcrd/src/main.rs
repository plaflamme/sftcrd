//! `VSmartCard` front end: presents [`PivApplet`] as a PC/SC card.
//!
//! This binary is the `vpicc` (virtual ICC) side of the `VSmartCard`
//! architecture: it listens on a TCP port; the `vpcd` PC/SC reader driver
//! should be configured to connect to the listening socket exposed by this
//! server.
//!
//! # Wire protocol
//!
//! `VSmartCard` is a length-prefixed TCP protocol in both directions: a
//! big-endian `u16` count, then exactly that many payload bytes.
//!
//! * The driver sends a one-byte control message: `0x00` (power off),
//!   `0x01` (power on) or `0x02` (reset) — none of the three is
//!   answered — or `0x04` (get ATR), answered with the ATR bytes. An
//!   empty answer would mean "card absent"; this front end is always
//!   present.
//! * Every other message is a command APDU. The answer is the response
//!   APDU: the response data, followed by the two-byte status word.
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use figment::Figment;
use figment::providers::{Format, Toml};
use tracing::{info, trace, warn};
use tracing_subscriber::EnvFilter;

use sftcrd::{CardConfig, DEFAULT_SERIAL, PgpApplet, PivApplet};
use toml_example::TomlExample;

/// The ATR of a `YubiKey` 5.7
const DEFAULT_ATR: &str = "3BFD1300008131FE158073C021C057597562694B657940";

// VSmartCard control commands (driver → card, one-byte payload).
const CTRL_POWER_OFF: u8 = 0x00;
const CTRL_POWER_ON: u8 = 0x01;
const CTRL_RESET: u8 = 0x02;
const CTRL_GET_ATR: u8 = 0x04;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "sftcrd",
    version,
    about = "Present the a PIV applet as a PC/SC card via VSmartCard"
)]
struct Args {
    /// Host to bind the listener on.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port to listen on.
    #[arg(long, default_value_t = 35963u16)]
    port: u16,

    /// ATR presented to PC/SC clients, as a hex string.
    #[arg(long, default_value = DEFAULT_ATR)]
    atr: String,

    /// Path to a TOML configuration file to initialize the card state.
    #[arg(short, long)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Print the reference TOML configuration wrapped in a Markdown code block.
    #[command(hide = true)]
    ConfigReference,
}

fn main() -> ExitCode {
    let args = Args::parse();

    if let Some(Command::ConfigReference) = args.command {
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

    // We are the vpicc listener: vpcd is configured in connect mode and
    // dials us.
    let listener = match TcpListener::bind((args.host.as_str(), args.port)) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(host = %args.host, port = args.port, "cannot bind: {e}");
            return ExitCode::FAILURE;
        }
    };

    info!(host = %args.host, port = args.port, "listening for vpcd");

    loop {
        match listener.accept() {
            Ok((stream, addr)) => {
                info!(%addr, "vpcd connected");
                if let Err(e) = serve_connection(stream, &atr, &mut piv_applet, &mut pgp_applet) {
                    warn!("connection with {addr} failed: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
}

/// Initialize the PIV and `OpenPGP` applets from an optional TOML config file.
fn init_applets(config_path: Option<&std::path::Path>) -> io::Result<(PivApplet, PgpApplet)> {
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

/// Serve one vpcd connection until it drops.
fn serve_connection(
    mut stream: TcpStream,
    atr: &[u8],
    piv_applet: &mut PivApplet,
    pgp_applet: &mut PgpApplet,
) -> io::Result<()> {
    let mut power_on = false;

    let contact = apdu_dispatch::interchanges::Channel::new();
    let Some((mut contact_requester, contact_rp)) = contact.split() else {
        return Err(io::Error::other("cannot create channel"));
    };
    let contactless = apdu_dispatch::interchanges::Channel::new();
    let Some((_, contactless_rp)) = contactless.split() else {
        return Err(io::Error::other("cannot create channel"));
    };
    let mut dispatch = apdu_dispatch::dispatch::ApduDispatch::new(contact_rp, contactless_rp);

    loop {
        let Some(msg) = read_msg(&mut stream)? else {
            info!("vpcd disconnected");
            return Ok(());
        };

        if msg.len() == 1 {
            // A control command: answered, at most, with an ATR.
            match msg[0] {
                CTRL_POWER_OFF => {
                    power_on = false;
                    tracing::debug!("power off");
                }
                CTRL_POWER_ON => {
                    power_on = true;
                    tracing::debug!("power on");
                }
                CTRL_RESET => tracing::debug!("reset"),
                CTRL_GET_ATR => write_msg(&mut stream, atr)?,
                other => warn!("unknown control command 0x{other:02x}"),
            }
            continue;
        }

        if power_on {
            let Ok(data) = apdu_dispatch::interchanges::Data::from_slice(&msg) else {
                warn!(
                    "command too large. Expected up to {}, got {} bytes",
                    apdu_dispatch::interchanges::SIZE,
                    msg.len(),
                );
                continue;
            };

            trace!(apdu = hex::encode_upper(&data), "APDU command");

            // NOTE: presumably, reading and writing should run in their own thread.
            match contact_requester.request(data) {
                Ok(()) => (),
                Err(e) => {
                    warn!("failed to send request: {e:?}");
                    continue;
                }
            }

            let response = match dispatch.poll(&mut [piv_applet, pgp_applet]) {
                Some(iso7816::Interface::Contact) => contact_requester.take_response(),
                Some(iso7816::Interface::Contactless) => unreachable!("contactless is unused"),
                None => continue,
            };

            if let Some(response) = response {
                trace!(sw = hex::encode_upper(&response), "APDU response");
                write_msg(&mut stream, &response)?;
            }
        } else {
            warn!("command APDU while powered off");
        }
    }
}

/// Read one length-prefixed message; `None` on a clean close.
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

/// Write one length-prefixed message.
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
    use std::thread;

    const SW_OK: [u8; 2] = [0x90, 0x00];
    const OPENPGP_SELECT: &[u8] = &[
        0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    ];

    fn send_apdu(stream: &mut TcpStream, apdu: &[u8]) -> Vec<u8> {
        write_msg(stream, apdu).expect("write APDU");
        read_msg(stream)
            .expect("read response")
            .expect("non-empty response")
    }

    #[test]
    fn state_persists_across_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let atr = hex::decode(DEFAULT_ATR).expect("valid default ATR");

        let server = thread::spawn(move || {
            let (mut piv_applet, mut pgp_applet) = init_applets(None).expect("init applets");
            for _ in 0..2 {
                let (stream, _) = listener.accept().expect("accept");
                serve_connection(stream, &atr, &mut piv_applet, &mut pgp_applet)
                    .expect("serve connection");
            }
        });

        // Connection 1: mutate both PIV and OpenPGP applet state.
        {
            let mut client = TcpStream::connect(addr).expect("connect 1");
            write_msg(&mut client, &[CTRL_POWER_ON]).expect("power on");

            // Select PIV and change PIN from 123456 to 654321.
            let resp = send_apdu(&mut client, &keyroost_piv::select());
            assert!(resp.ends_with(&SW_OK), "PIV select failed: {resp:02X?}");

            let resp = send_apdu(
                &mut client,
                &keyroost_piv::change_reference(0x80, b"123456", b"654321")
                    .expect("change_reference apdu"),
            );
            assert_eq!(resp, SW_OK);

            // Select OpenPGP and fail PW1 verification once (retries 3 -> 2).
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

            // PIV PIN must still be 654321.
            let resp = send_apdu(&mut client, &keyroost_piv::select());
            assert!(resp.ends_with(&SW_OK), "PIV select failed: {resp:02X?}");

            let resp = send_apdu(
                &mut client,
                &keyroost_piv::verify_pin(b"654321").expect("verify_pin apdu"),
            );
            assert_eq!(resp, SW_OK);

            // OpenPGP PW1 retry counter must still be 2.
            let resp = send_apdu(&mut client, OPENPGP_SELECT);
            assert!(resp.ends_with(&SW_OK), "PGP select failed: {resp:02X?}");

            let check_pw1_retries = [0x00, 0x20, 0x00, 0x81];
            let resp = send_apdu(&mut client, &check_pw1_retries);
            assert_eq!(resp, [0x63, 0xC2]);
        }

        server.join().expect("server thread");
    }
}
