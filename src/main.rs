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
use std::process::ExitCode;

use clap::Parser;
use tracing::{info, trace, warn};
use tracing_subscriber::EnvFilter;

use sftcrd::PivApplet;

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
}

fn main() -> ExitCode {
    let args = Args::parse();

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
                if let Err(e) = serve_connection(stream, &atr) {
                    warn!("connection with {addr} failed: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
}

/// Serve one vpcd connection until it drops.
fn serve_connection(mut stream: TcpStream, atr: &[u8]) -> io::Result<()> {
    // The card: the applet instance
    let mut applet = PivApplet::new();
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

            let response = match dispatch.poll(&mut [&mut applet]) {
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
