//! `VSmartCard` (`vpcd`) TCP transport.
//!
//! `VSmartCard` is a length-prefixed TCP protocol in both directions: a
//! big-endian `u16` count, then exactly that many payload bytes.
//!
//! * One-byte payloads are control commands: `0x00` (power off), `0x01`
//!   (power on), `0x02` (reset), or `0x04` (get ATR).
//! * All other payloads are command APDUs answered with the response APDU.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;

use tracing::{info, warn};

use crate::{CardChannels, PgpApplet, PivApplet};

// VSmartCard control commands (driver -> card, one-byte payload).
const CTRL_POWER_OFF: u8 = 0x00;
const CTRL_POWER_ON: u8 = 0x01;
const CTRL_RESET: u8 = 0x02;
const CTRL_GET_ATR: u8 = 0x04;

/// Run the `VSmartCard` (`vpcd`) TCP listener loop.
pub fn run(
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
                if let Err(e) = serve_connection(stream, atr, piv_applet, pgp_applet) {
                    warn!("connection with {addr} failed: {e}");
                }
            }
            Err(e) => warn!("accept failed: {e}"),
        }
    }
}

/// Serve one `VSmartCard` (`vpcd`) TCP connection until it drops.
///
/// # Errors
///
/// Returns an [`io::Error`] if reading or writing messages or initializing
/// [`CardChannels`] fails.
pub fn serve_connection(
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
    use std::thread;

    const DEFAULT_ATR: &str = "3BFD1300008131FE158073C021C057597562694B657940";
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
            let mut piv_applet = PivApplet::new();
            let mut pgp_applet = PgpApplet::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().expect("accept");
                serve_connection(stream, &atr, &mut piv_applet, &mut pgp_applet)
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
}
