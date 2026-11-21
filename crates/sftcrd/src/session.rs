//! Transport-agnostic smartcard session managing power state, ATR, and APDU dispatch.

use std::fmt;
use std::io;

use apdu_dispatch::dispatch::ApduDispatch;
use apdu_dispatch::interchanges::{Channel, Data, Requester, SIZE as MAX_APDU_LEN};
use sftcrd_pgp::PgpApplet;
use sftcrd_piv::PivApplet;
use tracing::{debug, trace};

/// Error returned by [`CardSession::transmit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransmitError {
    /// The card is currently powered off.
    NotPowered,
    /// The command APDU exceeds the maximum interchange buffer size.
    ApduTooLarge {
        /// Actual APDU length in bytes.
        len: usize,
        /// Maximum supported APDU length in bytes.
        max: usize,
    },
    /// Internal APDU dispatch failure.
    Internal(String),
}

impl fmt::Display for TransmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPowered => write!(f, "card is powered off"),
            Self::ApduTooLarge { len, max } => {
                write!(f, "command too large: expected up to {max}, got {len} bytes")
            }
            Self::Internal(msg) => write!(f, "internal APDU dispatch error: {msg}"),
        }
    }
}

impl std::error::Error for TransmitError {}

/// Backing `apdu-dispatch` interchanges for a [`CardSession`].
pub struct CardChannels {
    contact: Channel,
    contactless: Channel,
}

impl Default for CardChannels {
    fn default() -> Self {
        Self::new()
    }
}

impl CardChannels {
    /// Allocate a fresh pair of contact and contactless interchange channels.
    #[must_use]
    pub fn new() -> Self {
        Self {
            contact: Channel::new(),
            contactless: Channel::new(),
        }
    }

    /// Create a [`CardSession`] borrowing these channels and the given applets.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the underlying channels were already split.
    pub fn session<'a>(
        &'a mut self,
        atr: &'a [u8],
        piv_applet: &'a mut PivApplet,
        pgp_applet: &'a mut PgpApplet,
    ) -> io::Result<CardSession<'a>> {
        CardSession::new(self, atr, piv_applet, pgp_applet)
    }
}

/// Transport-agnostic smartcard session for a single client connection.
///
/// Manages power state, ATR storage, and APDU routing to [`PivApplet`] and
/// [`PgpApplet`] via `apdu-dispatch`, without any dependency on TCP or
/// `VSmartCard` framing.
pub struct CardSession<'a> {
    power_on: bool,
    atr: &'a [u8],
    piv_applet: &'a mut PivApplet,
    pgp_applet: &'a mut PgpApplet,
    contact_requester: Requester<'a>,
    dispatch: ApduDispatch<'a>,
}

impl<'a> CardSession<'a> {
    /// Create a new powered-off session backed by the given channels, ATR, and applets.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if the internal `apdu-dispatch` channels
    /// cannot be initialized.
    pub fn new(
        channels: &'a mut CardChannels,
        atr: &'a [u8],
        piv_applet: &'a mut PivApplet,
        pgp_applet: &'a mut PgpApplet,
    ) -> io::Result<Self> {
        let Some((contact_requester, contact_rp)) = channels.contact.split() else {
            return Err(io::Error::other("cannot create contact channel"));
        };
        let Some((_, contactless_rp)) = channels.contactless.split() else {
            return Err(io::Error::other("cannot create contactless channel"));
        };
        let dispatch = ApduDispatch::new(contact_rp, contactless_rp);

        Ok(Self {
            power_on: false,
            atr,
            piv_applet,
            pgp_applet,
            contact_requester,
            dispatch,
        })
    }

    /// Power on the card.
    pub fn power_on(&mut self) {
        self.power_on = true;
        debug!("power on");
    }

    /// Power off the card.
    pub fn power_off(&mut self) {
        self.power_on = false;
        debug!("power off");
    }

    /// Reset the card and ensure it is powered on.
    pub fn reset(&mut self) {
        self.power_on = true;
        debug!("reset");
    }

    /// Return whether the card is currently powered on.
    #[must_use]
    pub const fn is_powered_on(&self) -> bool {
        self.power_on
    }

    /// Return the configured Answer-To-Reset (ATR) bytes.
    #[must_use]
    pub const fn atr(&self) -> &[u8] {
        self.atr
    }

    /// Transmit a command APDU to the active applet and return the response APDU.
    ///
    /// Returns `Ok(None)` if the dispatch cycle produced no response.
    ///
    /// # Errors
    ///
    /// Returns [`TransmitError::NotPowered`] if the card is powered off,
    /// [`TransmitError::ApduTooLarge`] if `apdu` exceeds the interchange buffer,
    /// or [`TransmitError::Internal`] if queuing the request fails.
    pub fn transmit(&mut self, apdu: &[u8]) -> Result<Option<Vec<u8>>, TransmitError> {
        if !self.power_on {
            return Err(TransmitError::NotPowered);
        }

        let Ok(data) = Data::from_slice(apdu) else {
            return Err(TransmitError::ApduTooLarge {
                len: apdu.len(),
                max: MAX_APDU_LEN,
            });
        };

        trace!(apdu = hex::encode_upper(&data), "APDU command");

        if let Err(e) = self.contact_requester.request(data) {
            return Err(TransmitError::Internal(format!(
                "failed to send request: {e:?}"
            )));
        }

        let response = match self.dispatch.poll(&mut [self.piv_applet, self.pgp_applet]) {
            Some(iso7816::Interface::Contact) => self.contact_requester.take_response(),
            Some(iso7816::Interface::Contactless) => unreachable!("contactless is unused"),
            None => None,
        };

        if let Some(ref resp) = response {
            trace!(sw = hex::encode_upper(resp), "APDU response");
        }

        Ok(response.map(|resp| resp.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SW_OK: [u8; 2] = [0x90, 0x00];
    const OPENPGP_SELECT: &[u8] = &[
        0x00, 0xA4, 0x04, 0x00, 0x06, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
    ];

    #[test]
    fn power_state_and_atr() {
        let atr = [0x3B, 0xFD, 0x13];
        let mut piv = PivApplet::new();
        let mut pgp = PgpApplet::new();
        let mut channels = CardChannels::new();
        let mut session = channels.session(&atr, &mut piv, &mut pgp).expect("create session");

        assert_eq!(session.atr(), &atr);
        assert!(!session.is_powered_on());

        assert_eq!(
            session.transmit(&keyroost_piv::select()),
            Err(TransmitError::NotPowered)
        );

        session.power_on();
        assert!(session.is_powered_on());

        let resp = session
            .transmit(&keyroost_piv::select())
            .expect("transmit while powered on")
            .expect("response APDU");
        assert!(resp.ends_with(&SW_OK), "PIV select failed: {resp:02X?}");

        session.reset();
        let resp = session
            .transmit(OPENPGP_SELECT)
            .expect("transmit after reset")
            .expect("response APDU");
        assert!(resp.ends_with(&SW_OK), "PGP select failed: {resp:02X?}");

        session.power_off();
        assert!(!session.is_powered_on());
        assert_eq!(
            session.transmit(&keyroost_piv::select()),
            Err(TransmitError::NotPowered)
        );
    }

    #[test]
    fn rejects_oversized_apdu() {
        let mut piv = PivApplet::new();
        let mut pgp = PgpApplet::new();
        let mut channels = CardChannels::new();
        let mut session = channels.session(&[0x3B], &mut piv, &mut pgp).expect("create session");
        session.power_on();

        let oversized = vec![0u8; MAX_APDU_LEN + 1];
        assert_eq!(
            session.transmit(&oversized),
            Err(TransmitError::ApduTooLarge {
                len: MAX_APDU_LEN + 1,
                max: MAX_APDU_LEN,
            })
        );
    }

    #[test]
    fn applet_state_persists_across_sessions() {
        let atr = [0x3B, 0xFD, 0x13];
        let mut piv = PivApplet::new();
        let mut pgp = PgpApplet::new();

        {
            let mut channels = CardChannels::new();
            let mut session = channels.session(&atr, &mut piv, &mut pgp).expect("session 1");
            session.power_on();

            let resp = session
                .transmit(&keyroost_piv::select())
                .expect("PIV select")
                .expect("response");
            assert!(resp.ends_with(&SW_OK));

            let change_pin = keyroost_piv::change_reference(0x80, b"123456", b"654321")
                .expect("change_reference apdu");
            let resp = session.transmit(&change_pin).expect("change pin").expect("response");
            assert_eq!(resp, SW_OK);
        }

        {
            let mut channels = CardChannels::new();
            let mut session = channels.session(&atr, &mut piv, &mut pgp).expect("session 2");
            session.power_on();

            let resp = session
                .transmit(&keyroost_piv::select())
                .expect("PIV select")
                .expect("response");
            assert!(resp.ends_with(&SW_OK));

            let verify_pin = keyroost_piv::verify_pin(b"654321").expect("verify_pin apdu");
            let resp = session.transmit(&verify_pin).expect("verify pin").expect("response");
            assert_eq!(resp, SW_OK);
        }
    }
}
