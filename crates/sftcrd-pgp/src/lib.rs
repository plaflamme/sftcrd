//! `OpenPGP` Card v3.4 applet, in pure Rust.
//!
//! This is the card-side counterpart to [`keyroost-openpgp`]: it receives raw
//! ISO 7816-4 APDUs (or [`apdu_app::App`] calls), maintains PIN state (PW1,
//! RC, PW3), and produces card responses without performing any I/O.

#![forbid(unsafe_code)]

mod auth;
mod constants;
mod pin;

use iso7816::{Instruction, Status};
use pin::PinState;
pub use pin::PwRef;
pub use sftcrd_apdu::Response;
use sftcrd_apdu::{CommandView, Trace};

pub use constants::{AID_PREFIX, DEFAULT_SERIAL, MANUFACTURER_ID, OPENPGP_VERSION, build_aid};

/// An `OpenPGP` Card v3.4 applet instance.
pub struct PgpApplet {
    /// Full 16-byte `OpenPGP` Card AID.
    aid: [u8; 16],
    /// PIN secrets, retry counters, and session verification flags.
    pub(crate) pins: PinState,
}

impl Default for PgpApplet {
    fn default() -> Self {
        Self::new()
    }
}

impl iso7816::App for PgpApplet {
    fn aid(&self) -> iso7816::Aid {
        iso7816::Aid::new_truncatable(&self.aid, AID_PREFIX.len())
    }
}

impl apdu_app::App for PgpApplet {
    fn select(
        &mut self,
        _interface: iso7816::Interface,
        apdu: apdu_app::CommandView<'_>,
        _reply: &mut apdu_app::VecView<u8>,
    ) -> apdu_app::Result {
        tracing::debug!(
            class = %Trace::Byte(apdu.class().into_inner()),
            ins = %Trace::Ins(apdu.instruction()),
            p1 = %Trace::Byte(apdu.p1),
            p2 = %Trace::Byte(apdu.p2),
            "select"
        );

        self.pins.session_end();
        Ok(())
    }

    fn deselect(&mut self) {
        tracing::debug!("deselect");
        self.pins.session_end();
    }

    fn call(
        &mut self,
        _interface: iso7816::Interface,
        apdu: apdu_app::CommandView<'_>,
        reply: &mut apdu_app::VecView<u8>,
    ) -> apdu_app::Result {
        tracing::debug!(
            class = %Trace::Byte(apdu.class().into_inner()),
            ins = %Trace::Ins(apdu.instruction()),
            p1 = %Trace::Byte(apdu.p1),
            p2 = %Trace::Byte(apdu.p2),
            le = apdu.expected(),
            data = %Trace::Slice(apdu.data()),
            "call"
        );

        match self.process_command(&apdu).into_inner() {
            apdu_dispatch::Response::Data(d) => {
                tracing::debug!(data = %Trace::Slice(d.as_slice()), "reply");
                reply.extend(d);
            }
            apdu_dispatch::Response::Status(s) => {
                tracing::debug!(status = ?s, "reply");
                return Err(s);
            }
        }

        Ok(())
    }
}

impl PgpApplet {
    /// Create a factory-fresh `OpenPGP` Card v3.4 applet with [`DEFAULT_SERIAL`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_serial(DEFAULT_SERIAL)
    }

    /// Create a factory-fresh `OpenPGP` Card v3.4 applet with the given 32-bit serial.
    #[must_use]
    pub fn with_serial(serial: u32) -> Self {
        Self {
            aid: build_aid(serial),
            pins: PinState::default(),
        }
    }

    /// Returns the full 16-byte `OpenPGP` Card AID.
    #[must_use]
    pub fn full_aid(&self) -> &[u8; 16] {
        &self.aid
    }

    /// Returns whether PW1 (`0x81`) remains valid for multiple `PSO:CDS` commands.
    #[must_use]
    pub fn pw1_valid_multiple(&self) -> bool {
        self.pins.pw1_valid_multiple()
    }

    /// Configure the optional Resetting Code (RC, min 8 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Status::WrongLength`] if `rc` is shorter than 8 bytes or longer
    /// than 127 bytes.
    pub fn set_resetting_code(&mut self, rc: &[u8]) -> Result<(), Status> {
        self.pins.set_rc(rc)
    }

    /// Parse and process a raw APDU byte slice.
    pub fn process(&mut self, apdu: &[u8]) -> Response {
        let command = match CommandView::try_from(apdu) {
            Ok(command) => command,
            Err(
                iso7816::command::FromSliceError::TooLong
                | iso7816::command::FromSliceError::TooShort
                | iso7816::command::FromSliceError::InvalidSliceLength
                | iso7816::command::FromSliceError::InvalidFirstBodyByteForExtended,
            ) => return Status::WrongLength.into(),
            Err(iso7816::command::FromSliceError::InvalidClass) => {
                return Status::ClassNotSupported.into();
            }
        };
        self.process_command(&command)
    }

    /// Process a parsed [`CommandView`].
    pub fn process_command(&mut self, command: &CommandView<'_>) -> Response {
        if command.class().chain().not_the_last() {
            return Status::ClaNotSupported.into();
        }

        if matches!(
            command.class().range(),
            iso7816::command::class::Range::Proprietary
        ) {
            return Status::ClaNotSupported.into();
        }

        match command.instruction() {
            Instruction::Verify => self.process_verify(command),
            Instruction::ChangeReferenceData => self.process_change_reference_data(command),
            Instruction::ResetRetryCounter => self.process_reset_retry_counter(command),
            _ => Status::InstructionNotSupportedOrInvalid.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use iso7816::App as _;

    use super::*;

    #[test]
    fn aid_matches_openpgp_v34_layout() {
        let applet = PgpApplet::with_serial(0x0102_0304);
        let expected: [u8; 16] = [
            0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, // OpenPGP RID + PIX
            0x03, 0x04, // version 3.4
            0x00, 0x06, // manufacturer 0006
            0x01, 0x02, 0x03, 0x04, // serial
            0x00, 0x00, // RFU
        ];
        assert_eq!(applet.full_aid(), &expected);
        assert_eq!(applet.aid().as_bytes(), &expected);
        assert!(applet.aid().matches(&AID_PREFIX));
    }

    #[test]
    fn rejects_unchained_cla_bit_directly() {
        let mut applet = PgpApplet::new();
        let chunk = [0x10, 0x20, 0x00, 0x81, 0x03, b'1', b'2', b'3'];
        assert_eq!(applet.process(&chunk).status(), Status::ClaNotSupported);
    }
}
