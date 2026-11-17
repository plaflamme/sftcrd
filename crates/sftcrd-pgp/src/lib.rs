//! `OpenPGP` Card v3.4 applet, in pure Rust.
//!
//! This is the card-side counterpart to [`keyroost-openpgp`]: it receives raw
//! ISO 7816-4 APDUs (or [`apdu_app::App`] calls), handles command chaining,
//! maintains PIN state (PW1, RC, PW3), and produces card responses without
//! performing any I/O.

#![forbid(unsafe_code)]

mod apdu;
mod auth;
mod constants;
mod pin;
mod trace;

pub use apdu::Response;
pub use constants::{AID_PREFIX, DEFAULT_SERIAL, MANUFACTURER_ID, OPENPGP_VERSION, build_aid};
use iso7816::{Instruction, Status};
pub use pin::InvalidPinLength;
use pin::{PinState, Pw1Validity};
use trace::Trace;
use zeroize::Zeroizing;

use crate::apdu::Command;

/// Maximum total payload size accepted across a chained APDU sequence.
const MAX_CHAIN_LEN: usize = 4096;

/// An `OpenPGP` Card v3.4 applet instance.
pub struct PgpApplet {
    /// Full 16-byte `OpenPGP` Card AID.
    aid: [u8; 16],
    /// PIN secrets, retry counters, and session verification flags.
    pub(crate) pins: PinState,
    /// `(ins, p1, p2)` of an in-progress ISO 7816 command chain.
    chain_header: Option<(u8, u8, u8)>,
    /// Reassembly buffer for ISO 7816 command chaining (`CLA & 0x10 != 0`).
    chain_buffer: Zeroizing<Vec<u8>>,
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

        self.reset_session();
        Ok(())
    }

    fn deselect(&mut self) {
        tracing::debug!("deselect");
        self.reset_session();
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
            chain_header: None,
            chain_buffer: Zeroizing::new(Vec::new()),
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
        self.pins.pw1_validity == Pw1Validity::Multiple
    }

    /// Configure the optional Resetting Code (RC, min 8 bytes).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPinLength`] if `rc` is shorter than 8 bytes or longer
    /// than 127 bytes.
    pub fn set_resetting_code(&mut self, rc: &[u8]) -> Result<(), InvalidPinLength> {
        self.pins.rc.set(rc)
    }

    fn reset_session(&mut self) {
        self.pins.session_end();
        self.clear_chain();
    }

    fn clear_chain(&mut self) {
        self.chain_header = None;
        self.chain_buffer.clear();
    }

    /// Parse and process a raw APDU byte slice.
    pub fn process(&mut self, apdu: &[u8]) -> Response {
        let command = match apdu::CommandView::try_from(apdu) {
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

    /// Process a parsed [`apdu::CommandView`], handling ISO 7816 command chaining.
    pub fn process_command(&mut self, command: &apdu::CommandView<'_>) -> Response {
        if matches!(
            command.class().range(),
            iso7816::command::class::Range::Proprietary
        ) {
            self.clear_chain();
            return Status::ClaNotSupported.into();
        }

        let ins = u8::from(command.instruction());
        let header = (ins, command.p1, command.p2);

        if command.class().chain().not_the_last() {
            if let Some(expected) = self.chain_header
                && expected != header
            {
                self.clear_chain();
                return Status::ConditionsOfUseNotSatisfied.into();
            }
            if self.chain_buffer.len() + command.data().len() > MAX_CHAIN_LEN {
                self.clear_chain();
                return Status::WrongLength.into();
            }
            self.chain_header = Some(header);
            self.chain_buffer.extend_from_slice(command.data());
            return Status::Success.into();
        }

        if let Some(expected) = self.chain_header.take() {
            if expected != header {
                self.chain_buffer.clear();
                return Status::ConditionsOfUseNotSatisfied.into();
            }
            if self.chain_buffer.len() + command.data().len() > MAX_CHAIN_LEN {
                self.chain_buffer.clear();
                return Status::WrongLength.into();
            }
            self.chain_buffer.extend_from_slice(command.data());
            let assembled = Zeroizing::new(std::mem::take(&mut *self.chain_buffer));
            return self.dispatch_command(&Command {
                ins,
                p1: command.p1,
                p2: command.p2,
                data: &assembled,
            });
        }

        self.dispatch_command(&Command {
            ins,
            p1: command.p1,
            p2: command.p2,
            data: command.data(),
        })
    }

    fn dispatch_command(&mut self, cmd: &Command<'_>) -> Response {
        match Instruction::from(cmd.ins) {
            Instruction::Verify => self.process_verify(cmd),
            Instruction::ChangeReferenceData => self.process_change_reference_data(cmd),
            Instruction::ResetRetryCounter => self.process_reset_retry_counter(cmd),
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
    fn command_chaining_reassembles_verify_apdu() {
        let mut applet = PgpApplet::new();

        // First chunk: CLA=0x10 (chaining), INS=0x20 (VERIFY), P1=0x00, P2=0x81, "123"
        let chunk1 = [0x10, 0x20, 0x00, 0x81, 0x03, b'1', b'2', b'3'];
        assert_eq!(applet.process(&chunk1).status(), Status::Success);

        // Not yet verified until final chunk arrives
        // (Send final chunk: CLA=0x00, INS=0x20, P1=0x00, P2=0x81, "456")
        let chunk2 = [0x00, 0x20, 0x00, 0x81, 0x03, b'4', b'5', b'6'];
        assert_eq!(applet.process(&chunk2).status(), Status::Success);

        // Status query confirms PW1_SIGN is now verified
        assert_eq!(
            applet.process(&[0x00, 0x20, 0x00, 0x81]).status(),
            Status::Success
        );
    }

    #[test]
    fn command_chaining_rejects_mismatched_header_and_clears_buffer() {
        let mut applet = PgpApplet::new();

        let chunk1 = [0x10, 0x20, 0x00, 0x81, 0x03, b'1', b'2', b'3'];
        assert_eq!(applet.process(&chunk1).status(), Status::Success);

        // Mismatched P2 in final chunk -> ConditionsNotSatisfied (6985)
        let bad_chunk2 = [0x00, 0x20, 0x00, 0x82, 0x03, b'4', b'5', b'6'];
        assert_eq!(
            applet.process(&bad_chunk2).status(),
            Status::ConditionsOfUseNotSatisfied
        );

        // Buffer was cleared; subsequent unchained VERIFY works normally
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(
                    keyroost_openpgp::PW1_SIGN,
                    b"123456"
                ))
                .status(),
            Status::Success
        );
    }
}
