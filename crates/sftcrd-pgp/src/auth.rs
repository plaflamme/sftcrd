//! VERIFY (0x20), CHANGE REFERENCE DATA (0x24), and RESET RETRY COUNTER (0x2C).

use iso7816::Status;
use sftcrd_apdu::CommandView;

use crate::{
    PgpApplet, Response,
    pin::{MAX_PIN_LEN, PW1_MIN_LEN, PwRef},
};

impl PgpApplet {
    /// `VERIFY` (`0x20`): verify PW1 (`0x81`/`0x82`) or PW3 (`0x83`), query
    /// verification/retry status (`Lc = 0`), or clear verification (`P1 = 0xFF`).
    pub(crate) fn process_verify(&mut self, cmd: &CommandView<'_>) -> Response {
        match cmd.p1 {
            0xFF => self.verify_clear(cmd.p2, cmd.data()),
            0x00 => self.verify_present_or_status(cmd.p2, cmd.data()),
            _ => Status::IncorrectP1OrP2Parameter.into(),
        }
    }

    fn verify_clear(&mut self, p2: u8, data: &[u8]) -> Response {
        if !data.is_empty() {
            return Status::WrongLength.into();
        }
        let Some(pw_ref) = PwRef::from_u8(p2) else {
            return Status::KeyReferenceNotFound.into();
        };
        self.pins.clear_verified(pw_ref);
        Status::Success.into()
    }

    fn verify_present_or_status(&mut self, p2: u8, data: &[u8]) -> Response {
        let Some(pw_ref) = PwRef::from_u8(p2) else {
            return Status::KeyReferenceNotFound.into();
        };
        let slot = self.pins.slot(pw_ref);

        if data.is_empty() {
            return if self.pins.is_verified(pw_ref) {
                Status::Success.into()
            } else if slot.tries() == 0 {
                Status::OperationBlocked.into()
            } else {
                Status::RemainingRetries(slot.tries()).into()
            };
        }

        if slot.tries() == 0 {
            return Status::OperationBlocked.into();
        }

        if data.len() < slot.min_len() || data.len() > MAX_PIN_LEN {
            return Status::WrongLength.into();
        }

        match self.pins.verify(pw_ref, data) {
            Ok(()) => Status::Success.into(),
            Err(tries) => Status::RemainingRetries(tries).into(),
        }
    }

    /// `CHANGE REFERENCE DATA` (`0x24`): change PW1 (`P2 = 0x81`) or PW3 (`P2 = 0x83`).
    pub(crate) fn process_change_reference_data(&mut self, cmd: &CommandView<'_>) -> Response {
        if cmd.p1 != 0x00 {
            return Status::IncorrectP1OrP2Parameter.into();
        }

        let pw_ref = match PwRef::from_u8(cmd.p2) {
            Some(r @ (PwRef::Pw1Sign | PwRef::Pw3Admin)) => r,
            Some(PwRef::Pw1Other) | None => return Status::KeyReferenceNotFound.into(),
        };
        let slot = self.pins.slot_mut(pw_ref);
        let min_len = slot.min_len();
        let new_pin = match slot.check_prefix(cmd.data(), min_len) {
            Ok(rest) => rest,
            Err(status) => return status.into(),
        };
        if !slot.is_valid_new_pin(new_pin) {
            return Status::WrongLength.into();
        }
        slot.set_value(new_pin);
        Status::Success.into()
    }

    /// `RESET RETRY COUNTER` (`0x2C`): unblock PW1 (`P2 = 0x81`) using RC
    /// (`P1 = 0x00`) or verified PW3 (`P1 = 0x02`).
    pub(crate) fn process_reset_retry_counter(&mut self, cmd: &CommandView<'_>) -> Response {
        if PwRef::from_u8(cmd.p2) != Some(PwRef::Pw1Sign) {
            return Status::KeyReferenceNotFound.into();
        }

        match cmd.p1 {
            0x00 => self.reset_pw1_by_rc(cmd.data()),
            0x02 => self.reset_pw1_by_admin(cmd.data()),
            _ => Status::IncorrectP1OrP2Parameter.into(),
        }
    }

    fn reset_pw1_by_rc(&mut self, data: &[u8]) -> Response {
        let Some(rc) = self.pins.rc_mut() else {
            return Status::OperationBlocked.into();
        };
        match rc.check_prefix(data, PW1_MIN_LEN) {
            Ok(new_pw1) => self.reset_pw1(new_pw1),
            Err(status) => status.into(),
        }
    }

    fn reset_pw1_by_admin(&mut self, new_pw1: &[u8]) -> Response {
        if !self.pins.is_verified(PwRef::Pw3Admin) {
            return Status::SecurityStatusNotSatisfied.into();
        }
        self.reset_pw1(new_pw1)
    }

    fn reset_pw1(&mut self, new_pw1: &[u8]) -> Response {
        let pw1 = self.pins.slot_mut(PwRef::Pw1Sign);
        if !pw1.is_valid_new_pin(new_pw1) {
            return Status::WrongLength.into();
        }
        pw1.set_value(new_pw1);
        Status::Success.into()
    }
}

#[cfg(test)]
mod tests {
    use apdu_app::App as _;
    use iso7816::Status;
    use keyroost_openpgp::{PW1_OTHER, PW1_SIGN, PW3_ADMIN};

    use super::*;

    fn select_applet(applet: &mut PgpApplet) {
        let select_apdu = keyroost_openpgp::select();
        let cmd = CommandView::try_from(select_apdu.as_slice()).unwrap();
        let mut reply = apdu_dispatch::response::Data::new();
        applet
            .select(iso7816::Interface::Contactless, cmd, &mut reply)
            .unwrap();
    }

    fn block_pw1(applet: &mut PgpApplet) {
        for tries in (1..=3u8).rev() {
            let resp = applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"000000"));
            assert_eq!(resp.status(), Status::RemainingRetries(tries - 1));
        }
    }

    #[test]
    fn verify_default_pw1_and_pw3() {
        let mut applet = PgpApplet::new();

        let resp = applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"123456"));
        assert_eq!(resp.status(), Status::Success);

        let resp = applet.process(&keyroost_openpgp::verify(PW1_OTHER, b"123456"));
        assert_eq!(resp.status(), Status::Success);

        let resp = applet.process(&keyroost_openpgp::verify(PW3_ADMIN, b"12345678"));
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn pw1_sign_and_other_flags_are_independent() {
        let mut applet = PgpApplet::new();

        // Verify PW1_SIGN only
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_SIGN, b"123456"))
                .status(),
            Status::Success
        );
        // Status query on PW1_SIGN -> 9000
        assert_eq!(
            applet.process(&[0x00, 0x20, 0x00, PW1_SIGN]).status(),
            Status::Success
        );
        // Status query on PW1_OTHER -> still unverified (63C3)
        assert_eq!(
            applet.process(&[0x00, 0x20, 0x00, PW1_OTHER]).status(),
            Status::RemainingRetries(3)
        );

        // Clear PW1_SIGN with P1=0xFF
        assert_eq!(
            applet.process(&[0x00, 0x20, 0xFF, PW1_SIGN]).status(),
            Status::Success
        );
        assert_eq!(
            applet.process(&[0x00, 0x20, 0x00, PW1_SIGN]).status(),
            Status::RemainingRetries(3)
        );
    }

    #[test]
    fn verify_wrong_pin_decrements_and_blocks_then_correct_resets() {
        let mut applet = PgpApplet::new();

        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_SIGN, b"wrong1"))
                .status(),
            Status::RemainingRetries(2)
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_OTHER, b"123456"))
                .status(),
            Status::Success
        );
        // Retry counter was shared and restored to 3
        assert_eq!(
            applet.process(&[0x00, 0x20, 0x00, PW1_SIGN]).status(),
            Status::RemainingRetries(3)
        );

        block_pw1(&mut applet);
        // Further attempts return OperationBlocked (6983)
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_SIGN, b"123456"))
                .status(),
            Status::OperationBlocked
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_OTHER, b"123456"))
                .status(),
            Status::OperationBlocked
        );
    }

    #[test]
    fn select_clears_session_pin_state() {
        let mut applet = PgpApplet::new();
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_SIGN, b"123456"))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_OTHER, b"123456"))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW3_ADMIN, b"12345678"))
                .status(),
            Status::Success
        );

        select_applet(&mut applet);

        assert_eq!(
            applet.process(&[0x00, 0x20, 0x00, PW1_SIGN]).status(),
            Status::RemainingRetries(3)
        );
        assert_eq!(
            applet.process(&[0x00, 0x20, 0x00, PW1_OTHER]).status(),
            Status::RemainingRetries(3)
        );
        assert_eq!(
            applet.process(&[0x00, 0x20, 0x00, PW3_ADMIN]).status(),
            Status::RemainingRetries(3)
        );
    }

    #[test]
    fn change_reference_data_pw1_and_pw3() {
        let mut applet = PgpApplet::new();

        // Wrong old PW1 burns a try
        assert_eq!(
            applet
                .process(&keyroost_openpgp::change_reference_data(
                    PW1_SIGN, b"000000", b"654321"
                ))
                .status(),
            Status::RemainingRetries(2)
        );

        // Correct old PW1 changes to new variable-length PIN
        assert_eq!(
            applet
                .process(&keyroost_openpgp::change_reference_data(
                    PW1_SIGN,
                    b"123456",
                    b"newuserpin"
                ))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_SIGN, b"123456"))
                .status(),
            Status::RemainingRetries(2)
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_SIGN, b"newuserpin"))
                .status(),
            Status::Success
        );

        // Change PW3
        assert_eq!(
            applet
                .process(&keyroost_openpgp::change_reference_data(
                    PW3_ADMIN,
                    b"12345678",
                    b"adminpin99"
                ))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW3_ADMIN, b"adminpin99"))
                .status(),
            Status::Success
        );
    }

    #[test]
    fn reset_retry_counter_by_admin_unblocks_pw1() {
        let mut applet = PgpApplet::new();
        block_pw1(&mut applet);

        // Fails without PW3 verified
        assert_eq!(
            applet
                .process(&keyroost_openpgp::reset_retry_counter(b"654321"))
                .status(),
            Status::SecurityStatusNotSatisfied
        );

        // Verify PW3 then unblock PW1
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW3_ADMIN, b"12345678"))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::reset_retry_counter(b"654321"))
                .status(),
            Status::Success
        );

        // New PW1 works with restored retries
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_SIGN, b"654321"))
                .status(),
            Status::Success
        );
    }

    #[test]
    fn reset_retry_counter_by_rc_unblocks_and_blocks_rc() {
        let mut applet = PgpApplet::new();

        // Without RC configured -> OperationBlocked
        let mut body = Vec::new();
        body.extend_from_slice(b"resetcode");
        body.extend_from_slice(b"654321");
        let mut apdu = vec![
            0x00,
            0x2C,
            0x00,
            PW1_SIGN,
            u8::try_from(body.len()).unwrap(),
        ];
        apdu.extend_from_slice(&body);
        assert_eq!(applet.process(&apdu).status(), Status::OperationBlocked);

        // Configure RC and block PW1
        applet.set_resetting_code(b"resetcode").unwrap();
        block_pw1(&mut applet);

        // Wrong RC burns RC tries
        let mut wrong_apdu = vec![0x00, 0x2C, 0x00, PW1_SIGN, 15];
        wrong_apdu.extend_from_slice(b"wrongcode");
        wrong_apdu.extend_from_slice(b"654321");
        assert_eq!(
            applet.process(&wrong_apdu).status(),
            Status::RemainingRetries(2)
        );

        // Correct RC unblocks PW1
        assert_eq!(applet.process(&apdu).status(), Status::Success);
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_SIGN, b"654321"))
                .status(),
            Status::Success
        );

        // Blocking RC after 3 wrong attempts
        block_pw1(&mut applet);
        for tries in (1..=3u8).rev() {
            assert_eq!(
                applet.process(&wrong_apdu).status(),
                Status::RemainingRetries(tries - 1)
            );
        }
        assert_eq!(applet.process(&apdu).status(), Status::OperationBlocked);
    }

    #[test]
    fn pw1_valid_multiple_defaults_to_false() {
        let applet = PgpApplet::new();
        assert!(!applet.pw1_valid_multiple());
    }
}
