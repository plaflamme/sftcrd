//! `OpenPGP` Card v3.4 PIN state: PW1, Resetting Code (RC), and PW3.

use iso7816::Status;

/// `OpenPGP` Card password reference (`P2` in `VERIFY`, `CHANGE REFERENCE DATA`,
/// and `RESET RETRY COUNTER`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PwRef {
    /// PW1 in signing context (`PSO:CDS`).
    Pw1Sign = 0x81,
    /// PW1 in other contexts (decipher, internal auth).
    Pw1Other = 0x82,
    /// PW3 (admin PIN).
    Pw3Admin = 0x83,
}

impl PwRef {
    /// Parse a raw `P2` byte into a [`PwRef`].
    #[must_use]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x81 => Some(Self::Pw1Sign),
            0x82 => Some(Self::Pw1Other),
            0x83 => Some(Self::Pw3Admin),
            _ => None,
        }
    }
}

/// Default user PIN (PW1): `"123456"`.
const DEFAULT_PW1: &[u8] = b"123456";
/// Default admin PIN (PW3): `"12345678"`.
const DEFAULT_PW3: &[u8] = b"12345678";
/// Default retry limit for PW1, RC, and PW3.
const DEFAULT_TRIES: u8 = 3;

/// Minimum length of PW1 in bytes (`OpenPGP` Card v3.4 §4.3.2).
pub(crate) const PW1_MIN_LEN: usize = 6;
/// Minimum length of Resetting Code in bytes (`OpenPGP` Card v3.4 §4.3.2).
const RC_MIN_LEN: usize = 8;
/// Minimum length of PW3 in bytes (`OpenPGP` Card v3.4 §4.3.2).
const PW3_MIN_LEN: usize = 8;
/// Maximum length of any `OpenPGP` PIN/RC in bytes (`OpenPGP` Card v3.4 §4.3.2).
pub(crate) const MAX_PIN_LEN: usize = 127;

/// Verification context within a [`PinSlot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum PinContext {
    /// Primary context: `PW1_SIGN` (`0x81`) or `PW3_ADMIN` (`0x83`).
    Primary = 1 << 0,
    /// Secondary context: `PW1_OTHER` (`0x82`).
    Secondary = 1 << 1,
}

impl PinContext {
    const fn bit(self) -> u8 {
        self as u8
    }
}

/// Stored PIN or Resetting Code secret, retry counter, and session verification flags.
pub(crate) struct PinSlot {
    value: Vec<u8>,
    min_len: usize,
    max_tries: u8,
    tries: u8,
    verified_mask: u8,
}

impl PinSlot {
    pub(crate) fn new(default: &[u8], min_len: usize, max_tries: u8) -> Self {
        Self {
            value: default.to_vec(),
            min_len,
            max_tries,
            tries: max_tries,
            verified_mask: 0,
        }
    }

    pub(crate) fn tries(&self) -> u8 {
        self.tries
    }

    pub(crate) fn min_len(&self) -> usize {
        self.min_len
    }

    pub(crate) fn is_valid_new_pin(&self, candidate: &[u8]) -> bool {
        (self.min_len..=MAX_PIN_LEN).contains(&candidate.len())
    }

    fn is_verified(&self, ctx: PinContext) -> bool {
        self.verified_mask & ctx.bit() != 0
    }

    fn clear_verified(&mut self, ctx: PinContext) {
        self.verified_mask &= !ctx.bit();
    }

    pub(crate) fn session_end(&mut self) {
        self.verified_mask = 0;
    }

    /// Compare `presented` against the stored PIN without modifying verification flags.
    ///
    /// On match, restores `tries` to `max_tries`. On mismatch, decrements
    /// `tries` and returns the remaining count.
    pub(crate) fn check(&mut self, presented: &[u8]) -> Result<(), u8> {
        if self.tries == 0 {
            return Err(0);
        }
        if self.value == presented {
            self.tries = self.max_tries;
            Ok(())
        } else {
            self.tries = self.tries.saturating_sub(1);
            Err(self.tries)
        }
    }

    /// Verify `presented` for `ctx`, updating both retry counter and the
    /// verification bit for `ctx`.
    fn verify(&mut self, ctx: PinContext, presented: &[u8]) -> Result<(), u8> {
        match self.check(presented) {
            Ok(()) => {
                self.verified_mask |= ctx.bit();
                Ok(())
            }
            Err(tries) => {
                self.clear_verified(ctx);
                Err(tries)
            }
        }
    }

    /// Gate an `old_secret || new_secret` body against this slot.
    ///
    /// Returns `Ok(new_secret)` when the slot is unblocked and the prefix
    /// matches in constant time, or `Err(Status)` otherwise.
    pub(crate) fn check_prefix<'a>(
        &mut self,
        data: &'a [u8],
        min_new_len: usize,
    ) -> Result<&'a [u8], Status> {
        if self.tries == 0 {
            return Err(Status::OperationBlocked);
        }
        if data.len() < self.min_len + min_new_len {
            return Err(Status::WrongLength);
        }
        let Some((presented, rest)) = data.split_at_checked(self.value.len()) else {
            let Err(tries) = self.check(data) else {
                unreachable!("shorter slice never matches stored secret");
            };
            self.session_end();
            return Err(Status::RemainingRetries(tries));
        };
        if let Err(tries) = self.check(presented) {
            self.session_end();
            return Err(Status::RemainingRetries(tries));
        }
        Ok(rest)
    }

    /// Replace the stored value, restore `tries` to `max_tries`, and clear
    /// all verification flags.
    pub(crate) fn set_value(&mut self, new_value: &[u8]) {
        self.value = new_value.to_vec();
        self.tries = self.max_tries;
        self.verified_mask = 0;
    }
}

/// Whether PW1 (`0x81`) stays valid for one or multiple `PSO:CDS` commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Pw1Validity {
    #[default]
    Single,
    Multiple,
}

/// All `OpenPGP` Card PINs.
pub(crate) struct PinState {
    pw1: PinSlot,
    rc: Option<PinSlot>,
    pw3: PinSlot,
    /// PW1 (`0x81`) validity mode: single `PSO:CDS` vs multiple.
    pw1_validity: Pw1Validity,
}

impl Default for PinState {
    fn default() -> Self {
        Self {
            pw1: PinSlot::new(DEFAULT_PW1, PW1_MIN_LEN, DEFAULT_TRIES),
            rc: None,
            pw3: PinSlot::new(DEFAULT_PW3, PW3_MIN_LEN, DEFAULT_TRIES),
            pw1_validity: Pw1Validity::default(),
        }
    }
}

impl PinState {
    fn slot_and_context(&self, pw_ref: PwRef) -> (&PinSlot, PinContext) {
        match pw_ref {
            PwRef::Pw1Sign => (&self.pw1, PinContext::Primary),
            PwRef::Pw1Other => (&self.pw1, PinContext::Secondary),
            PwRef::Pw3Admin => (&self.pw3, PinContext::Primary),
        }
    }

    fn slot_and_context_mut(&mut self, pw_ref: PwRef) -> (&mut PinSlot, PinContext) {
        match pw_ref {
            PwRef::Pw1Sign => (&mut self.pw1, PinContext::Primary),
            PwRef::Pw1Other => (&mut self.pw1, PinContext::Secondary),
            PwRef::Pw3Admin => (&mut self.pw3, PinContext::Primary),
        }
    }

    pub(crate) fn slot(&self, pw_ref: PwRef) -> &PinSlot {
        self.slot_and_context(pw_ref).0
    }

    pub(crate) fn slot_mut(&mut self, pw_ref: PwRef) -> &mut PinSlot {
        self.slot_and_context_mut(pw_ref).0
    }

    pub(crate) fn rc_mut(&mut self) -> Option<&mut PinSlot> {
        self.rc.as_mut()
    }

    pub(crate) fn pw1_valid_multiple(&self) -> bool {
        self.pw1_validity == Pw1Validity::Multiple
    }

    pub(crate) fn set_pw1_valid_multiple(&mut self, valid_multiple: bool) {
        self.pw1_validity = if valid_multiple {
            Pw1Validity::Multiple
        } else {
            Pw1Validity::Single
        };
    }

    /// Encode the 7-byte PW Status DO (`C4`).
    pub(crate) fn pw_status_bytes(&self) -> [u8; 7] {
        #[allow(clippy::cast_possible_truncation)]
        let max_len = MAX_PIN_LEN as u8;
        [
            u8::from(self.pw1_valid_multiple()),
            max_len,
            max_len,
            max_len,
            self.pw1.tries(),
            self.rc.as_ref().map_or(0, PinSlot::tries),
            self.pw3.tries(),
        ]
    }

    pub(crate) fn both_pw1_and_pw3_blocked(&self) -> bool {
        self.pw1.tries() == 0 && self.pw3.tries() == 0
    }

    pub(crate) fn is_verified(&self, pw_ref: PwRef) -> bool {
        let (slot, ctx) = self.slot_and_context(pw_ref);
        slot.is_verified(ctx)
    }

    pub(crate) fn clear_verified(&mut self, pw_ref: PwRef) {
        let (slot, ctx) = self.slot_and_context_mut(pw_ref);
        slot.clear_verified(ctx);
    }

    pub(crate) fn verify(&mut self, pw_ref: PwRef, presented: &[u8]) -> Result<(), u8> {
        let (slot, ctx) = self.slot_and_context_mut(pw_ref);
        slot.verify(ctx, presented)
    }

    /// Configure or replace the optional Resetting Code (RC).
    pub(crate) fn set_rc(&mut self, rc: &[u8]) -> Result<(), Status> {
        if !(RC_MIN_LEN..=MAX_PIN_LEN).contains(&rc.len()) {
            return Err(Status::WrongLength);
        }
        self.rc = Some(PinSlot::new(rc, RC_MIN_LEN, DEFAULT_TRIES));
        Ok(())
    }

    /// Remove the optional Resetting Code (RC).
    pub(crate) fn clear_rc(&mut self) {
        self.rc = None;
    }

    /// Clear all session verification flags (on `SELECT` / `deselect`).
    pub(crate) fn session_end(&mut self) {
        self.pw1.session_end();
        self.pw3.session_end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pw_ref_from_u8_parses_known_values() {
        assert_eq!(PwRef::from_u8(0x81), Some(PwRef::Pw1Sign));
        assert_eq!(PwRef::from_u8(0x82), Some(PwRef::Pw1Other));
        assert_eq!(PwRef::from_u8(0x83), Some(PwRef::Pw3Admin));
        assert_eq!(PwRef::from_u8(0x80), None);
        assert_eq!(PwRef::from_u8(0x84), None);
    }

    #[test]
    fn pin_slot_contexts_are_independent() {
        let mut slot = PinSlot::new(b"123456", 6, 3);

        assert!(!slot.is_verified(PinContext::Primary));
        assert!(!slot.is_verified(PinContext::Secondary));

        assert_eq!(slot.verify(PinContext::Primary, b"123456"), Ok(()));
        assert!(slot.is_verified(PinContext::Primary));
        assert!(!slot.is_verified(PinContext::Secondary));

        assert_eq!(slot.verify(PinContext::Secondary, b"123456"), Ok(()));
        assert!(slot.is_verified(PinContext::Primary));
        assert!(slot.is_verified(PinContext::Secondary));

        // Failing Secondary clears only Secondary
        assert_eq!(slot.verify(PinContext::Secondary, b"wrong!"), Err(2));
        assert!(slot.is_verified(PinContext::Primary));
        assert!(!slot.is_verified(PinContext::Secondary));

        // clear_verified clears only Primary
        slot.clear_verified(PinContext::Primary);
        assert!(!slot.is_verified(PinContext::Primary));

        // session_end clears all contexts
        assert_eq!(slot.verify(PinContext::Primary, b"123456"), Ok(()));
        assert_eq!(slot.verify(PinContext::Secondary, b"123456"), Ok(()));
        slot.session_end();
        assert!(!slot.is_verified(PinContext::Primary));
        assert!(!slot.is_verified(PinContext::Secondary));
    }

    #[test]
    fn pin_slot_retries_block_and_set_value_resets() {
        let mut slot = PinSlot::new(b"123456", 6, 3);

        assert_eq!(slot.verify(PinContext::Primary, b"wrong1"), Err(2));
        assert_eq!(slot.verify(PinContext::Primary, b"wrong2"), Err(1));
        assert_eq!(slot.verify(PinContext::Primary, b"wrong3"), Err(0));
        assert_eq!(slot.tries(), 0);
        // Blocked even with correct PIN
        assert_eq!(slot.verify(PinContext::Primary, b"123456"), Err(0));
        assert!(!slot.is_verified(PinContext::Primary));

        // set_value restores tries and clears verification
        assert_eq!(slot.verify(PinContext::Secondary, b"123456"), Err(0));
        slot.set_value(b"654321");
        assert_eq!(slot.tries(), 3);
        assert_eq!(slot.verify(PinContext::Primary, b"654321"), Ok(()));
        slot.set_value(b"abcdef");
        assert!(!slot.is_verified(PinContext::Primary));
    }

    #[test]
    fn pin_slot_length_validation() {
        let slot = PinSlot::new(b"123456", 6, 3);
        assert!(!slot.is_valid_new_pin(b"12345"));
        assert!(slot.is_valid_new_pin(b"123456"));
        assert!(slot.is_valid_new_pin(&[b'a'; MAX_PIN_LEN]));
        assert!(!slot.is_valid_new_pin(&[b'a'; MAX_PIN_LEN + 1]));
    }

    #[test]
    fn check_prefix_splits_validates_and_handles_short_input() {
        let mut slot = PinSlot::new(b"longsecret", 6, 3);
        assert_eq!(slot.verify(PinContext::Primary, b"longsecret"), Ok(()));

        // Shorter than min_len + min_new_len -> WrongLength, no retry burned
        assert_eq!(slot.check_prefix(b"short", 6), Err(Status::WrongLength));
        assert_eq!(slot.tries(), 3);

        // At least min_len + min_new_len, but shorter than stored secret + min_new_len
        // (10 bytes stored, so 12 bytes total: split_at_checked(10) succeeds, prefix != stored)
        assert_eq!(
            slot.check_prefix(b"wrong1234567", 6),
            Err(Status::RemainingRetries(2))
        );
        assert!(!slot.is_verified(PinContext::Primary));

        // Valid prefix returns trailing new_secret and restores tries
        assert_eq!(
            slot.check_prefix(b"longsecretnewpin", 6),
            Ok(&b"newpin"[..])
        );
        assert_eq!(slot.tries(), 3);

        // Exhaust retries -> OperationBlocked
        assert_eq!(
            slot.check_prefix(b"wrong1234567", 6),
            Err(Status::RemainingRetries(2))
        );
        assert_eq!(
            slot.check_prefix(b"wrong1234567", 6),
            Err(Status::RemainingRetries(1))
        );
        assert_eq!(
            slot.check_prefix(b"wrong1234567", 6),
            Err(Status::RemainingRetries(0))
        );
        assert_eq!(
            slot.check_prefix(b"longsecretnewpin", 6),
            Err(Status::OperationBlocked)
        );
    }

    #[test]
    fn pin_state_rc_validation_and_session_end() {
        let mut state = PinState::default();
        assert!(state.rc_mut().is_none());

        assert_eq!(state.set_rc(b"short"), Err(Status::WrongLength));
        assert_eq!(
            state.set_rc(&[b'x'; MAX_PIN_LEN + 1]),
            Err(Status::WrongLength)
        );
        assert_eq!(state.set_rc(b"resetcode"), Ok(()));
        assert!(state.rc_mut().is_some());

        assert_eq!(state.verify(PwRef::Pw1Sign, DEFAULT_PW1), Ok(()));
        assert_eq!(state.verify(PwRef::Pw1Other, DEFAULT_PW1), Ok(()));
        assert_eq!(state.verify(PwRef::Pw3Admin, DEFAULT_PW3), Ok(()));
        state.session_end();
        assert!(!state.is_verified(PwRef::Pw1Sign));
        assert!(!state.is_verified(PwRef::Pw1Other));
        assert!(!state.is_verified(PwRef::Pw3Admin));
    }
}
