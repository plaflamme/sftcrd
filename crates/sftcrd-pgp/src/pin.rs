//! `OpenPGP` Card v3.4 PIN state: PW1, Resetting Code (RC), and PW3.

use zeroize::Zeroizing;

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

/// Error returned when a PIN or Resetting Code length is outside the allowed range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPinLength;

/// Default user PIN (PW1): `"123456"`.
pub(crate) const DEFAULT_PW1: &[u8] = b"123456";
/// Default admin PIN (PW3): `"12345678"`.
pub(crate) const DEFAULT_PW3: &[u8] = b"12345678";
/// Default retry limit for PW1, RC, and PW3.
pub(crate) const DEFAULT_TRIES: u8 = 3;

/// Minimum length of PW1 in bytes (`OpenPGP` Card v3.4 §4.3.2).
pub(crate) const PW1_MIN_LEN: usize = 6;
/// Minimum length of Resetting Code in bytes (`OpenPGP` Card v3.4 §4.3.2).
pub(crate) const RC_MIN_LEN: usize = 8;
/// Minimum length of PW3 in bytes (`OpenPGP` Card v3.4 §4.3.2).
pub(crate) const PW3_MIN_LEN: usize = 8;
/// Maximum length of any `OpenPGP` PIN/RC in bytes (`OpenPGP` Card v3.4 §4.3.2).
pub(crate) const MAX_PIN_LEN: usize = 127;

/// Verification context within a [`PinSlot`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PinContext {
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

/// Constant-time byte-slice equality.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Stored PIN or Resetting Code secret, retry counter, and session verification flags.
pub(crate) struct PinSlot {
    value: Zeroizing<Vec<u8>>,
    min_len: usize,
    max_tries: u8,
    tries: u8,
    verified_mask: u8,
}

impl PinSlot {
    pub(crate) fn new(default: &[u8], min_len: usize, max_tries: u8) -> Self {
        Self {
            value: Zeroizing::new(default.to_vec()),
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

    pub(crate) fn len(&self) -> usize {
        self.value.len()
    }

    pub(crate) fn is_valid_new_pin(&self, candidate: &[u8]) -> bool {
        (self.min_len..=MAX_PIN_LEN).contains(&candidate.len())
    }

    pub(crate) fn is_verified(&self, ctx: PinContext) -> bool {
        self.verified_mask & ctx.bit() != 0
    }

    pub(crate) fn clear_verified(&mut self, ctx: PinContext) {
        self.verified_mask &= !ctx.bit();
    }

    pub(crate) fn session_end(&mut self) {
        self.verified_mask = 0;
    }

    /// Compare `presented` against the stored PIN in constant time without
    /// modifying verification flags.
    ///
    /// On match, restores `tries` to `max_tries`. On mismatch, decrements
    /// `tries` and returns the remaining count.
    pub(crate) fn check(&mut self, presented: &[u8]) -> Result<(), u8> {
        if self.tries == 0 {
            return Err(0);
        }
        if ct_eq(&self.value, presented) {
            self.tries = self.max_tries;
            Ok(())
        } else {
            self.tries = self.tries.saturating_sub(1);
            Err(self.tries)
        }
    }

    /// Verify `presented` for `ctx`, updating both retry counter and the
    /// verification bit for `ctx`.
    pub(crate) fn verify(&mut self, ctx: PinContext, presented: &[u8]) -> Result<(), u8> {
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

    /// Replace the stored value, restore `tries` to `max_tries`, and clear
    /// all verification flags.
    pub(crate) fn set_value(&mut self, new_value: &[u8]) {
        *self.value = new_value.to_vec();
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
    pub(crate) pw1: PinSlot,
    pub(crate) rc: Option<PinSlot>,
    pub(crate) pw3: PinSlot,
    /// PW1 (`0x81`) validity mode: single `PSO:CDS` vs multiple.
    pub(crate) pw1_validity: Pw1Validity,
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
    /// Resolve a [`PwRef`] to its [`PinSlot`] and [`PinContext`].
    pub(crate) fn slot_and_context(&mut self, pw_ref: PwRef) -> (&mut PinSlot, PinContext) {
        match pw_ref {
            PwRef::Pw1Sign => (&mut self.pw1, PinContext::Primary),
            PwRef::Pw1Other => (&mut self.pw1, PinContext::Secondary),
            PwRef::Pw3Admin => (&mut self.pw3, PinContext::Primary),
        }
    }

    /// Configure or replace the optional Resetting Code (RC).
    pub(crate) fn set_rc(&mut self, rc: &[u8]) -> Result<(), InvalidPinLength> {
        if !(RC_MIN_LEN..=MAX_PIN_LEN).contains(&rc.len()) {
            return Err(InvalidPinLength);
        }
        self.rc = Some(PinSlot::new(rc, RC_MIN_LEN, DEFAULT_TRIES));
        Ok(())
    }

    /// Clear all session verification flags (on `SELECT` / `deselect`).
    pub(crate) fn session_end(&mut self) {
        self.pw1.session_end();
        self.pw3.session_end();
    }
}
