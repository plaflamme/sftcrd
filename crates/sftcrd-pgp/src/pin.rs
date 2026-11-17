//! `OpenPGP` Card v3.4 PIN state: PW1, Resetting Code (RC), and PW3.

use zeroize::Zeroizing;

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

/// Stored PIN secret and retry counter.
pub(crate) struct PinSlot {
    value: Zeroizing<Vec<u8>>,
    min_len: usize,
    max_tries: u8,
    tries: u8,
}

impl PinSlot {
    pub(crate) fn new(default: &[u8], min_len: usize, max_tries: u8) -> Self {
        Self {
            value: Zeroizing::new(default.to_vec()),
            min_len,
            max_tries,
            tries: max_tries,
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

    /// Compare `presented` against the stored PIN in constant time.
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

    pub(crate) fn set_value(&mut self, new_value: &[u8]) {
        *self.value = new_value.to_vec();
        self.tries = self.max_tries;
    }
}

/// Optional Resetting Code (RC) used to unblock PW1 via `RESET RETRY COUNTER` (`P1 = 0x00`).
pub(crate) struct ResettingCode {
    value: Option<Zeroizing<Vec<u8>>>,
    max_tries: u8,
    tries: u8,
}

impl ResettingCode {
    pub(crate) fn empty(max_tries: u8) -> Self {
        Self {
            value: None,
            max_tries,
            tries: 0,
        }
    }

    pub(crate) fn tries(&self) -> u8 {
        self.tries
    }

    pub(crate) fn len(&self) -> Option<usize> {
        self.value.as_ref().map(|v| v.len())
    }

    /// Configure or replace the Resetting Code.
    ///
    /// Returns `Err(InvalidPinLength)` if `rc` is shorter than [`RC_MIN_LEN`] or
    /// longer than [`MAX_PIN_LEN`].
    pub(crate) fn set(&mut self, rc: &[u8]) -> Result<(), InvalidPinLength> {
        if !(RC_MIN_LEN..=MAX_PIN_LEN).contains(&rc.len()) {
            return Err(InvalidPinLength);
        }
        self.value = Some(Zeroizing::new(rc.to_vec()));
        self.tries = self.max_tries;
        Ok(())
    }

    /// Check `presented` against the stored Resetting Code.
    ///
    /// Returns `Ok(())` on match, `Err(None)` if RC is not configured or
    /// already blocked, or `Err(Some(remaining))` on mismatch.
    pub(crate) fn check(&mut self, presented: &[u8]) -> Result<(), Option<u8>> {
        let Some(stored) = self.value.as_ref() else {
            return Err(None);
        };
        if self.tries == 0 {
            return Err(None);
        }
        if ct_eq(stored, presented) {
            self.tries = self.max_tries;
            Ok(())
        } else {
            self.tries = self.tries.saturating_sub(1);
            Err(Some(self.tries))
        }
    }
}

/// Whether PW1 (`0x81`) stays valid for one or multiple `PSO:CDS` commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Pw1Validity {
    #[default]
    Single,
    Multiple,
}

/// All `OpenPGP` Card PINs and session verification flags.
pub(crate) struct PinState {
    pub(crate) pw1: PinSlot,
    pub(crate) rc: ResettingCode,
    pub(crate) pw3: PinSlot,
    /// PW1 (`0x81`) validity mode: single `PSO:CDS` vs multiple.
    pub(crate) pw1_validity: Pw1Validity,
    /// Session verification flag for PW1 signing context (`0x81`).
    pub(crate) pw1_sign_verified: bool,
    /// Session verification flag for PW1 other context (`0x82`).
    pub(crate) pw1_other_verified: bool,
    /// Session verification flag for PW3 admin context (`0x83`).
    pub(crate) pw3_verified: bool,
}

impl Default for PinState {
    fn default() -> Self {
        Self {
            pw1: PinSlot::new(DEFAULT_PW1, PW1_MIN_LEN, DEFAULT_TRIES),
            rc: ResettingCode::empty(DEFAULT_TRIES),
            pw3: PinSlot::new(DEFAULT_PW3, PW3_MIN_LEN, DEFAULT_TRIES),
            pw1_validity: Pw1Validity::default(),
            pw1_sign_verified: false,
            pw1_other_verified: false,
            pw3_verified: false,
        }
    }
}

impl PinState {
    /// Clear all session verification flags (on `SELECT` / `deselect`).
    pub(crate) fn session_end(&mut self) {
        self.pw1_sign_verified = false;
        self.pw1_other_verified = false;
        self.pw3_verified = false;
    }

    /// Clear both PW1 verification flags (`0x81` and `0x82`).
    pub(crate) fn clear_pw1_verified(&mut self) {
        self.pw1_sign_verified = false;
        self.pw1_other_verified = false;
    }
}
