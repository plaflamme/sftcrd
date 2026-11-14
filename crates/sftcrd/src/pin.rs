//! The applet's reference-data secrets: the application PIN and the PUK.

use elliptic_curve::bigint::CtEq;
use zeroize::Zeroizing;

/// The factory application PIN: "123456" 0xFF-padded to 8 bytes.
const DEFAULT_PIN_VALUE: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0xFF, 0xFF];
/// The factory PUK: "12345678".
const DEFAULT_PUK_VALUE: [u8; 8] = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
/// The factory PIN retry limit
const DEFAULT_PIN_TRIES: u8 = 5;
/// The factory PUK retry limit
const DEFAULT_PUK_TRIES: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum VerifiedState {
    /// The pin was never verified
    #[default]
    Never,
    /// The pin was verified once this session
    Session,
    /// The pin was verified by the previous APDU
    Previous,
    /// The pin was verified by this APDU
    Now,
}

impl VerifiedState {
    /// Returns true when the pin was verified at least once in the session.
    fn is_verified(self) -> bool {
        !matches!(self, Self::Never)
    }

    /// A more strict check that only accepts the verified state when it was verified by the previous APDU
    fn is_verified_previous(self) -> bool {
        matches!(self, Self::Previous)
    }
}

/// One PIV reference-data state.
///
/// The value and the counter live for the applet's life; `verified` lives
/// only as long as the session — set by a successful check, cleared by the
/// card's reset points (an unverify, an unblock, a fresh instance) — and is
/// what the card's security-status sync consults when the key slots land.
pub(crate) struct Pin {
    /// The default value of this pin, used to check if the current value still
    /// holds the default value.
    default_value: Zeroizing<[u8; 8]>,
    /// The stored value: six ASCII digits plus two 0xFF padding bytes (the
    /// eight-character PUK has no padding).
    value: Zeroizing<[u8; 8]>,
    /// The retry limit the factory (or SET PIN RETRIES) configured.
    max_tries: u8,
    /// Tries remaining; 0 means blocked.
    tries: u8,
    verified_state: VerifiedState,
}

impl Pin {
    fn new(value: [u8; 8], max_tries: u8) -> Self {
        Self {
            default_value: Zeroizing::new(value),
            value: Zeroizing::new(value),
            max_tries,
            tries: max_tries,
            verified_state: VerifiedState::default(),
        }
    }

    pub(crate) fn default_pin(max_tries: Option<u8>) -> Self {
        Self::new(DEFAULT_PIN_VALUE, max_tries.unwrap_or(DEFAULT_PIN_TRIES))
    }

    pub(crate) fn default_puk(max_tries: Option<u8>) -> Self {
        Self::new(DEFAULT_PUK_VALUE, max_tries.unwrap_or(DEFAULT_PUK_TRIES))
    }

    pub(crate) fn tries(&self) -> u8 {
        self.tries
    }

    pub(crate) fn max_tries(&self) -> u8 {
        self.max_tries
    }

    pub(crate) fn is_default(&self) -> bool {
        self.value == self.default_value
    }

    /// Returns true when this pin was successfully verified at least once in the current session
    pub(crate) fn verified(&self) -> bool {
        self.verified_state.is_verified()
    }

    /// Returns true when this pin was successfully verified by the previous command
    pub(crate) fn verified_previous(&self) -> bool {
        self.verified_state.is_verified_previous()
    }

    /// Compare `presented` to the stored value in
    /// constant time. A correct value sets `verified` and restores the
    /// counter to its limit; a wrong one burns a try and leaves `verified`
    /// untouched. Callers must not call this while blocked.
    ///
    /// Returns `Err(remaining tries)` when the presented pin is invalid or when there are no tries left.
    pub(crate) fn check(&mut self, presented: [u8; 8]) -> Result<(), u8> {
        if self.tries == 0 {
            return Err(0);
        }

        let ok = presented.ct_eq(&self.value).to_bool();
        if ok {
            self.verified_state = VerifiedState::Now;
            self.tries = self.max_tries;
            Ok(())
        } else {
            self.tries = self.tries.saturating_sub(1);
            Err(self.tries)
        }
    }

    pub(crate) fn session_end(&mut self) {
        self.verified_state = VerifiedState::Never;
    }

    /// Downgrade the verified state.
    ///
    /// If the state was verified by the current APDU, then it is downgraded to [`VerifiedState::Previous`].
    /// If the state is [`VerifiedState::Previous`], then it is downgraded to [`VerifiedState::Session`].
    ///
    /// Anything else leves the verified state untouched.
    pub(crate) fn downgrade(&mut self) {
        self.verified_state = match self.verified_state {
            VerifiedState::Never | VerifiedState::Session => return,
            VerifiedState::Previous => VerifiedState::Session,
            VerifiedState::Now => VerifiedState::Previous,
        };
    }

    /// Reset the counter back to its limit, `verified` cleared.
    pub(crate) fn reset(&mut self) {
        self.tries = self.max_tries;
        self.verified_state = VerifiedState::Never;
    }

    /// Replace the stored value; the counter and `verified` are untouched.
    pub(crate) fn set_value(&mut self, value: [u8; 8]) {
        *self.value = value;
    }
}
