//! `OpenPGP` Card v3.4 key-slot types and status mapping.

use iso7816::Status;
pub(crate) use sftcrd_key::{KeyError, PublicKey, RsaBits, SlotKey};

/// Resolved key-slot algorithm from `C1`/`C2`/`C3` algorithm attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotAlg {
    Rsa { n_bits: RsaBits, e_bits: u16 },
    P256,
    P384,
    P521,
    Ed25519,
    X25519,
}

impl From<SlotAlg> for sftcrd_key::KeyAlg {
    fn from(alg: SlotAlg) -> Self {
        match alg {
            SlotAlg::Rsa { n_bits, .. } => Self::Rsa(n_bits),
            SlotAlg::P256 => Self::P256,
            SlotAlg::P384 => Self::P384,
            SlotAlg::P521 => Self::P521,
            SlotAlg::Ed25519 => Self::Ed25519,
            SlotAlg::X25519 => Self::X25519,
        }
    }
}

/// Map a [`KeyError`] from `sftcrd-key` to the `OpenPGP` Card ISO 7816 status code.
pub(crate) fn key_error_to_status(err: &KeyError) -> Status {
    match err {
        KeyError::InvalidLength => Status::WrongLength,
        KeyError::UnsupportedOperation => Status::ConditionsOfUseNotSatisfied,
        KeyError::InvalidData
        | KeyError::InvalidDataWithMsg(_)
        | KeyError::CryptoFailure
        | KeyError::Pem(_) => Status::IncorrectDataParameter,
    }
}
