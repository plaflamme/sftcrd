//! `OpenPGP` Card v3.4 domain models and protocol enums.

/// `OpenPGP` Card instructions not in the `iso7816` crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PgpInstruction {
    GetData = 0xCA,
    PutData = 0xDA,
    TerminateDf = 0xE6,
    ActivateFile = 0x44,
}

impl PgpInstruction {
    pub(crate) const fn from_u8(code: u8) -> Option<Self> {
        match code {
            0xCA => Some(Self::GetData),
            0xDA => Some(Self::PutData),
            0xE6 => Some(Self::TerminateDf),
            0x44 => Some(Self::ActivateFile),
            _ => None,
        }
    }
}

/// ISO/IEC 5218 gender encoding (`5F35`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub(crate) enum Gender {
    NotKnown = b'0',
    Male = b'1',
    Female = b'2',
    #[default]
    NotApplicable = b'9',
}

impl Gender {
    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            b'0' => Some(Self::NotKnown),
            b'1' => Some(Self::Male),
            b'2' => Some(Self::Female),
            b'9' => Some(Self::NotApplicable),
            _ => None,
        }
    }
}

/// User Interaction Flag mode (`D6`/`D7`/`D8` byte 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub(crate) enum UifMode {
    #[default]
    Off = 0x00,
    On = 0x01,
    Permanent = 0x02,
}

impl UifMode {
    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Off),
            0x01 => Some(Self::On),
            0x02 => Some(Self::Permanent),
            _ => None,
        }
    }
}

/// Supported algorithm IDs (`OpenPGP` Card v3.4 §4.4.3.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum AlgoId {
    Rsa = 0x01,
    Ecdh = 0x12,
    Ecdsa = 0x13,
    EdDsa = 0x16,
}

impl AlgoId {
    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Rsa),
            0x12 => Some(Self::Ecdh),
            0x13 => Some(Self::Ecdsa),
            0x16 => Some(Self::EdDsa),
            _ => None,
        }
    }
}
