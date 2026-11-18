//! `OpenPGP` Card v3.4 domain models and protocol enums.

/// `OpenPGP` Card instructions not in the `iso7816` crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum PgpInstruction {
    GetData = 0xCA,
    PutData = 0xDA,
    TerminateDf = 0xE6,
    ActivateFile = 0x44,
    PerformSecurityOperation = 0x2A,
    InternalAuthenticate = 0x88,
}

impl PgpInstruction {
    pub(crate) const fn from_u8(code: u8) -> Option<Self> {
        match code {
            0xCA => Some(Self::GetData),
            0xDA => Some(Self::PutData),
            0xE6 => Some(Self::TerminateDf),
            0x44 => Some(Self::ActivateFile),
            0x2A => Some(Self::PerformSecurityOperation),
            0x88 => Some(Self::InternalAuthenticate),
            _ => None,
        }
    }
}

/// `P1P2` operation selector for `PERFORM SECURITY OPERATION` (`0x2A`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum PsoOp {
    /// `COMPUTE DIGITAL SIGNATURE` (`9E 9A`).
    ComputeDigitalSignature = 0x9E9A,
    /// `DECIPHER` (`80 86`).
    Decipher = 0x8086,
}

impl PsoOp {
    pub(crate) const fn from_p1p2(p1: u8, p2: u8) -> Option<Self> {
        match u16::from_be_bytes([p1, p2]) {
            0x9E9A => Some(Self::ComputeDigitalSignature),
            0x8086 => Some(Self::Decipher),
            _ => None,
        }
    }
}

/// Which of the three `OpenPGP` key slots a CRT tag or DO refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum KeySlotId {
    Sig = 0xB6,
    Dec = 0xB8,
    Aut = 0xA4,
}

/// `P1` mode for `GENERATE ASYMMETRIC KEY PAIR` (`0x47`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum GenerateMode {
    Generate = 0x80,
    ReadPublicKey = 0x81,
}

impl GenerateMode {
    pub(crate) const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x80 => Some(Self::Generate),
            0x81 => Some(Self::ReadPublicKey),
            _ => None,
        }
    }
}

/// Supported RSA modulus bit widths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum RsaBits {
    Rsa2048 = 2048,
    Rsa3072 = 3072,
    Rsa4096 = 4096,
}

impl RsaBits {
    pub(crate) const fn from_u16(bits: u16) -> Option<Self> {
        match bits {
            2048 => Some(Self::Rsa2048),
            3072 => Some(Self::Rsa3072),
            4096 => Some(Self::Rsa4096),
            _ => None,
        }
    }

    pub(crate) const fn modulus_bytes(self) -> usize {
        (self as usize) / 8
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
