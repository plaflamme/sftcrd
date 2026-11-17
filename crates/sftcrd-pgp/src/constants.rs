//! Applet-wide constants for `OpenPGP` Card v3.4.

/// `OpenPGP` Card application AID prefix (RID `D2 76 00 01 24` + PIX `01`).
pub const AID_PREFIX: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// `OpenPGP` Card specification version `03 04` (v3.4).
pub const OPENPGP_VERSION: [u8; 2] = [0x03, 0x04];

/// Manufacturer ID (`00 06` = Yubico).
pub const MANUFACTURER_ID: [u8; 2] = [0x00, 0x06];

/// Default 4-byte card serial number.
pub const DEFAULT_SERIAL: u32 = 87_654_321;

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

/// Historical bytes (`5F52`): category `00`, card service `31 C5`, card
/// capabilities `73 C0 01 C0`, status indicator `05 90 00`.
pub(crate) const HISTORICAL_BYTES: [u8; 10] =
    [0x00, 0x31, 0xC5, 0x73, 0xC0, 0x01, 0xC0, 0x05, 0x90, 0x00];

/// Extended capabilities (`C0`, 10 bytes): key import (`0x20`), PW status
/// changeable (`0x10`), algorithm attributes changeable (`0x04`).
pub(crate) const EXTENDED_CAPABILITIES: [u8; 10] =
    [0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00];

/// Default algorithm attributes: RSA-2048 (`01 | 08 00 | 00 20 | 00`).
pub(crate) const DEFAULT_ALGO_ATTR: [u8; 6] = [AlgoId::Rsa as u8, 0x08, 0x00, 0x00, 0x20, 0x00];

/// Default User Interaction Flag (`D6`/`D7`/`D8`): off (`00`), button present (`20`).
pub(crate) const DEFAULT_UIF: [u8; 2] = [UifMode::Off as u8, 0x20];

/// ISO/IEC 5218 gender/sex encoding (`5F35`).
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

// Supported curve OIDs (bare OID body, without 0x06 + length)
pub(crate) const OID_ED25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
pub(crate) const OID_X25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];
pub(crate) const OID_NIST_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
pub(crate) const OID_NIST_P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
pub(crate) const OID_NIST_P521: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x23];

/// Build the 16-byte `OpenPGP` Card AID:
/// `D2 76 00 01 24 01 | 03 04 | 00 06 | <serial:4 BE> | 00 00`.
#[must_use]
pub const fn build_aid(serial: u32) -> [u8; 16] {
    let s = serial.to_be_bytes();
    [
        AID_PREFIX[0],
        AID_PREFIX[1],
        AID_PREFIX[2],
        AID_PREFIX[3],
        AID_PREFIX[4],
        AID_PREFIX[5],
        OPENPGP_VERSION[0],
        OPENPGP_VERSION[1],
        MANUFACTURER_ID[0],
        MANUFACTURER_ID[1],
        s[0],
        s[1],
        s[2],
        s[3],
        0x00,
        0x00,
    ]
}
