//! Applet-wide constants for `OpenPGP` Card v3.4.

/// `OpenPGP` Card application AID prefix (RID `D2 76 00 01 24` + PIX `01`).
pub const AID_PREFIX: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// `OpenPGP` Card specification version `03 04` (v3.4).
pub const OPENPGP_VERSION: [u8; 2] = [0x03, 0x04];

/// Manufacturer ID (`00 06` = Yubico).
pub const MANUFACTURER_ID: [u8; 2] = [0x00, 0x06];

/// Default 4-byte card serial number.
pub const DEFAULT_SERIAL: u32 = 87_654_321;

/// `GET DATA` instruction (`0xCA`).
pub(crate) const INS_GET_DATA: u8 = 0xCA;
/// `PUT DATA` instruction (`0xDA`).
pub(crate) const INS_PUT_DATA: u8 = 0xDA;
/// `TERMINATE DF` instruction (`0xE6`).
pub(crate) const INS_TERMINATE_DF: u8 = 0xE6;
/// `ACTIVATE FILE` instruction (`0x44`).
pub(crate) const INS_ACTIVATE_FILE: u8 = 0x44;

// OpenPGP Card v3.4 Data Object tags
pub(crate) const TAG_AID: u16 = 0x004F;
pub(crate) const TAG_NAME: u16 = 0x005B;
pub(crate) const TAG_LOGIN_DATA: u16 = 0x005E;
pub(crate) const TAG_LANGUAGE: u16 = 0x5F2D;
pub(crate) const TAG_SEX: u16 = 0x5F35;
pub(crate) const TAG_URL: u16 = 0x5F50;
pub(crate) const TAG_HISTORICAL_BYTES: u16 = 0x5F52;
pub(crate) const TAG_CARDHOLDER_RELATED_DATA: u16 = 0x0065;
pub(crate) const TAG_APPLICATION_RELATED_DATA: u16 = 0x006E;
pub(crate) const TAG_DISCRETIONARY: u16 = 0x0073;
pub(crate) const TAG_SECURITY_SUPPORT: u16 = 0x007A;
pub(crate) const TAG_DS_COUNTER: u16 = 0x0093;
pub(crate) const TAG_EXTENDED_CAPABILITIES: u16 = 0x00C0;
pub(crate) const TAG_ALGO_ATTR_SIG: u16 = 0x00C1;
pub(crate) const TAG_ALGO_ATTR_DEC: u16 = 0x00C2;
pub(crate) const TAG_ALGO_ATTR_AUT: u16 = 0x00C3;
pub(crate) const TAG_PW_STATUS: u16 = 0x00C4;
pub(crate) const TAG_FINGERPRINTS: u16 = 0x00C5;
pub(crate) const TAG_CA_FINGERPRINTS: u16 = 0x00C6;
pub(crate) const TAG_FPR_SIGN: u16 = 0x00C7;
pub(crate) const TAG_FPR_DEC: u16 = 0x00C8;
pub(crate) const TAG_FPR_AUTH: u16 = 0x00C9;
pub(crate) const TAG_GENERATION_TIMES: u16 = 0x00CD;
pub(crate) const TAG_TIME_SIGN: u16 = 0x00CE;
pub(crate) const TAG_TIME_DEC: u16 = 0x00CF;
pub(crate) const TAG_TIME_AUTH: u16 = 0x00D0;
pub(crate) const TAG_RESETTING_CODE: u16 = 0x00D3;
pub(crate) const TAG_UIF_SIG: u16 = 0x00D6;
pub(crate) const TAG_UIF_DEC: u16 = 0x00D7;
pub(crate) const TAG_UIF_AUT: u16 = 0x00D8;
pub(crate) const TAG_ALGORITHM_INFORMATION: u16 = 0x00FA;

/// Historical bytes (`5F52`): category `00`, card service `31 C5`, card
/// capabilities `73 C0 01 C0`, status indicator `05 90 00`.
pub(crate) const HISTORICAL_BYTES: [u8; 10] =
    [0x00, 0x31, 0xC5, 0x73, 0xC0, 0x01, 0xC0, 0x05, 0x90, 0x00];

/// Extended capabilities (`C0`, 10 bytes): key import (`0x20`), PW status
/// changeable (`0x10`), algorithm attributes changeable (`0x04`).
pub(crate) const EXTENDED_CAPABILITIES: [u8; 10] =
    [0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00];

/// Default algorithm attributes: RSA-2048 (`01 | 08 00 | 00 20 | 00`).
pub(crate) const DEFAULT_ALGO_ATTR: [u8; 6] = [0x01, 0x08, 0x00, 0x00, 0x20, 0x00];

/// Default User Interaction Flag (`D6`/`D7`/`D8`): off (`00`), button present (`20`).
pub(crate) const DEFAULT_UIF: [u8; 2] = [0x00, 0x20];

/// Default sex (`5F35`): `'9'` (not applicable, ISO/IEC 5218).
pub(crate) const DEFAULT_SEX: u8 = b'9';

// Supported ECC algorithm IDs (`OpenPGP` Card v3.4 §4.4.3.9)
pub(crate) const ALGO_RSA: u8 = 0x01;
pub(crate) const ALGO_ECDH: u8 = 0x12;
pub(crate) const ALGO_ECDSA: u8 = 0x13;
pub(crate) const ALGO_EDDSA: u8 = 0x16;

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
