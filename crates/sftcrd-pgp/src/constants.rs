//! Applet-wide constants for `OpenPGP` Card v3.4.

/// `OpenPGP` Card application AID prefix (RID `D2 76 00 01 24` + PIX `01`).
pub const AID_PREFIX: [u8; 6] = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

/// `OpenPGP` Card specification version `03 04` (v3.4).
pub const OPENPGP_VERSION: [u8; 2] = [0x03, 0x04];

/// Manufacturer ID (`00 06` = Yubico).
pub const MANUFACTURER_ID: [u8; 2] = [0x00, 0x06];

/// Default 4-byte card serial number.
pub const DEFAULT_SERIAL: u32 = 87_654_321;

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

/// Password reference (P2) for PW1 in signing context (`PSO:CDS`).
pub const PW1_SIGN: u8 = 0x81;
/// Password reference (P2) for PW1 in other contexts (decipher, internal auth).
pub const PW1_OTHER: u8 = 0x82;
/// Password reference (P2) for PW3 (admin PIN).
pub const PW3_ADMIN: u8 = 0x83;
