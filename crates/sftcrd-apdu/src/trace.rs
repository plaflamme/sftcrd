//! Tracing formatting helpers for APDUs.

use std::fmt::{self, Display};

use crate::YubicoInstruction;

/// Lazy [`Display`] wrapper for formatting APDU fields in `tracing` events.
#[derive(Clone)]
pub enum Trace<'a> {
    /// Single byte formatted as two uppercase hex digits.
    Byte(u8),
    /// Byte slice formatted as uppercase hex.
    Slice(&'a [u8]),
    /// ISO 7816 instruction formatted using its variant name, [`YubicoInstruction`], or `Unknown(XX)`.
    Ins(iso7816::Instruction),
}

impl Display for Trace<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Byte(v) => write!(f, "{v:02X}"),
            Self::Slice(s) => write!(f, "{}", hex::encode_upper(s)),
            Self::Ins(iso7816::Instruction::Unknown(ins))
                if let Some(yubico) = YubicoInstruction::from_code(*ins) =>
            {
                write!(f, "{yubico:?}")
            }
            Self::Ins(iso7816::Instruction::Unknown(ins)) => {
                write!(f, "Unknown({ins:02X})")
            }
            Self::Ins(ins) => write!(f, "{ins:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_byte_slice_and_instruction() {
        assert_eq!(Trace::Byte(0x0a).to_string(), "0A");
        assert_eq!(
            Trace::Slice(&[0xde, 0xad, 0xbe, 0xef]).to_string(),
            "DEADBEEF"
        );
        assert_eq!(
            Trace::Ins(iso7816::Instruction::Select).to_string(),
            "Select"
        );
        assert_eq!(
            Trace::Ins(iso7816::Instruction::Unknown(0xfd)).to_string(),
            "GetVersion"
        );
        assert_eq!(
            Trace::Ins(iso7816::Instruction::Unknown(0x01)).to_string(),
            "Unknown(01)"
        );
    }
}
