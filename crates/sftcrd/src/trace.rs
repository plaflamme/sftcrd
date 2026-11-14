use std::fmt::Display;

use crate::yubico::YubicoInstruction;

#[derive(Clone)]
pub(crate) enum Trace<'a> {
    Byte(u8),
    Slice(&'a [u8]),
    Ins(iso7816::Instruction),
}

impl Display for Trace<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
