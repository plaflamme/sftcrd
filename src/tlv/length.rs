use super::DecodeError;

pub trait Length {
    fn decode(buf: &[u8]) -> Result<(usize, usize), DecodeError>
    where
        Self: Sized;
}

pub struct U8Length;
impl Length for U8Length {
    fn decode(buf: &[u8]) -> Result<(usize, usize), DecodeError>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Err(DecodeError::BufferUnderrun);
        }
        Ok((buf[0] as usize, 1))
    }
}

/// ASN.1 Basic Encoding Rules (BER) length form.
///
/// The first byte indicates the form of the length field:
/// * `first <= 0x7F` => short "definite lenth form", length one byte long and is the value of `first`
/// * `first == 0x80` => "indefinite lenth form", read until End-of-Content (0x00, 0x00) occurs in the byte stream
/// * `first > 0x80` => "variable "definite lenth form", bits 0x7f indicate the number of bytes the length is encoded on (big-endian)
pub struct BerLength;
impl Length for BerLength {
    fn decode(buf: &[u8]) -> Result<(usize, usize), DecodeError>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Err(DecodeError::BufferUnderrun);
        }

        let first = buf[0];
        // short form
        if first & 0x80 == 0 {
            return Ok((first as usize, 1));
        }

        if first == 0x80 {
            // not implemented
            return Err(DecodeError::InvalidLength);
        }

        let nbytes = (first & 0x7F) as usize;
        if nbytes == 0 {
            return Err(DecodeError::InvalidLength);
        }

        if nbytes > 8 {
            // too large
            return Err(DecodeError::InvalidLength);
        }
        if buf.len() < 1 + nbytes {
            return Err(DecodeError::BufferUnderrun);
        }

        let mut len: usize = 0;
        for i in 0..nbytes {
            len = (len << 8) | (buf[1 + i] as usize);
        }
        Ok((len, 1 + nbytes))
    }
}
