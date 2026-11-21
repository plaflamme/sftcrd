use crate::error::EncodeError;

use super::DecodeError;

pub trait Length {
    /// Returns the number of bytes required to write the value's length.
    fn length(value_length: usize) -> u8;

    /// Encodes the length in the provided buffer.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::BufferUnderrun`] if the provided buffer's length is not exactly the value returned by [`Length::length`].
    /// Returns [`EncodeError::InvalidLength`] if `value_length` cannot be represented by the implementation.
    fn encode(value_length: usize, buf: &mut [u8]) -> Result<(), EncodeError>;

    #[allow(clippy::missing_errors_doc)]
    fn decode(buf: &[u8]) -> Result<(usize, usize), DecodeError>
    where
        Self: Sized;
}

pub struct U8Length;
impl Length for U8Length {
    fn length(_value: usize) -> u8 {
        1
    }

    fn encode(length: usize, buf: &mut [u8]) -> Result<(), EncodeError> {
        let length = u8::try_from(length).map_err(|_| EncodeError::InvalidLength)?;
        buf[0] = length;
        Ok(())
    }

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

/// Fixed 4-byte big-endian `u32` length encoding.
pub struct U32Length;
impl Length for U32Length {
    fn length(_value: usize) -> u8 {
        4
    }

    fn encode(length: usize, buf: &mut [u8]) -> Result<(), EncodeError> {
        if buf.len() != 4 {
            return Err(EncodeError::BufferUnderrun);
        }
        let length = u32::try_from(length).map_err(|_| EncodeError::InvalidLength)?;
        buf.copy_from_slice(&length.to_be_bytes());
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<(usize, usize), DecodeError>
    where
        Self: Sized,
    {
        let Some(bytes) = buf.get(..4) else {
            return Err(DecodeError::BufferUnderrun);
        };
        let arr: [u8; 4] = bytes.try_into().expect("slice has length 4");
        let len =
            usize::try_from(u32::from_be_bytes(arr)).map_err(|_| DecodeError::InvalidLength)?;
        Ok((len, 4))
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
    fn length(value_length: usize) -> u8 {
        let length = u64::try_from(value_length)
            .expect("this crate will not compile on anything but 32 or 64 architectures");

        match length {
            0..0x80 => 1,
            0x0000_0000_0000_0080..=0x0000_0000_0000_00FF => 2,
            0x0000_0000_0000_0100..=0x0000_0000_0000_FFFF => 3,
            0x0000_0000_0001_0000..=0x0000_0000_00FF_FFFF => 4,
            0x0000_0000_0100_0000..=0x0000_0000_FFFF_FFFF => 5,
            0x0000_0001_0000_0000..=0x0000_00FF_FFFF_FFFF => 6,
            0x0000_0100_0000_0000..=0x0000_FFFF_FFFF_FFFF => 7,
            0x0001_0000_0000_0000..=0x00FF_FFFF_FFFF_FFFF => 8,
            0x0100_0000_0000_0000..=0xFFFF_FFFF_FFFF_FFFF => 9,
        }
    }

    fn encode(value_length: usize, buf: &mut [u8]) -> Result<(), EncodeError> {
        let length = BerLength::length(value_length);

        if buf.len() != length as usize {
            return Err(EncodeError::BufferUnderrun);
        }

        match length {
            1 => buf[0] = u8::try_from(value_length).expect("can be represented on u8"),
            len => {
                let n_bytes = len - 1;
                let bytes = value_length.to_be_bytes();
                let start = bytes.len() - n_bytes as usize;
                buf[0] = 0x80 | n_bytes;
                buf[1..].copy_from_slice(&bytes[start..]);
            }
        }
        Ok(())
    }

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

#[cfg(test)]
mod tests {
    use crate::{BerLength, DecodeError, Length, U32Length, error::EncodeError};

    #[test]
    fn test_u32_length() {
        assert_eq!(U32Length::length(0), 4);
        assert_eq!(U32Length::length(65_544), 4);

        let mut buf = [0u8; 4];
        U32Length::encode(0x0001_0008, &mut buf).unwrap();
        assert_eq!(buf, [0x00, 0x01, 0x00, 0x08]);
        assert_eq!(U32Length::decode(&buf), Ok((0x0001_0008, 4)));

        assert_eq!(
            U32Length::encode(1, &mut [0u8; 3]),
            Err(EncodeError::BufferUnderrun)
        );
        assert_eq!(
            U32Length::decode(&[0x00, 0x01, 0x02]),
            Err(DecodeError::BufferUnderrun)
        );
    }

    #[test]
    fn test_ber_length_decode() {
        // short form
        assert_eq!(BerLength::decode(&[0x7F, 0x00]), Ok((0x7F, 1)));
        // indefinite form (unsupported)
        assert_eq!(
            BerLength::decode(&[0x80, 0x00]),
            Err(DecodeError::InvalidLength)
        );
        // variable form
        assert_eq!(BerLength::decode(&[0x81, 0x00]), Ok((0, 2)));
        assert_eq!(BerLength::decode(&[0x82, 0x01, 0x00]), Ok((0x0100, 3)));
        assert_eq!(
            BerLength::decode(&[0x88, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            Ok((0x0102_0304_0506_0708, 9))
        );
        assert_eq!(
            BerLength::decode(&[0x89, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]),
            Err(DecodeError::InvalidLength)
        );
        assert_eq!(BerLength::decode(&[0x81]), Err(DecodeError::BufferUnderrun));
        assert_eq!(
            BerLength::decode(&[0x82, 0x01]),
            Err(DecodeError::BufferUnderrun)
        );
    }

    #[test]
    fn test_ber_length() {
        let cases: &[(usize, &[u8])] = &[
            (0x00, &[0x00]),
            (0x7F, &[0x7F]),
            (0x80, &[0x81, 0x80]),
            (0xFF, &[0x81, 0xFF]),
            (0x0102, &[0x82, 0x01, 0x02]),
            (0x01_0203, &[0x83, 0x01, 0x02, 0x03]),
            (0x0102_0304, &[0x84, 0x01, 0x02, 0x03, 0x04]),
            (0x01_0203_0405, &[0x85, 0x01, 0x02, 0x03, 0x04, 0x05]),
            (
                0x0102_0304_0506,
                &[0x86, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            ),
            (
                0x01_0203_0405_0607,
                &[0x87, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            ),
            (
                0x0102_0304_0506_0708,
                &[0x88, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            ),
        ];

        for &(value_length, expected) in cases {
            assert_eq!(
                BerLength::length(value_length) as usize,
                expected.len(),
                "BerLength({value_length}) == {}",
                expected.len()
            );

            let mut buf = vec![0u8; expected.len()];
            assert!(BerLength::encode(value_length, &mut buf).is_ok());
            assert_eq!(
                buf, expected,
                "BerLength::encode({value_length}) == {expected:?}"
            );
        }
    }

    #[test]
    fn test_ber_length_encode_assertion() {
        assert_eq!(
            BerLength::encode(0xFFFF, &mut [0; 2]),
            Err(EncodeError::BufferUnderrun)
        );
    }
}
