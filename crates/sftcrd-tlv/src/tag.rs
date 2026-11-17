use crate::error::EncodeError;

use super::DecodeError;

/// A TLV tag.
pub trait Tag: Sized {
    /// Returns the number of bytes required to write this tag.
    fn length(&self) -> usize;

    /// Encodes this tag in the provided buffer.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::BufferUnderrun`] if the provided buffer is shorter than the value returned by [`Tag::length`].
    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError>;

    /// Decodes a tag from the start of `buf`, returning the tag and the number of bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::BufferUnderrun`] if `buf` is too short to hold the tag.
    /// Returns [`DecodeError::InvalidTag`] if the tag cannot be represented by the implementation.
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>;
}

/// Fixed-width, one byte tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct U8Tag(pub u8);
impl Tag for U8Tag {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        let Some(first) = buf.first_mut() else {
            return Err(EncodeError::BufferUnderrun);
        };
        *first = self.0;
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let Some(&first) = buf.first() else {
            return Err(DecodeError::BufferUnderrun);
        };
        Ok((Self(first), 1))
    }
}

/// Fixed-width, two byte tag.
///
/// The tag is encoded and decoded in big-endian byte order (most significant byte first),
/// e.g. `U16Tag(0x7F49)` is written as `[0x7F, 0x49]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct U16Tag(pub u16);
impl Tag for U16Tag {
    fn length(&self) -> usize {
        2
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        let Some(dst) = buf.first_chunk_mut::<2>() else {
            return Err(EncodeError::BufferUnderrun);
        };
        *dst = self.0.to_be_bytes();
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let Some(bytes) = buf.first_chunk() else {
            return Err(DecodeError::BufferUnderrun);
        };
        Ok((Self(u16::from_be_bytes(*bytes)), 2))
    }
}

/// ASN.1 Basic Encoding Rules (BER) tag of variable width (1 to 4 bytes).
///
/// The value is the big-endian concatenation of the tag's bytes, e.g. `0x4F`, `0x5F50` or `0x7F49`.
///
/// * if the low 5 bits of the first byte are not all set, the tag is one byte long;
/// * otherwise ("high tag number form"), subsequent bytes follow, and every subsequent byte
///   except the last one has its high bit (`0x80`) set.
///
/// Tags are limited to 4 bytes, which covers all tags used by ISO/IEC 7816-4, PIV and `OpenPGP` card.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BerTag(pub u32);
impl BerTag {
    const MAX_LENGTH: usize = 4;
}

impl Tag for BerTag {
    fn length(&self) -> usize {
        match self.0 {
            0..=0xFF => 1,
            0x100..=0xFFFF => 2,
            0x1_0000..=0xFF_FFFF => 3,
            _ => 4,
        }
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        let length = self.length();
        let Some(dst) = buf.get_mut(..length) else {
            return Err(EncodeError::BufferUnderrun);
        };
        dst.copy_from_slice(&self.0.to_be_bytes()[Self::MAX_LENGTH - length..]);
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError> {
        let Some(&first) = buf.first() else {
            return Err(DecodeError::BufferUnderrun);
        };
        let mut tag = u32::from(first);
        if first & 0x1F != 0x1F {
            return Ok((Self(tag), 1));
        }

        for (idx, &byte) in buf.iter().enumerate().skip(1) {
            if idx >= Self::MAX_LENGTH {
                return Err(DecodeError::InvalidTag);
            }
            tag = (tag << 8) | u32::from(byte);
            if byte & 0x80 == 0 {
                return Ok((Self(tag), idx + 1));
            }
        }
        Err(DecodeError::BufferUnderrun)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn encode<T: Tag>(tag: &T) -> Vec<u8> {
        let mut buf = vec![0; tag.length()];
        tag.encode(&mut buf).expect("encode");
        buf
    }

    #[test]
    fn test_ber_tag_decode() {
        assert_eq!(BerTag::decode(&[0x4F, 0x00]), Ok((BerTag(0x4F), 1)));
        assert_eq!(BerTag::decode(&[0x73]), Ok((BerTag(0x73), 1)));
        assert_eq!(BerTag::decode(&[0xC5, 0x14]), Ok((BerTag(0xC5), 1)));
        assert_eq!(BerTag::decode(&[0x5F, 0x50, 0x00]), Ok((BerTag(0x5F50), 2)));
        assert_eq!(BerTag::decode(&[0x7F, 0x49]), Ok((BerTag(0x7F49), 2)));
        assert_eq!(
            BerTag::decode(&[0x5F, 0x81, 0x01]),
            Ok((BerTag(0x5F_8101), 3))
        );
        assert_eq!(
            BerTag::decode(&[0x5F, 0x81, 0x82, 0x03]),
            Ok((BerTag(0x5F81_8203), 4))
        );
    }

    #[test]
    fn test_ber_tag_decode_errors() {
        assert_eq!(BerTag::decode(&[]), Err(DecodeError::BufferUnderrun));
        assert_eq!(BerTag::decode(&[0x5F]), Err(DecodeError::BufferUnderrun));
        assert_eq!(
            BerTag::decode(&[0x5F, 0x81]),
            Err(DecodeError::BufferUnderrun)
        );
        assert_eq!(
            BerTag::decode(&[0x5F, 0x81, 0x82, 0x83, 0x04]),
            Err(DecodeError::InvalidTag)
        );
    }

    #[test]
    fn test_ber_tag_encode() {
        assert_eq!(encode(&BerTag(0x00)), [0x00]);
        assert_eq!(encode(&BerTag(0x4F)), [0x4F]);
        assert_eq!(encode(&BerTag(0x5F50)), [0x5F, 0x50]);
        assert_eq!(encode(&BerTag(0x5F_8101)), [0x5F, 0x81, 0x01]);
        assert_eq!(encode(&BerTag(0x5F81_8203)), [0x5F, 0x81, 0x82, 0x03]);
        assert_eq!(
            BerTag(0x5F50).encode(&mut [0x00]),
            Err(EncodeError::BufferUnderrun)
        );
    }

    #[test]
    fn test_fixed_tags() {
        assert_eq!(encode(&U8Tag(0x4F)), [0x4F]);
        assert_eq!(encode(&U16Tag(0x5F50)), [0x5F, 0x50]);
        assert_eq!(encode(&U16Tag(0x4F)), [0x00, 0x4F]);
        assert_eq!(U16Tag::decode(&[0x5F, 0x50]), Ok((U16Tag(0x5F50), 2)));
        assert_eq!(U16Tag::decode(&[0x5F]), Err(DecodeError::BufferUnderrun));
        assert_eq!(U8Tag::decode(&[]), Err(DecodeError::BufferUnderrun));
    }
}
