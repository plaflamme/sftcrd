use crate::error::EncodeError;

use super::{DecodeError, Decoder, Encoder};

/// Implemented by types that can be decoded from a [`Decoder`] (either a TLV stream / raw bytes
/// or an ISO/IEC 7816-4 header list).
pub trait Decode<'a>: Sized {
    /// Decodes `Self` from the provided [`Decoder`].
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if decoding fails or the decoder mode is incompatible with `Self`.
    fn decode(decoder: Decoder<'a>) -> Result<Self, DecodeError>;

    /// Decodes `Self` from a standard TLV stream or raw byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if decoding fails.
    fn decode_tlv(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        Decoder::decode_tlv(bytes)
    }

    /// Decodes `Self` from an ISO/IEC 7816-4 header list `(template, values)` pair.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if decoding fails or `Self` does not support header lists.
    fn decode_header_list(template: &'a [u8], values: &'a [u8]) -> Result<Self, DecodeError> {
        Decoder::decode_header_list(template, values)
    }
}

/// Implemented by types that can be encoded into an [`Encoder`] (either a TLV stream / raw bytes
/// or an ISO/IEC 7816-4 header list).
pub trait Encode {
    /// Encodes `self` into the provided [`Encoder`].
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if encoding fails or the encoder mode is incompatible with `Self`.
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError>;

    /// Returns the encoded byte length of `self` in standard TLV mode.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if measuring fails.
    fn encoded_length(&self) -> Result<usize, EncodeError> {
        Encoder::measure_tlv(self)
    }

    /// Encodes `self` to a newly allocated buffer in standard TLV mode.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if encoding fails.
    fn encode_tlv(&self) -> Result<Vec<u8>, EncodeError> {
        Encoder::encode_tlv(self)
    }

    /// Encodes `self` into a `(template, values)` byte-vector pair in header-list mode.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if encoding fails or `Self` does not support header lists.
    fn encode_header_list(&self) -> Result<(Vec<u8>, Vec<u8>), EncodeError> {
        Encoder::encode_header_list(self)
    }
}

/// Implemented by leaf values that decode from a raw byte slice.
///
/// Any type implementing `DecodeValue<'a>` automatically implements [`Decode<'a>`].
pub trait DecodeValue<'a>: Sized {
    /// Decodes a value from the provided bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when there are not enough bytes to decode a value ([`DecodeError::BufferUnderrun`])
    /// or if the encoded value is invalid ([`DecodeError::InvalidValue`]).
    fn decode_bytes(bytes: &'a [u8]) -> Result<Self, DecodeError>;
}

impl<'a, T: DecodeValue<'a>> Decode<'a> for T {
    fn decode(decoder: Decoder<'a>) -> Result<Self, DecodeError> {
        Self::decode_bytes(decoder.into_bytes()?)
    }
}

/// Implemented by leaf values that encode into a raw byte slice.
///
/// Any type implementing `EncodeValue` automatically implements [`Encode`].
pub trait EncodeValue {
    /// Returns the encoded byte length of `self`.
    fn length(&self) -> usize;

    /// Writes the value into `buf`, which is guaranteed to have length `self.length()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is not large enough or if the value cannot be encoded safely.
    fn encode_bytes(&self, buf: &mut [u8]) -> Result<(), EncodeError>;
}

impl<T: EncodeValue> Encode for T {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.write_value(self)
    }
}

/// Implemented by values that know they encode to a constant number of bytes.
pub trait ConstLength {
    const LENGTH: usize;
}

impl DecodeValue<'_> for bool {
    fn decode_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if let [byte] = bytes {
            match byte {
                0x00 => Ok(false),
                0x01 => Ok(true),
                _ => Err(DecodeError::InvalidValue),
            }
        } else {
            Err(DecodeError::BufferUnderrun)
        }
    }
}

impl ConstLength for bool {
    const LENGTH: usize = 1;
}

impl DecodeValue<'_> for u8 {
    fn decode_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if let [byte] = bytes {
            Ok(*byte)
        } else {
            Err(DecodeError::BufferUnderrun)
        }
    }
}

impl ConstLength for u8 {
    const LENGTH: usize = 1;
}

impl DecodeValue<'_> for u16 {
    fn decode_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        if let [msb, lsb] = bytes {
            Ok(u16::from_be_bytes([*msb, *lsb]))
        } else {
            Err(DecodeError::BufferUnderrun)
        }
    }
}

impl ConstLength for u16 {
    const LENGTH: usize = 2;
}

impl DecodeValue<'_> for u32 {
    fn decode_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let Ok(arr): Result<[u8; 4], _> = bytes.try_into() else {
            return Err(DecodeError::BufferUnderrun);
        };
        Ok(u32::from_be_bytes(arr))
    }
}

impl ConstLength for u32 {
    const LENGTH: usize = 4;
}

impl<'a, T, const N: usize> DecodeValue<'a> for [T; N]
where
    T: DecodeValue<'a> + ConstLength,
{
    fn decode_bytes(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() < N * T::LENGTH {
            return Err(DecodeError::BufferUnderrun);
        }
        if bytes.len() > N * T::LENGTH {
            return Err(DecodeError::InvalidValue);
        }
        let mut items = Vec::with_capacity(N);
        for chunk in bytes.chunks_exact(T::LENGTH) {
            items.push(T::decode_bytes(chunk)?);
        }
        items.try_into().map_err(|_| DecodeError::BufferUnderrun)
    }
}

impl<T: ConstLength, const N: usize> ConstLength for [T; N] {
    const LENGTH: usize = N * T::LENGTH;
}

impl DecodeValue<'_> for Vec<u8> {
    fn decode_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Vec::from(bytes))
    }
}

impl<'a> DecodeValue<'a> for &'a [u8] {
    fn decode_bytes(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        Ok(bytes)
    }
}

impl<'a, A, B> DecodeValue<'a> for (A, B)
where
    A: DecodeValue<'a> + ConstLength,
    B: DecodeValue<'a>,
{
    fn decode_bytes(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let (left, right) = bytes
            .split_at_checked(A::LENGTH)
            .ok_or(DecodeError::BufferUnderrun)?;
        Ok((A::decode_bytes(left)?, B::decode_bytes(right)?))
    }
}

impl EncodeValue for bool {
    fn length(&self) -> usize {
        1
    }

    fn encode_bytes(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        if buf.is_empty() {
            return Err(EncodeError::BufferUnderrun);
        }
        buf[0] = u8::from(*self);
        Ok(())
    }
}

impl EncodeValue for u8 {
    fn length(&self) -> usize {
        1
    }

    fn encode_bytes(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        if buf.is_empty() {
            return Err(EncodeError::BufferUnderrun);
        }
        buf[0] = *self;
        Ok(())
    }
}

impl EncodeValue for u16 {
    fn length(&self) -> usize {
        2
    }

    fn encode_bytes(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        if buf.len() != 2 {
            return Err(EncodeError::BufferUnderrun);
        }
        buf.copy_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl EncodeValue for u32 {
    fn length(&self) -> usize {
        4
    }

    fn encode_bytes(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        if buf.len() != 4 {
            return Err(EncodeError::BufferUnderrun);
        }
        buf.copy_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl<T: Encode, const N: usize> Encode for [T; N] {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        for item in self {
            item.encode(encoder)?;
        }
        Ok(())
    }
}

impl EncodeValue for &[u8] {
    fn length(&self) -> usize {
        self.len()
    }

    fn encode_bytes(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        if buf.len() != self.len() {
            return Err(EncodeError::BufferUnderrun);
        }
        buf.copy_from_slice(self);
        Ok(())
    }
}

impl EncodeValue for Vec<u8> {
    fn length(&self) -> usize {
        self.len()
    }

    fn encode_bytes(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        if buf.len() != self.len() {
            return Err(EncodeError::BufferUnderrun);
        }
        buf.copy_from_slice(self);
        Ok(())
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        if let Some(v) = self {
            v.encode(encoder)?;
        }
        Ok(())
    }
}

impl<A: Encode, B: Encode> Encode for (A, B) {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        self.0.encode(encoder)?;
        self.1.encode(encoder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_array_and_u32_codec() {
        let arr: [[u8; 2]; 3] = [[0x01, 0x02], [0x03, 0x04], [0x05, 0x06]];
        let encoded = arr.encode_tlv().unwrap();
        assert_eq!(encoded, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(<[[u8; 2]; 3]>::decode_tlv(&encoded), Ok(arr));
        assert_eq!(
            <[[u8; 2]; 3]>::decode_tlv(&[0x01, 0x02, 0x03]),
            Err(DecodeError::BufferUnderrun)
        );
        assert_eq!(
            <[[u8; 2]; 3]>::decode_tlv(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            Err(DecodeError::InvalidValue)
        );

        let nums: [u32; 2] = [0x0102_0304, 0xAABB_CCDD];
        let encoded_nums = nums.encode_tlv().unwrap();
        assert_eq!(
            encoded_nums,
            [0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]
        );
        assert_eq!(<[u32; 2]>::decode_tlv(&encoded_nums), Ok(nums));
    }

    #[test]
    fn test_leaf_rejects_header_list() {
        assert_eq!(
            u8::decode_header_list(&[0x01, 0x01], &[0x42]),
            Err(DecodeError::InvalidValue)
        );
        assert_eq!(0x42u8.encode_header_list(), Err(EncodeError::InvalidValue));
        assert_eq!(
            <&[u8]>::decode_header_list(&[0x01, 0x01], &[0x42]),
            Err(DecodeError::InvalidValue)
        );
        assert_eq!(
            [0x42u8].as_slice().encode_header_list(),
            Err(EncodeError::InvalidValue)
        );
    }
}
