use crate::error::EncodeError;

use super::DecodeError;

/// Implemented by values for reading them out of TLV byte buffers.
pub trait ValueDecoder<'a>
where
    Self: Sized,
{
    /// Decodes a value from the provided bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when there are not enough bytes to decode a value ([`DecodeError::BufferUnderrun`])
    /// or if the encoded value is invalid ([`DecodeError::InvalidValue`]).
    fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError>;
}

/// Implemented by structs decoded from an ISO/IEC 7816-4 header list
/// (a `(template, values)` pair of sibling TLVs, such as `OpenPGP` `7F48` + `5F48`).
pub trait HeaderListDecoder<'a>: Sized {
    /// Decodes `Self` from a tag-length `template` and flat `values` buffer.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the template or values are malformed or a required field is missing.
    fn decode_header_list(template: &'a [u8], values: &'a [u8]) -> Result<Self, DecodeError>;
}

/// Implemented by structs encoded as an ISO/IEC 7816-4 header list
/// (a `(template, values)` pair of sibling TLVs).
pub trait HeaderListEncoder {
    /// Returns the encoded `(template_len, values_len)` byte lengths.
    fn header_list_lengths(&self) -> (usize, usize);

    /// Encodes `self` into a `(template, values)` byte-vector pair.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if any tag, length, or value fails to encode.
    fn encode_header_list(&self) -> Result<(Vec<u8>, Vec<u8>), EncodeError>;
}

/// Implemented by values that know they encode to a constant number of bytes.
pub trait ConstLength {
    const LENGTH: usize;
}

impl ValueDecoder<'_> for bool {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
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

impl ValueDecoder<'_> for u8 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
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

impl ValueDecoder<'_> for u16 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
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

impl ValueDecoder<'_> for u32 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let Ok(arr): Result<[u8; 4], _> = bytes.try_into() else {
            return Err(DecodeError::BufferUnderrun);
        };
        Ok(u32::from_be_bytes(arr))
    }
}

impl ConstLength for u32 {
    const LENGTH: usize = 4;
}

impl<'a, T, const N: usize> ValueDecoder<'a> for [T; N]
where
    T: ValueDecoder<'a> + ConstLength,
{
    fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        if bytes.len() < N * T::LENGTH {
            return Err(DecodeError::BufferUnderrun);
        }
        if bytes.len() > N * T::LENGTH {
            return Err(DecodeError::InvalidValue);
        }
        let mut items = Vec::with_capacity(N);
        for chunk in bytes.chunks_exact(T::LENGTH) {
            items.push(T::decode(chunk)?);
        }
        items.try_into().map_err(|_| DecodeError::BufferUnderrun)
    }
}

impl<T: ConstLength, const N: usize> ConstLength for [T; N] {
    const LENGTH: usize = N * T::LENGTH;
}
impl ValueDecoder<'_> for Vec<u8> {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Ok(Vec::from(bytes))
    }
}

impl<'a> ValueDecoder<'a> for &'a [u8] {
    fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        Ok(bytes)
    }
}

impl<'a, A, B> ValueDecoder<'a> for (A, B)
where
    A: ValueDecoder<'a> + ConstLength,
    B: ValueDecoder<'a>,
{
    fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError> {
        let (left, right) = bytes.split_at(A::LENGTH);
        Ok((A::decode(left)?, B::decode(right)?))
    }
}

/// Implemented by values for writing them into TLV byte buffers.
pub trait ValueEncoder {
    fn length(&self) -> usize;

    /// Writes the value in the provided buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is not large enough or if the value cannot be encoded safely.
    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError>;

    /// Encodes the value to a newly allocated buffer and returns it.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is not large enough or if the value cannot be encoded safely.
    fn encode_top_level(&self) -> Result<Vec<u8>, EncodeError> {
        let mut value = vec![0; self.length()];
        self.encode(&mut value)?;
        Ok(value)
    }
}

impl ValueEncoder for bool {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        buf[0] = u8::from(*self);
        Ok(())
    }
}

impl ValueEncoder for u8 {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        buf[0] = *self;
        Ok(())
    }
}

impl ValueEncoder for u16 {
    fn length(&self) -> usize {
        2
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        buf.copy_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl ValueEncoder for u32 {
    fn length(&self) -> usize {
        4
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        buf.copy_from_slice(&self.to_be_bytes());
        Ok(())
    }
}

impl<T: ValueEncoder, const N: usize> ValueEncoder for [T; N] {
    fn length(&self) -> usize {
        self.iter().map(ValueEncoder::length).sum()
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        let mut offset = 0;
        for item in self {
            let len = item.length();
            if offset + len > buf.len() {
                return Err(EncodeError::BufferUnderrun);
            }
            item.encode(&mut buf[offset..offset + len])?;
            offset += len;
        }
        Ok(())
    }
}

impl ValueEncoder for &[u8] {
    fn length(&self) -> usize {
        self.len()
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        buf.copy_from_slice(self);
        Ok(())
    }
}

impl ValueEncoder for Vec<u8> {
    fn length(&self) -> usize {
        self.len()
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        buf.copy_from_slice(self);
        Ok(())
    }
}

impl<T> ValueEncoder for Option<T>
where
    T: ValueEncoder,
{
    fn length(&self) -> usize {
        match self {
            None => 0,
            Some(v) => v.length(),
        }
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        match self {
            None => (),
            Some(v) => v.encode(buf)?,
        }
        Ok(())
    }
}

impl<A, B> ValueEncoder for (A, B)
where
    A: ValueEncoder,
    B: ValueEncoder,
{
    fn length(&self) -> usize {
        self.0.length() + self.1.length()
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        self.0.encode(&mut buf[0..self.0.length()])?;
        self.1.encode(&mut buf[self.0.length()..])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixed_array_and_u32_codec() {
        let arr: [[u8; 2]; 3] = [[0x01, 0x02], [0x03, 0x04], [0x05, 0x06]];
        let encoded = arr.encode_top_level().unwrap();
        assert_eq!(encoded, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(<[[u8; 2]; 3]>::decode(&encoded), Ok(arr));
        assert_eq!(
            <[[u8; 2]; 3]>::decode(&[0x01, 0x02, 0x03]),
            Err(DecodeError::BufferUnderrun)
        );
        assert_eq!(
            <[[u8; 2]; 3]>::decode(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            Err(DecodeError::InvalidValue)
        );

        let nums: [u32; 2] = [0x0102_0304, 0xAABB_CCDD];
        let encoded_nums = nums.encode_top_level().unwrap();
        assert_eq!(
            encoded_nums,
            [0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]
        );
        assert_eq!(<[u32; 2]>::decode(&encoded_nums), Ok(nums));
    }
}
