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
