use crate::error::EncodeError;

use super::DecodeError;

pub trait Tag {
    /// Returns the number of bytes required to represent the tag.
    fn length() -> usize;

    /// Encodes the tag value in the provided buffer.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::BufferUnderrun`] if the provided buffer's length is not exactly the value returned by [`Tag::length`].
    /// Returns [`EncodeError::InvalidLength`] if `value_length` cannot be represented by the implementation.
    fn encode(self, buf: &mut [u8]) -> Result<(), EncodeError>;

    #[allow(clippy::missing_errors_doc)]
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>
    where
        Self: Sized;
}

impl Tag for u8 {
    fn length() -> usize {
        1
    }

    fn encode(self, buf: &mut [u8]) -> Result<(), EncodeError> {
        if buf.is_empty() {
            return Err(EncodeError::BufferUnderrun);
        }
        buf[0] = self;
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Err(DecodeError::BufferUnderrun);
        }
        Ok((buf[0], 1))
    }
}

impl Tag for u16 {
    fn length() -> usize {
        2
    }

    fn encode(self, buf: &mut [u8]) -> Result<(), EncodeError> {
        if buf.len() < Self::length() {
            return Err(EncodeError::BufferUnderrun);
        }
        buf.copy_from_slice(&self.to_be_bytes());
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>
    where
        Self: Sized,
    {
        let Some(len) = buf.first_chunk() else {
            return Err(DecodeError::BufferUnderrun);
        };
        Ok((u16::from_be_bytes(*len), 2))
    }
}
