use super::DecodeError;
use super::EncodeError;

pub trait Tag {
    fn length() -> usize;
    fn encode(self, buf: &mut [u8]) -> Result<(), EncodeError>;
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>
    where
        Self: Sized;
}

impl Tag for u8 {
    fn length() -> usize {
        1
    }
    fn encode(self, buf: &mut [u8]) -> Result<(), EncodeError> {
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
