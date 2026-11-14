use super::DecodeError;

pub trait Tag {
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>
    where
        Self: Sized;
}

impl Tag for u8 {
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
