use std::marker::PhantomData;

use super::{DecodeError, Length, Tag};

pub struct Decoder<'buf> {
    buf: &'buf [u8],
    pos: usize,
}

impl<'buf> Decoder<'buf> {
    pub fn new(buf: &'buf [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_tag_length<T: Tag, L: Length>(&mut self) -> Result<(T, usize), DecodeError> {
        let (tag, tag_bytes) = T::decode(&self.buf[self.pos..])?;
        self.pos += tag_bytes;

        if self.is_empty() {
            return Err(DecodeError::BufferUnderrun);
        }

        let (length, length_bytes) = L::decode(&self.buf[self.pos..])?;
        self.pos += length_bytes;

        Ok((tag, length))
    }

    fn read_value(&mut self, length: usize) -> Result<&'buf [u8], DecodeError> {
        if self.remaining() < length {
            return Err(DecodeError::BufferUnderrun);
        }

        let value = &self.buf[self.pos..self.pos + length];
        self.pos += length;
        Ok(value)
    }

    fn read_tlv<T: Tag, L: Length>(&mut self) -> Result<(T, &'buf [u8]), DecodeError> {
        let (tag, length) = self.read_tag_length::<T, L>()?;
        let value = self.read_value(length)?;
        Ok((tag, value))
    }

    pub fn into_iter_tags<T: Tag, L: Length>(self) -> TlvIter<'buf, T, L> {
        TlvIter {
            decoder: self,
            _phantom: PhantomData,
        }
    }
}

pub struct TlvIter<'buf, T: Tag, L: Length> {
    decoder: Decoder<'buf>,
    _phantom: PhantomData<(T, L)>,
}

impl<'buf, T: Tag, L: Length> Iterator for TlvIter<'buf, T, L> {
    type Item = Result<(T, &'buf [u8]), DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.decoder.is_empty() {
            None
        } else {
            Some(self.decoder.read_tlv::<T, L>())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tlv::U8Length;

    #[test]
    fn test_u8_is_tag() {
        let buf = [0x01, 0x00];
        let mut decoder = Decoder::new(&buf);
        assert_eq!(decoder.read_tag_length::<u8, U8Length>(), Ok((0x01, 0x00)));
    }

    #[test]
    fn test_u8_length() {
        let buf = [0x01, 0xFF];
        let mut decoder = Decoder::new(&buf);
        assert_eq!(decoder.read_tag_length::<u8, U8Length>(), Ok((0x01, 0xFF)));
    }
}
