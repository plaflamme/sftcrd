use crate::error::EncodeError;

use super::{Length, Tag, ValueEncoder};

pub struct Encoder<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Encoder<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[allow(unused)]
    fn into_inner(self) -> &'a mut [u8] {
        &mut self.buf[0..self.pos]
    }

    /// Moves the write pointer forward by `len` and returns a mutable slice over the region created.
    fn advance_by(&mut self, len: usize) -> &mut [u8] {
        let pos = self.pos;
        self.pos += len;
        &mut self.buf[pos..pos + len]
    }

    fn write_tag_length<T: Tag, L: Length>(
        &mut self,
        tag: T,
        value_length: usize,
    ) -> Result<(), EncodeError> {
        tag.encode(self.advance_by(T::length()))?;
        L::encode(
            value_length,
            self.advance_by(L::length(value_length) as usize),
        )?;
        Ok(())
    }

    /// Writes a tag-length-value to the buffer.
    ///
    /// # Errors
    ///
    /// Returns an [`EncodeError`] if the buffer is not large enough or if the value's tag or length cannot be encoded.
    pub fn write_tlv<T: Tag, L: Length, V: ValueEncoder>(
        &mut self,
        tag: T,
        value: &V,
    ) -> Result<(), EncodeError> {
        let value_length = value.length();
        self.write_tag_length::<T, L>(tag, value_length)?;
        value.encode(self.advance_by(value_length))?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::U8Length;

    #[test]
    fn test_encode_u8() {
        let mut buf = [0; 256];
        let mut encoder = Encoder::new(&mut buf);
        encoder
            .write_tlv::<u8, U8Length, u8>(0x01u8, &0x02)
            .expect("encode");
        assert_eq!(encoder.into_inner(), [0x01, 0x01, 0x02]);
    }
}
