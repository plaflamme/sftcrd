use crate::tlv::{Length, Tag, ValueEncoder};

pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.buf
    }

    /// Extends buf by `len` and returns a mutable slice to the extended region.
    fn grow_by(&mut self, len: usize) -> &mut [u8] {
        let pos = self.buf.len();
        self.buf.resize(self.buf.len() + len, 0);
        &mut self.buf[pos..]
    }

    fn write_tag_length<T: Tag, L: Length>(&mut self, tag: T, length: usize) {
        let tag_len = T::length();
        tag.encode(self.grow_by(tag_len));

        let length_len = L::length(length);
        L::encode(length_len, self.grow_by(length_len));
    }

    pub fn write_tlv<T: Tag, L: Length, V: ValueEncoder>(&mut self, tag: T, value: &V) {
        let value_length = value.length();
        self.write_tag_length::<T, L>(tag, value_length);
        value.encode(self.grow_by(value_length));
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::tlv::U8Length;

    #[test]
    fn test_encode_u8() {
        let mut encoder = Encoder::new();
        encoder.write_tlv::<u8, U8Length, u8>(0x01u8, &0x02);
        assert_eq!(encoder.into_inner(), [0x01, 0x01, 0x02]);
    }
}
