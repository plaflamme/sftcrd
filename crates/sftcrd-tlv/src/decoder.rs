use std::marker::PhantomData;

use super::{Decode, DecodeError, Length, Tag};

struct SliceCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SliceCursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
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

    fn read_value(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < length {
            return Err(DecodeError::BufferUnderrun);
        }

        let value = &self.buf[self.pos..self.pos + length];
        self.pos += length;
        Ok(value)
    }

    fn read_tlv<T: Tag, L: Length>(&mut self) -> Result<(T, &'a [u8]), DecodeError> {
        let (tag, length) = self.read_tag_length::<T, L>()?;
        let value = self.read_value(length)?;
        Ok((tag, value))
    }
}

enum DecoderKind<'a> {
    Bytes(&'a [u8]),
    HeaderList {
        template: &'a [u8],
        values: &'a [u8],
    },
}

/// Decodes TLV streams, raw leaf value bytes, or ISO/IEC 7816-4 header lists.
pub struct Decoder<'a>(DecoderKind<'a>);

impl<'a> Decoder<'a> {
    /// Creates a decoder over a standard TLV stream or raw value bytes.
    #[must_use]
    fn new(buf: &'a [u8]) -> Self {
        Self(DecoderKind::Bytes(buf))
    }

    /// Creates a decoder over an ISO/IEC 7816-4 header-list `(template, values)` pair.
    #[must_use]
    fn header_list(template: &'a [u8], values: &'a [u8]) -> Self {
        Self(DecoderKind::HeaderList { template, values })
    }

    /// Decodes `V` from a standard TLV stream or raw byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if decoding fails.
    pub fn decode_tlv<V: Decode<'a>>(buf: &'a [u8]) -> Result<V, DecodeError> {
        V::decode(Self::new(buf))
    }

    /// Decodes `V` from an ISO/IEC 7816-4 header-list `(template, values)` pair.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if decoding fails or `V` does not support header lists.
    pub fn decode_header_list<V: Decode<'a>>(
        template: &'a [u8],
        values: &'a [u8],
    ) -> Result<V, DecodeError> {
        V::decode(Self::header_list(template, values))
    }

    /// Consumes the decoder and returns the underlying byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::InvalidValue`] if the decoder is in header-list mode.
    pub(crate) fn into_bytes(self) -> Result<&'a [u8], DecodeError> {
        match self.0 {
            DecoderKind::Bytes(bytes) => Ok(bytes),
            DecoderKind::HeaderList { .. } => Err(DecodeError::InvalidValue),
        }
    }

    /// Consumes the decoder and returns an iterator over `(tag, value_slice)` entries.
    #[must_use]
    pub fn into_iter_tags<T: Tag, L: Length>(self) -> TagIter<'a, T, L> {
        match self.0 {
            DecoderKind::Bytes(buf) => TagIter(TagIterKind::Tlv {
                cursor: SliceCursor::new(buf),
                _phantom: PhantomData,
            }),
            DecoderKind::HeaderList { template, values } => TagIter(TagIterKind::HeaderList {
                template: SliceCursor::new(template),
                values,
                _phantom: PhantomData,
            }),
        }
    }
}

enum TagIterKind<'a, T: Tag, L: Length> {
    Tlv {
        cursor: SliceCursor<'a>,
        _phantom: PhantomData<(T, L)>,
    },
    HeaderList {
        template: SliceCursor<'a>,
        values: &'a [u8],
        _phantom: PhantomData<(T, L)>,
    },
    Done,
}

/// Iterator over `(tag, value_slice)` entries from either a TLV stream or a header list.
pub struct TagIter<'a, T: Tag, L: Length>(TagIterKind<'a, T, L>);

impl<'a, T: Tag, L: Length> Iterator for TagIter<'a, T, L> {
    type Item = Result<(T, &'a [u8]), DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.0 {
            TagIterKind::Done => None,
            TagIterKind::Tlv { cursor, .. } => {
                if cursor.is_empty() {
                    self.0 = TagIterKind::Done;
                    return None;
                }
                let res = cursor.read_tlv::<T, L>();
                if res.is_err() {
                    self.0 = TagIterKind::Done;
                }
                Some(res)
            }
            TagIterKind::HeaderList {
                template, values, ..
            } => {
                if template.is_empty() {
                    let trailing = !values.is_empty();
                    self.0 = TagIterKind::Done;
                    return if trailing {
                        Some(Err(DecodeError::InvalidLength))
                    } else {
                        None
                    };
                }
                match template.read_tag_length::<T, L>() {
                    Ok((tag, len)) => {
                        if values.len() < len {
                            self.0 = TagIterKind::Done;
                            return Some(Err(DecodeError::BufferUnderrun));
                        }
                        let (slice, rest) = values.split_at(len);
                        *values = rest;
                        Some(Ok((tag, slice)))
                    }
                    Err(err) => {
                        self.0 = TagIterKind::Done;
                        Some(Err(err))
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{U8Length, U8Tag};

    #[test]
    fn test_u8_is_tag() {
        let buf = [0x01, 0x00];
        let mut cursor = SliceCursor::new(&buf);
        assert_eq!(
            cursor.read_tag_length::<U8Tag, U8Length>(),
            Ok((U8Tag(0x01), 0x00))
        );
    }

    #[test]
    fn test_u8_length() {
        let buf = [0x01, 0xFF];
        let mut cursor = SliceCursor::new(&buf);
        assert_eq!(
            cursor.read_tag_length::<U8Tag, U8Length>(),
            Ok((U8Tag(0x01), 0xFF))
        );
    }

    #[test]
    fn test_into_bytes_rejects_header_list() {
        assert_eq!(Decoder::new(&[0x01, 0x02]).into_bytes(), Ok(&[0x01, 0x02][..]));
        assert_eq!(
            Decoder::header_list(&[0x01, 0x01], &[0x02]).into_bytes(),
            Err(DecodeError::InvalidValue)
        );
    }
}
