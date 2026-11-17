use std::marker::PhantomData;

use super::{DecodeError, Length, Tag};

pub struct Decoder<'buf> {
    buf: &'buf [u8],
    pos: usize,
}

impl<'buf> Decoder<'buf> {
    #[must_use]
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

    #[must_use]
    pub fn into_iter_tags<T: Tag, L: Length>(self) -> TlvIter<'buf, T, L> {
        TlvIter {
            decoder: self,
            _phantom: PhantomData,
        }
    }

    /// Iterates over `(tag, length)` pairs without reading value bytes, as used
    /// in ISO/IEC 7816-4 header-list templates (e.g. `OpenPGP` tag `7F48`).
    #[must_use]
    pub fn into_iter_tag_lengths<T: Tag, L: Length>(self) -> TagLengthIter<'buf, T, L> {
        TagLengthIter {
            decoder: self,
            _phantom: PhantomData,
        }
    }
}

/// Iterator over `(tag, length)` pairs decoded from a tag-length template.
pub struct TagLengthIter<'buf, T: Tag, L: Length> {
    decoder: Decoder<'buf>,
    _phantom: PhantomData<(T, L)>,
}

impl<T: Tag, L: Length> Iterator for TagLengthIter<'_, T, L> {
    type Item = Result<(T, usize), DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.decoder.is_empty() {
            None
        } else {
            Some(self.decoder.read_tag_length::<T, L>())
        }
    }
}

/// Pairs an ISO/IEC 7816-4 tag-length `template` (e.g. `7F48`) with a flat
/// `values` buffer (e.g. `5F48`), yielding `(tag, value_slice)` entries.
#[must_use]
pub fn decode_header_list<'tpl, 'val, T: Tag, L: Length>(
    template: &'tpl [u8],
    values: &'val [u8],
) -> HeaderListIter<'tpl, 'val, T, L> {
    HeaderListIter {
        tags: Decoder::new(template).into_iter_tag_lengths(),
        values,
        done: false,
    }
}

/// Iterator over `(tag, value_slice)` entries decoded from a paired
/// `(template, values)` header list.
pub struct HeaderListIter<'tpl, 'val, T: Tag, L: Length> {
    tags: TagLengthIter<'tpl, T, L>,
    values: &'val [u8],
    done: bool,
}

impl<'val, T: Tag, L: Length> Iterator for HeaderListIter<'_, 'val, T, L> {
    type Item = Result<(T, &'val [u8]), DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.tags.next() {
            Some(Ok((tag, len))) => {
                if self.values.len() < len {
                    self.done = true;
                    return Some(Err(DecodeError::BufferUnderrun));
                }
                let (slice, rest) = self.values.split_at(len);
                self.values = rest;
                Some(Ok((tag, slice)))
            }
            Some(Err(err)) => {
                self.done = true;
                Some(Err(err))
            }
            None => {
                self.done = true;
                if self.values.is_empty() {
                    None
                } else {
                    Some(Err(DecodeError::InvalidLength))
                }
            }
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
    use crate::{U8Length, U8Tag};

    #[test]
    fn test_u8_is_tag() {
        let buf = [0x01, 0x00];
        let mut decoder = Decoder::new(&buf);
        assert_eq!(
            decoder.read_tag_length::<U8Tag, U8Length>(),
            Ok((U8Tag(0x01), 0x00))
        );
    }

    #[test]
    fn test_u8_length() {
        let buf = [0x01, 0xFF];
        let mut decoder = Decoder::new(&buf);
        assert_eq!(
            decoder.read_tag_length::<U8Tag, U8Length>(),
            Ok((U8Tag(0x01), 0xFF))
        );
    }
}
