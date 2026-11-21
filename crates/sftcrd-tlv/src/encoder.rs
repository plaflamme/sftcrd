use crate::error::EncodeError;

use super::{Encode, EncodeValue, Length, Tag};

enum BufSink<'a> {
    Count(usize),
    Write { buf: &'a mut [u8], pos: usize },
}

impl BufSink<'_> {
    fn pos(&self) -> usize {
        match self {
            Self::Count(pos) | Self::Write { pos, .. } => *pos,
        }
    }

    fn advance_by(&mut self, len: usize) -> Result<Option<&mut [u8]>, EncodeError> {
        match self {
            Self::Count(pos) => {
                *pos = pos.checked_add(len).ok_or(EncodeError::InvalidLength)?;
                Ok(None)
            }
            Self::Write { buf, pos } => {
                let end = pos.checked_add(len).ok_or(EncodeError::BufferUnderrun)?;
                if end > buf.len() {
                    return Err(EncodeError::BufferUnderrun);
                }
                let start = *pos;
                *pos = end;
                Ok(Some(&mut buf[start..end]))
            }
        }
    }

    fn write_tag_length<T: Tag, L: Length>(
        &mut self,
        tag: &T,
        value_length: usize,
    ) -> Result<(), EncodeError> {
        let tag_len = tag.length();
        if let Some(slice) = self.advance_by(tag_len)? {
            tag.encode(slice)?;
        }
        let len_len = L::length(value_length) as usize;
        if let Some(slice) = self.advance_by(len_len)? {
            L::encode(value_length, slice)?;
        }
        Ok(())
    }

    fn write_encoded<V: Encode + ?Sized>(
        &mut self,
        value_length: usize,
        value: &V,
    ) -> Result<(), EncodeError> {
        if let Some(slice) = self.advance_by(value_length)? {
            let mut sub = Encoder::new(slice);
            value.encode(&mut sub)?;
        }
        Ok(())
    }
}

enum EncoderKind<'a> {
    Tlv(BufSink<'a>),
    HeaderList { tpl: BufSink<'a>, val: BufSink<'a> },
}

/// Encodes TLV streams, leaf values, or ISO/IEC 7816-4 header lists into pre-allocated buffers
/// or measures their encoded byte lengths without allocation.
pub struct Encoder<'a>(EncoderKind<'a>);

impl<'a> Encoder<'a> {
    /// Creates an encoder writing standard TLV bytes or raw leaf values into `buf`.
    #[must_use]
    fn new(buf: &'a mut [u8]) -> Self {
        Self(EncoderKind::Tlv(BufSink::Write { buf, pos: 0 }))
    }

    /// Creates an encoder writing an ISO/IEC 7816-4 header list into disjoint `tpl` and `val` buffers.
    #[must_use]
    fn header_list(tpl: &'a mut [u8], val: &'a mut [u8]) -> Self {
        Self(EncoderKind::HeaderList {
            tpl: BufSink::Write { buf: tpl, pos: 0 },
            val: BufSink::Write { buf: val, pos: 0 },
        })
    }

    /// Encodes `value` into a newly allocated buffer in standard TLV mode.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if encoding fails.
    pub fn encode_tlv<V: Encode + ?Sized>(value: &V) -> Result<Vec<u8>, EncodeError> {
        let len = Self::measure_tlv(value)?;
        let mut buf = vec![0; len];
        let mut encoder = Encoder::new(&mut buf);
        value.encode(&mut encoder)?;
        Ok(buf)
    }

    /// Encodes `value` into a `(template, values)` byte-vector pair in header-list mode.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if encoding fails or `value` does not support header lists.
    pub fn encode_header_list<V: Encode + ?Sized>(
        value: &V,
    ) -> Result<(Vec<u8>, Vec<u8>), EncodeError> {
        let (tpl_len, val_len) = Self::measure_header_list(value)?;
        let mut template = vec![0; tpl_len];
        let mut values = vec![0; val_len];
        let mut encoder = Encoder::header_list(&mut template, &mut values);
        value.encode(&mut encoder)?;
        Ok((template, values))
    }

    /// Measures the encoded byte length of `value` in standard TLV mode.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if `value` fails to encode or is incompatible with TLV mode.
    pub(crate) fn measure_tlv<V: Encode + ?Sized>(value: &V) -> Result<usize, EncodeError> {
        let mut encoder = Encoder(EncoderKind::Tlv(BufSink::Count(0)));
        value.encode(&mut encoder)?;
        match encoder.0 {
            EncoderKind::Tlv(sink) => Ok(sink.pos()),
            EncoderKind::HeaderList { .. } => {
                unreachable!("measure_tlv only constructs EncoderKind::Tlv")
            }
        }
    }

    /// Measures the encoded `(template_len, values_len)` byte lengths of `value` in header-list mode.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if `value` fails to encode or is incompatible with header-list mode.
    fn measure_header_list<V: Encode + ?Sized>(value: &V) -> Result<(usize, usize), EncodeError> {
        let mut encoder = Encoder(EncoderKind::HeaderList {
            tpl: BufSink::Count(0),
            val: BufSink::Count(0),
        });
        value.encode(&mut encoder)?;
        match encoder.0 {
            EncoderKind::HeaderList { tpl, val } => Ok((tpl.pos(), val.pos())),
            EncoderKind::Tlv(_) => {
                unreachable!("measure_header_list only constructs EncoderKind::HeaderList")
            }
        }
    }

    /// Writes a leaf value (without tag or length) in TLV mode.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::InvalidValue`] in header-list mode, or [`EncodeError`] if the buffer
    /// is too small or the value fails to encode.
    pub(crate) fn write_value<V: EncodeValue + ?Sized>(
        &mut self,
        value: &V,
    ) -> Result<(), EncodeError> {
        let EncoderKind::Tlv(sink) = &mut self.0 else {
            return Err(EncodeError::InvalidValue);
        };
        let value_length = value.length();
        if let Some(slice) = sink.advance_by(value_length)? {
            value.encode_bytes(slice)?;
        }
        Ok(())
    }

    /// Writes a tag-length-value entry.
    ///
    /// In TLV mode, writes tag, length, and value bytes sequentially.
    /// In header-list mode, writes tag and length to the template buffer and value bytes to the values buffer.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if the buffer is not large enough or if the value, tag, or length cannot be encoded.
    pub fn write_tlv<T: Tag, L: Length, V: Encode + ?Sized>(
        &mut self,
        tag: &T,
        value: &V,
    ) -> Result<(), EncodeError> {
        let value_length = Self::measure_tlv(value)?;
        match &mut self.0 {
            EncoderKind::Tlv(sink) => {
                sink.write_tag_length::<T, L>(tag, value_length)?;
                sink.write_encoded(value_length, value)
            }
            EncoderKind::HeaderList { tpl, val } => {
                tpl.write_tag_length::<T, L>(tag, value_length)?;
                val.write_encoded(value_length, value)
            }
        }
    }

    /// Writes an ISO/IEC 7816-4 header-list field as a `(tpl_tag, val_tag)` pair of sibling TLVs,
    /// writing directly into disjoint slices without intermediate allocations.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::InvalidValue`] in header-list mode, or [`EncodeError`] if the buffer
    /// is not large enough or encoding fails.
    pub fn write_header_list<T: Tag, L: Length, V: Encode + ?Sized>(
        &mut self,
        tpl_tag: &T,
        val_tag: &T,
        value: &V,
    ) -> Result<(), EncodeError> {
        let EncoderKind::Tlv(sink) = &mut self.0 else {
            return Err(EncodeError::InvalidValue);
        };
        let (tpl_len, val_len) = Self::measure_header_list(value)?;
        sink.write_tag_length::<T, L>(tpl_tag, tpl_len)?;
        let val_hdr_len = val_tag.length() + L::length(val_len) as usize;
        let total_rest = tpl_len
            .checked_add(val_hdr_len)
            .and_then(|n| n.checked_add(val_len))
            .ok_or(EncodeError::InvalidLength)?;
        if let Some(region) = sink.advance_by(total_rest)? {
            let (tpl_buf, rest) = region.split_at_mut(tpl_len);
            let (val_hdr_buf, val_buf) = rest.split_at_mut(val_hdr_len);
            let mut hdr_sink = BufSink::Write {
                buf: val_hdr_buf,
                pos: 0,
            };
            hdr_sink.write_tag_length::<T, L>(val_tag, val_len)?;
            let mut hl_enc = Encoder::header_list(tpl_buf, val_buf);
            value.encode(&mut hl_enc)?;
        }
        Ok(())
    }
}

/// Internal helper used by [`crate::tlv_enum!`] to encode an inline struct
/// variant's nested TLV fields directly into a parent [`Encoder`] without
/// intermediate allocations.
#[doc(hidden)]
pub struct __EncodeFn<F>(pub F);

impl<F: Fn(&mut Encoder<'_>) -> Result<(), EncodeError>> Encode for __EncodeFn<F> {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        (self.0)(encoder)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{U8Length, U8Tag};

    #[test]
    fn test_encode_u8() {
        let mut buf = [0; 256];
        let mut encoder = Encoder::new(&mut buf);
        encoder
            .write_tlv::<U8Tag, U8Length, u8>(&U8Tag(0x01), &0x02)
            .expect("encode");
        let len = Encoder::measure_tlv(&0x02u8).expect("measure");
        assert_eq!(len, 1);
        assert_eq!(&buf[..3], [0x01, 0x01, 0x02]);
    }

    #[test]
    fn test_leaf_rejects_header_list_mode() {
        let mut tpl = [0; 16];
        let mut val = [0; 16];
        let mut encoder = Encoder::header_list(&mut tpl, &mut val);
        assert_eq!(0x02u8.encode(&mut encoder), Err(EncodeError::InvalidValue));
        assert_eq!(
            Encoder::measure_header_list(&0x02u8),
            Err(EncodeError::InvalidValue)
        );
    }
}
