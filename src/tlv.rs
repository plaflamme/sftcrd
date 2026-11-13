use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    BufferUnderrun,
    InvalidTag,
    InvalidLength,
    InvalidValue,
    DuplicateTag,
    MissingRequiredField,
}

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

pub trait Length {
    fn decode(buf: &[u8]) -> Result<(usize, usize), DecodeError>
    where
        Self: Sized;
}

pub struct U8Length;
impl Length for U8Length {
    fn decode(buf: &[u8]) -> Result<(usize, usize), DecodeError>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Err(DecodeError::BufferUnderrun);
        }
        Ok((buf[0] as usize, 1))
    }
}

/// ASN.1 Basic Encoding Rules (BER) length form.
///
/// The first byte indicates the form of the length field:
/// * `first <= 0x7F` => short "definite lenth form", length one byte long and is the value of `first`
/// * `first == 0x80` => "indefinite lenth form", read until End-of-Content (0x00, 0x00) occurs in the byte stream
/// * `first > 0x80` => "variable "definite lenth form", bits 0x7f indicate the number of bytes the length is encoded on (big-endian)
pub struct BerLength;
impl Length for BerLength {
    fn decode(buf: &[u8]) -> Result<(usize, usize), DecodeError>
    where
        Self: Sized,
    {
        if buf.is_empty() {
            return Err(DecodeError::BufferUnderrun);
        }

        let first = buf[0];
        // short form
        if first & 0x80 == 0 {
            return Ok((first as usize, 1));
        }

        if first == 0x80 {
            // not implemented
            return Err(DecodeError::InvalidLength);
        }

        let nbytes = (first & 0x7F) as usize;
        if nbytes == 0 {
            return Err(DecodeError::InvalidLength);
        }

        if nbytes > 8 {
            // too large
            return Err(DecodeError::InvalidLength);
        }
        if buf.len() < 1 + nbytes {
            return Err(DecodeError::BufferUnderrun);
        }

        let mut len: usize = 0;
        for i in 0..nbytes {
            len = (len << 8) | (buf[1 + i] as usize);
        }
        Ok((len, 1 + nbytes))
    }
}

pub trait ValueDecoder<'a>
where
    Self: Sized,
{
    fn decode(bytes: &'a [u8]) -> Result<Self, DecodeError>;
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

/// Declarative macro to generate a struct and a corresponding [`ValueDecoder`] implementation to parse it out of TLV bytes.
macro_rules! parse_struct {
    // -------------------------------------------------------------------------
    // 1) Attribute Munching
    // -------------------------------------------------------------------------

    // Match `#[length(SomeType)]`
    (@parse_attrs
        tag_type: [ $($tag_ty:tt)* ],
        length: [ $($len:tt)* ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ #[length($len_ty:ty)] $($rest:tt)* ]
    ) => {
        parse_struct!(@parse_attrs
            tag_type: [ $($tag_ty)* ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            retained: [ $($retained)* ],
            input: [ $($rest)* ]
        );
    };

    // Match `#[tag_type(SomeType)]`
    (@parse_attrs
        tag_type: [ $($tag_ty:tt)* ],
        length: [ $($len:tt)* ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ #[tag_type($new_tag_ty:ty)] $($rest:tt)* ]
    ) => {
        parse_struct!(@parse_attrs
            tag_type: [ $new_tag_ty ],
            length: [ $($len)* ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            retained: [ $($retained)* ],
            input: [ $($rest)* ]
        );
    };

    // Found any other attribute (keep it in `retained`)
    (@parse_attrs
        tag_type: [ $($tag_ty:tt)* ],
        length: [ $($len:tt)* ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ #[$($attr:tt)*] $($rest:tt)* ]
    ) => {
        parse_struct!(@parse_attrs
            tag_type: [ $($tag_ty)* ],
            length: [ $($len)* ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            retained: [ $($retained)* #[$($attr)*] ],
            input: [ $($rest)* ]
        );
    };

    // Base Case for attributes: Transition to field parsing
    (@parse_attrs
        tag_type: [ $tag_ty:ty ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        // We drop whatever lifetime the input had here, relying instead on our tracked state
        input: [ $vis:vis struct $name:ident $(<$ignore_lt:lifetime>)? { $($fields:tt)* } ]
    ) => {
        $crate::tlv::parse_struct!(@parse_fields
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            header: [ $($retained)* $vis struct $name $(<$struct_lt>)? ],
            parsed: [],
            remaining: [ $($fields)* ]
        );
    };

    // -------------------------------------------------------------------------
    // 2) Field Munchers
    // -------------------------------------------------------------------------

    // Muncher Arm 1: Optional field (`Option<T>`)
    (@parse_fields
        tag_type: [ $tag_ty:ty ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        parsed: [ $($parsed:tt)* ],
        remaining: [
            #[tag = $tag:expr]
            $(#[$field_meta:meta])*
            $field_vis:vis $field_name:ident : Option < $inner_ty:ty >
            $(, $($rest:tt)*)?
        ]
    ) => {
        parse_struct!(@parse_fields
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            header: [ $($header)* ],
            parsed: [
                $($parsed)*
                (
                    opt,
                    $tag,
                    [ $(#[$field_meta])* ],
                    $field_vis,
                    $field_name,
                    Option<$inner_ty>,
                    $inner_ty
                )
            ],
            remaining: [ $($($rest)*)? ]
        );
    };

    // Muncher Arm 2: Required field (`T`)
    (@parse_fields
        tag_type: [ $tag_ty:ty ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        parsed: [ $($parsed:tt)* ],
        remaining: [
            #[tag = $tag:expr]
            $(#[$field_meta:meta])*
            $field_vis:vis $field_name:ident : $field_ty:ty
            $(, $($rest:tt)*)?
        ]
    ) => {
        parse_struct!(@parse_fields
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            header: [ $($header)* ],
            parsed: [
                $($parsed)*
                (
                    req,
                    $tag,
                    [ $(#[$field_meta])* ],
                    $field_vis,
                    $field_name,
                    $field_ty,
                    $field_ty
                )
            ],
            remaining: [ $($($rest)*)? ]
        );
    };

    // Base Case: Generate struct and `from_bytes` (Unified!)
    (@parse_fields
        tag_type: [ $tag_ty:ty ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        // The header arrives perfectly formed from `@parse_attrs`
        header: [ $(#[$meta:meta])* $vis:vis struct $name:ident $(<$lt_header:lifetime>)? ],
        parsed: [
            $( ( $kind:ident, $tag:expr, [ $(#[$field_meta:meta])* ], $field_vis:vis, $field_name:ident, $full_ty:ty, $parse_ty:ty ) )*
        ],
        remaining: []
    ) => {
        $(#[$meta])*
        $vis struct $name $(<$struct_lt>)? {
            $(
                $(#[$field_meta])*
                $field_vis $field_name : $full_ty,
            )*
        }

        // $impl_lt is ALWAYS present here, while $struct_lt is optional!
        impl <$impl_lt> $crate::tlv::ValueDecoder<$impl_lt> for $name $(<$struct_lt>)? {
            fn decode(input: &$impl_lt [u8]) -> Result<Self, crate::tlv::DecodeError> {
                $( let mut $field_name: Option<$parse_ty> = None; )*

                for entry in crate::tlv::Decoder::new(input).into_iter_tags::<$tag_ty, $len_ty>() {
                    let (tag, value_bytes) = entry?;
                    match tag {
                        $(
                            $tag => {
                                if $field_name.is_some() {
                                    return Err($crate::tlv::DecodeError::DuplicateTag);
                                }
                                let val = <$parse_ty as $crate::tlv::ValueDecoder>::decode(value_bytes)?;
                                $field_name = Some(val);
                            }
                        )*
                        _ => return Err(crate::tlv::DecodeError::InvalidTag),
                    }
                }

                Ok(Self {
                    $( $field_name: parse_struct!(@unwrap_field $kind, $field_name), )*
                })
            }
        }
    };

    (@unwrap_field req, $field_name:ident) => {
        $field_name.ok_or(crate::tlv::DecodeError::MissingRequiredField)?
    };
    (@unwrap_field opt, $field_name:ident) => {
        $field_name
    };

    // -------------------------------------------------------------------------
    // 3) Public Entry Points
    // -------------------------------------------------------------------------

    // Path A: Struct has a lifetime parameter (e.g. struct Foo<'a>)
    (
        $(#[$($attr:tt)*])*
        $vis:vis struct $name:ident <$lt:lifetime> {
            $($fields:tt)*
        }
    ) => {
        parse_struct!(@parse_attrs
            tag_type: [ u8 ],
            length: [ $crate::tlv::U8Length ],
            impl_lt: [ $lt ],     // Trait uses the provided lifetime
            struct_lt: [ $lt ],   // Struct uses the provided lifetime
            retained: [],
            input: [ $(#[$($attr)*])* $vis struct $name <$lt> { $($fields)* } ]
        );
    };

    // Path B: Struct does NOT have a lifetime parameter
    (
        $(#[$($attr:tt)*])*
        $vis:vis struct $name:ident {
            $($fields:tt)*
        }
    ) => {
        parse_struct!(@parse_attrs
            tag_type: [ u8 ],
            length: [ $crate::tlv::U8Length ],
            impl_lt: [ 'a ], // Trait uses a synthetic generated lifetime
            struct_lt: [],   // Struct has no lifetime
            retained: [],
            input: [ $(#[$($attr)*])* $vis struct $name { $($fields)* } ]
        );
    };
}
pub(crate) use parse_struct;

#[cfg(test)]
mod test {
    use super::*;

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

    #[test]
    fn test_ber_length() {
        // short form
        assert_eq!(BerLength::decode(&[0x7F, 0x00]), Ok((0x7F, 1)));
        // indefinite form (unsupported)
        assert_eq!(
            BerLength::decode(&[0x80, 0x00]),
            Err(DecodeError::InvalidLength)
        );
        // variable form
        assert_eq!(BerLength::decode(&[0x81, 0x00]), Ok((0, 2)));
        assert_eq!(BerLength::decode(&[0x82, 0x01, 0x00]), Ok((0x0100, 3)));
        assert_eq!(
            BerLength::decode(&[0x88, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            Ok((0x0102_0304_0506_0708, 9))
        );
        assert_eq!(
            BerLength::decode(&[0x89, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09]),
            Err(DecodeError::InvalidLength)
        );
        assert_eq!(BerLength::decode(&[0x81]), Err(DecodeError::BufferUnderrun));
        assert_eq!(
            BerLength::decode(&[0x82, 0x01]),
            Err(DecodeError::BufferUnderrun)
        );
    }

    #[test]
    fn test_parse_struct() {
        parse_struct! {
            #[derive(Debug, PartialEq)]
            pub struct Packet {
                #[tag = 0x01]
                pub version: u8,
                #[tag = 0x02]
                pub payload_len: u16,
                #[tag = 0x03]
                pub opt: Option<u16>,
            }
        }
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0xFF, 0x02, 0x02, 0xFF, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: 0xFFFE,
                opt: None
            })
        );
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0xFF, 0x02, 0x02, 0xFF, 0xFE, 0x04, 0x00]),
            Err(DecodeError::InvalidTag)
        );
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0xFF, 0x02, 0x02, 0xFF, 0xFE, 0x01, 0x01, 0xFF]),
            Err(DecodeError::DuplicateTag)
        );
        assert_eq!(
            Packet::decode(&[0x01, 0x01]),
            Err(DecodeError::BufferUnderrun)
        );
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0xFF]),
            Err(DecodeError::MissingRequiredField)
        );
    }

    #[test]
    fn test_parse_struct_tag_type() {
        parse_struct! {
            #[derive(Debug, PartialEq)]
            #[tag_type(u16)]
            pub struct Packet {
                #[tag = 0x0101]
                pub version: u8,
                #[tag = 0x0102]
                pub payload_len: u8,
            }
        }
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0x01, 0xFF, 0x01, 0x02, 0x01, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: 0xFE,
            })
        );
    }

    #[test]
    fn test_parse_struct_length() {
        parse_struct! {
            #[derive(Debug, PartialEq)]
            #[length(BerLength)]
            pub struct Packet {
                #[tag = 0x01]
                pub version: u8,
                #[tag = 0x02]
                pub payload_len: Vec<u8>,
            }
        }
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0xFF, 0x02, 0x81, 0x01, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: vec![0xFE],
            })
        );
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0xFF, 0x02, 0x82, 0x00, 0x01, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: vec![0xFE],
            })
        );
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0xFF, 0x02, 0x80, 0xFE, 0x00, 0x00]),
            Err(DecodeError::InvalidLength)
        );
    }

    #[test]
    fn test_parse_struct_lifetime() {
        parse_struct! {
            #[derive(Debug, PartialEq)]
            #[length(BerLength)]
            pub struct Packet<'a> {
                #[tag = 0x01]
                pub version: u8,
                #[tag = 0x02]
                pub payload_len: &'a [u8],
            }
        }
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0xFF, 0x02, 0x81, 0x01, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: &[0xFE],
            })
        );
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0xFF, 0x02, 0x82, 0x00, 0x01, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: &[0xFE],
            })
        );
        assert_eq!(
            Packet::decode(&[0x01, 0x01, 0xFF, 0x02, 0x80, 0xFE, 0x00, 0x00]),
            Err(DecodeError::InvalidLength)
        );
    }
}
