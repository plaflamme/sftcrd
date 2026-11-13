use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    BufferUnderrun,
    InvalidTag,
    DuplicateTag,
    MissingRequiredField,
    InvalidValue,
}

impl From<!> for DecodeError {
    fn from(_value: !) -> Self {
        unreachable!()
    }
}

impl From<!> for EncodeError {
    fn from(_value: !) -> Self {
        unreachable!()
    }
}

pub trait Tag {
    #[allow(unused)]
    fn encode(self, buf: &mut [u8]) -> Result<usize, EncodeError>;
    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>
    where
        Self: Sized;
}

impl<T> Tag for T
where
    T: TryFrom<u8> + TryInto<u8>,
    <T as TryFrom<u8>>::Error: Into<DecodeError>,
    EncodeError: From<<T as TryInto<u8>>::Error>,
    DecodeError: From<<T as TryFrom<u8>>::Error>,
{
    fn encode(self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        buf[0] = self.try_into()?;
        Ok(1)
    }

    fn decode(buf: &[u8]) -> Result<(Self, usize), DecodeError>
    where
        Self: Sized,
    {
        Ok((Self::try_from(buf[0])?, 1))
    }
}

pub trait ValueDecoder
where
    Self: Sized,
{
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError>;
}

impl ValueDecoder for u8 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if let [byte] = bytes {
            Ok(*byte)
        } else {
            Err(DecodeError::BufferUnderrun)
        }
    }
}

impl ValueDecoder for u16 {
    fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if let [msb, lsb] = bytes {
            Ok(u16::from_be_bytes([*msb, *lsb]))
        } else {
            Err(DecodeError::BufferUnderrun)
        }
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

    fn read_tag<T: Tag>(&mut self) -> Result<(T, usize), DecodeError> {
        let (tag, tag_len) = T::decode(&self.buf[self.pos..])?;
        self.pos += tag_len;

        if self.is_empty() {
            return Err(DecodeError::BufferUnderrun);
        }

        // TODO: make a trait for different kinds of length encodings
        let length = self.buf[self.pos];
        self.pos += 1;

        Ok((tag, length as usize))
    }

    fn read_value(&mut self, length: usize) -> Result<&'buf [u8], DecodeError> {
        if self.remaining() < length {
            return Err(DecodeError::BufferUnderrun);
        }

        let value = &self.buf[self.pos..self.pos + length];
        self.pos += length;
        Ok(value)
    }

    pub fn into_iter_tags<T: Tag>(self) -> TlvIter<'buf, T> {
        TlvIter {
            decoder: self,
            _phantom: PhantomData,
        }
    }
}

pub struct TlvIter<'buf, T: Tag> {
    decoder: Decoder<'buf>,
    _phantom: PhantomData<T>,
}

impl<'buf, T: Tag> Iterator for TlvIter<'buf, T> {
    type Item = Result<(T, &'buf [u8]), DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.decoder.is_empty() {
            None
        } else {
            Some(self.decoder.read_tag().and_then(|(tag, length)| {
                self.decoder.read_value(length).map(|value| (tag, value))
            }))
        }
    }
}

/// Declarative macro to generate a struct and a corresponding [`ValueDecoder`] implementation to parse it out of TLV bytes.
macro_rules! parse_struct {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($fields:tt)*
        }
    ) => {
        $crate::tlv::parse_struct!(@parse_fields
            header: [ $(#[$meta])* $vis struct $name ],
            parsed: [],
            remaining: [ $($fields)* ]
        );
    };

    // Muncher Arm 1: Optional field (`Option<T>`)
    (@parse_fields
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

    // Base Case: Generate struct and `from_bytes`
    (@parse_fields
        header: [ $(#[$meta:meta])* $vis:vis struct $name:ident ],
        parsed: [
            $(
                (
                    $kind:ident,
                    $tag:expr,
                    [ $(#[$field_meta:meta])* ],
                    $field_vis:vis,
                    $field_name:ident,
                    $full_ty:ty,
                    $parse_ty:ty
                )
            )*
        ],
        remaining: []
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $(
                $(#[$field_meta])*
                $field_vis $field_name : $full_ty,
            )*
        }

        impl $crate::tlv::ValueDecoder for $name {
            fn decode(input: &[u8]) -> Result<Self, crate::tlv::DecodeError> {
                $(
                    let mut $field_name: Option<$parse_ty> = None;
                )*

                for entry in crate::tlv::Decoder::new(input).into_iter_tags::<u8>() {
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
                    $(
                        $field_name: parse_struct!(@unwrap_field $kind, $field_name),
                    )*
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
}
pub(crate) use parse_struct;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_u8_is_tag() {
        let buf = [0x01, 0x00];
        let mut decoder = Decoder::new(&buf);
        assert_eq!(decoder.read_tag::<u8>(), Ok((0x01, 0x00)));
    }

    #[test]
    fn test_parse_struct() {
        // 3. Usage Example
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
}
