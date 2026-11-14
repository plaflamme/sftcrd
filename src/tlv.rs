mod decoder;
mod encoder;
mod error;
mod length;
mod tag;
mod value;

pub use decoder::Decoder;
pub use encoder::Encoder;
pub use error::{DecodeError, EncodeError};
pub use length::{BerLength, Length, U8Length};
pub use tag::Tag;
pub use value::{ValueDecoder, ValueEncoder};

/// Declarative macro to generate a struct and a corresponding [`ValueDecoder`] implementation to parse it out of TLV bytes.
macro_rules! tlv_struct {
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
        tlv_struct!(@parse_attrs
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
        tlv_struct!(@parse_attrs
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
        tlv_struct!(@parse_attrs
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
        tlv_struct!(@parse_fields
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
        tlv_struct!(@parse_fields
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
        tlv_struct!(@parse_fields
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
                    $( $field_name: tlv_struct!(@unwrap_field $kind, $field_name), )*
                })
            }
        }

        impl <$impl_lt> $crate::tlv::ValueEncoder for $name $(<$struct_lt>)? {
            fn length(&self) -> usize {
                let mut length = 0;
                let tag_length = <$tag_ty as $crate::tlv::Tag>::length();
                $(
                    let value_len = <$full_ty as $crate::tlv::ValueEncoder>::length(&self.$field_name);
                    let length_len = <$len_ty as $crate::tlv::Length>::length(value_len);
                    length += tag_length + length_len + value_len;
                )*
                length
            }

            fn encode(&self, buf: &mut [u8]) {
                let tag_length = <$tag_ty as $crate::tlv::Tag>::length();
                $(
                    <$tag_ty as $crate::tlv::Tag>::encode($tag, &mut buf[0..tag_length]);
                    let value_len = <$full_ty as $crate::tlv::ValueEncoder>::length(&self.$field_name);
                    let length_len = <$len_ty as $crate::tlv::Length>::length(value_len);
                    <$len_ty as $crate::tlv::Length>::encode(value_len, &mut buf[tag_length..tag_length+length_len]);
                    <$full_ty as $crate::tlv::ValueEncoder>::encode(&self.$field_name, &mut buf[tag_length+length_len..]);

                )*
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
        tlv_struct!(@parse_attrs
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
        tlv_struct!(@parse_attrs
            tag_type: [ u8 ],
            length: [ $crate::tlv::U8Length ],
            impl_lt: [ 'a ], // Trait uses a synthetic generated lifetime
            struct_lt: [],   // Struct has no lifetime
            retained: [],
            input: [ $(#[$($attr)*])* $vis struct $name { $($fields)* } ]
        );
    };
}
pub(crate) use tlv_struct;

#[cfg(test)]
mod test {
    use super::*;

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
        tlv_struct! {
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
        tlv_struct! {
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
        tlv_struct! {
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
        tlv_struct! {
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
