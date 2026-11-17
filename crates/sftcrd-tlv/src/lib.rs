mod decoder;
mod encoder;
mod error;
mod length;
mod tag;
mod value;

pub use decoder::Decoder;
pub use encoder::{Encoder, encode_sequence};
pub use error::{DecodeError, EncodeError};
pub use length::{BerLength, Length, U8Length};
pub use tag::{BerTag, Tag, U8Tag, U16Tag};
pub use value::{ConstLength, ValueDecoder, ValueEncoder};

/// Declarative macro to generate a struct and a corresponding [`ValueDecoder`] and [`ValueEncoder`] implementations to decode/encode it out of/to TLV bytes.
#[macro_export]
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
        input: [ #[tag_type($new_tag_ty:path)] $($rest:tt)* ]
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
        tag_type: [ $tag_ty:path ],
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
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        parsed: [ $($parsed:tt)* ],
        remaining: [
            #[tag($tag:expr)]
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
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        parsed: [ $($parsed:tt)* ],
        remaining: [
            #[tag($tag:expr)]
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
        tag_type: [ $tag_ty:path ],
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
        impl <$impl_lt> $crate::ValueDecoder<$impl_lt> for $name $(<$struct_lt>)? {
            fn decode(input: &$impl_lt [u8]) -> Result<Self, $crate::DecodeError> {
                $( let mut $field_name: Option<$parse_ty> = None; )*

                for entry in $crate::Decoder::new(input).into_iter_tags::<$tag_ty, $len_ty>() {
                    let (tag, value_bytes) = entry?;
                    match tag {
                        $(
                            $tag_ty($tag) => {
                                if $field_name.is_some() {
                                    return Err($crate::DecodeError::DuplicateTag);
                                }
                                let val = <$parse_ty as $crate::ValueDecoder>::decode(value_bytes)?;
                                $field_name = Some(val);
                            }
                        )*
                        _ => return Err($crate::DecodeError::InvalidTag),
                    }
                }

                Ok(Self {
                    $( $field_name: tlv_struct!(@unwrap_field $kind, $field_name), )*
                })
            }
        }

        impl <$impl_lt> $crate::ValueEncoder for $name $(<$struct_lt>)? {
            fn length(&self) -> usize {
                let mut length = 0;
                $(
                    let value = &self.$field_name;
                    match tlv_struct!(@wrap_field $kind, value) {
                        None => (),
                        Some(value) => {
                            let value_len = <$parse_ty as $crate::ValueEncoder>::length(value);
                            let length_len = <$len_ty as $crate::Length>::length(value_len) as usize;
                            let tag_length = $crate::Tag::length(&$tag_ty($tag));
                            length += tag_length + length_len + value_len;
                        },
                    };
                )*
                length
            }

            fn encode(&self, buf: &mut [u8]) -> Result<(), $crate::EncodeError> {
                let mut encoder = $crate::Encoder::new(buf);
                $(
                    let value = &self.$field_name;
                    match tlv_struct!(@wrap_field $kind, value) {
                        None => (),
                        Some(value) => encoder.write_tlv::<$tag_ty, $len_ty, $parse_ty>(&$tag_ty($tag), value)?,
                    };
                )*
                Ok(())
            }
        }
    };

    (@unwrap_field req, $field_name:ident) => {
        $field_name.ok_or($crate::DecodeError::MissingRequiredField)?
    };
    (@unwrap_field opt, $field_name:ident) => {
        $field_name
    };

    (@wrap_field req, $field:expr) => {
        Some($field)
    };
    (@wrap_field opt, $field:expr) => {
        $field
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
            tag_type: [ $crate::U8Tag ],
            length: [ $crate::U8Length ],
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
            tag_type: [ $crate::U8Tag ],
            length: [ $crate::U8Length ],
            impl_lt: [ 'a ], // Trait uses a synthetic generated lifetime
            struct_lt: [],   // Struct has no lifetime
            retained: [],
            input: [ $(#[$($attr)*])* $vis struct $name { $($fields)* } ]
        );
    };
}

#[cfg(test)]
mod tests {
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
    fn test_tlv_struct_default() {
        tlv_struct! {
            #[derive(Debug, PartialEq)]
            pub struct Packet {
                #[tag(0x01)]
                pub version: u8,
                #[tag(0x02)]
                pub payload_len: u16,
                #[tag(0x03)]
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

        // encode
        assert_eq!(
            Packet {
                version: 0xFF,
                payload_len: 0xFFFE,
                opt: None
            }
            .encode_top_level(),
            Ok(vec![0x01, 0x01, 0xFF, 0x02, 0x02, 0xFF, 0xFE])
        );
        assert_eq!(
            Packet {
                version: 0xFF,
                payload_len: 0xFFFE,
                opt: Some(0xFDFC)
            }
            .encode_top_level(),
            Ok(vec![
                0x01, 0x01, 0xFF, 0x02, 0x02, 0xFF, 0xFE, 0x03, 0x02, 0xFD, 0xFC
            ])
        );
    }

    #[test]
    fn test_tlv_struct_tag_type() {
        tlv_struct! {
            #[derive(Debug, PartialEq)]
            #[tag_type(U16Tag)]
            pub struct Packet {
                #[tag(0x0101)]
                pub version: u8,
                #[tag(0x0102)]
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
        assert_eq!(
            Packet {
                version: 0xFF,
                payload_len: 0xFE,
            }
            .encode_top_level(),
            Ok(vec![0x01, 0x01, 0x01, 0xFF, 0x01, 0x02, 0x01, 0xFE])
        );
    }

    #[test]
    fn test_tlv_struct_ber_tag() {
        tlv_struct! {
            #[derive(Debug, PartialEq)]
            #[tag_type(BerTag)]
            #[length(BerLength)]
            pub struct Packet<'a> {
                #[tag(0x4F)]
                pub aid: &'a [u8],
                #[tag(0x5F52)]
                pub historical: Option<&'a [u8]>,
                #[tag(0x7F49)]
                pub key: Option<Vec<u8>>,
                #[tag(0xC5)]
                pub fingerprints: Option<&'a [u8]>,
            }
        }

        let bytes = [
            0x4F, 0x02, 0xD2, 0x76, // 4F
            0x5F, 0x52, 0x01, 0x00, // 5F52
            0x7F, 0x49, 0x81, 0x02, 0x86, 0x00, // 7F49 with BER length
            0xC5, 0x01, 0xAA, // C5
        ];
        let packet = Packet {
            aid: &[0xD2, 0x76],
            historical: Some(&[0x00]),
            key: Some(vec![0x86, 0x00]),
            fingerprints: Some(&[0xAA]),
        };
        assert_eq!(Packet::decode(&bytes), Ok(packet));

        // decoding in a different order works
        assert_eq!(
            Packet::decode(&[0x5F, 0x52, 0x01, 0x00, 0x4F, 0x01, 0xD2]),
            Ok(Packet {
                aid: &[0xD2],
                historical: Some(&[0x00]),
                key: None,
                fingerprints: None,
            })
        );

        // encode uses minimal tag width and lengths
        let packet = Packet {
            aid: &[0xD2, 0x76],
            historical: Some(&[0x00]),
            key: Some(vec![0x86, 0x00]),
            fingerprints: Some(&[0xAA]),
        };
        assert_eq!(packet.length(), 16);
        assert_eq!(
            packet.encode_top_level(),
            Ok(vec![
                0x4F, 0x02, 0xD2, 0x76, 0x5F, 0x52, 0x01, 0x00, 0x7F, 0x49, 0x02, 0x86, 0x00, 0xC5,
                0x01, 0xAA,
            ])
        );

        // unknown 2-byte tag
        assert_eq!(
            Packet::decode(&[0x4F, 0x00, 0x5F, 0x2D, 0x00]),
            Err(DecodeError::InvalidTag)
        );
        // duplicate 2-byte tag
        assert_eq!(
            Packet::decode(&[0x4F, 0x00, 0x5F, 0x52, 0x00, 0x5F, 0x52, 0x00]),
            Err(DecodeError::DuplicateTag)
        );
        // truncated multi-byte tag
        assert_eq!(
            Packet::decode(&[0x4F, 0x00, 0x5F]),
            Err(DecodeError::BufferUnderrun)
        );
    }

    #[test]
    fn test_tlv_struct_length() {
        tlv_struct! {
            #[derive(Debug, PartialEq)]
            #[length(BerLength)]
            pub struct Packet {
                #[tag(0x01)]
                pub version: u8,
                #[tag(0x02)]
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
    fn test_tlv_struct_lifetime() {
        tlv_struct! {
            #[derive(Debug, PartialEq)]
            #[length(BerLength)]
            pub struct Packet<'a> {
                #[tag(0x01)]
                pub version: u8,
                #[tag(0x02)]
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

    #[test]
    fn test_fixed_array_and_u32_codec() {
        let arr: [[u8; 2]; 3] = [[0x01, 0x02], [0x03, 0x04], [0x05, 0x06]];
        let encoded = arr.encode_top_level().unwrap();
        assert_eq!(encoded, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(<[[u8; 2]; 3]>::decode(&encoded), Ok(arr));
        assert_eq!(
            <[[u8; 2]; 3]>::decode(&[0x01, 0x02, 0x03]),
            Err(DecodeError::BufferUnderrun)
        );
        assert_eq!(
            <[[u8; 2]; 3]>::decode(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]),
            Err(DecodeError::InvalidValue)
        );

        let nums: [u32; 2] = [0x0102_0304, 0xAABB_CCDD];
        let encoded_nums = nums.encode_top_level().unwrap();
        assert_eq!(
            encoded_nums,
            [0x01, 0x02, 0x03, 0x04, 0xAA, 0xBB, 0xCC, 0xDD]
        );
        assert_eq!(<[u32; 2]>::decode(&encoded_nums), Ok(nums));
    }
}
