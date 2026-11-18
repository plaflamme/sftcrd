/// Declarative macro to generate a struct and corresponding [`crate::ValueDecoder`] /
/// [`crate::ValueEncoder`] implementations (or [`crate::HeaderListDecoder`] /
/// [`crate::HeaderListEncoder`] when marked with `#[header_list]`).
///
/// # Examples
///
/// Basic TLV struct using the default [`crate::U8Tag`] and [`crate::U8Length`],
/// with required and optional fields:
///
/// ```
/// use sftcrd_tlv::tlv_struct;
///
/// tlv_struct! {
///     #[derive(Debug, PartialEq)]
///     struct Packet {
///         #[tag(0x01)]
///         version: u8,
///         #[tag(0x02)]
///         opt: Option<u16>,
///     }
/// }
/// ```
///
/// Custom tag/length encodings (`#[tag_type]` and `#[length]`), borrowed slices,
/// and repeated tags (`#[tag(..., repeated)]`):
///
/// ```
/// use sftcrd_tlv::{BerLength, BerTag, tlv_struct};
///
/// tlv_struct! {
///     #[derive(Debug, PartialEq)]
///     #[tag_type(BerTag)]
///     #[length(BerLength)]
///     struct Packet<'a> {
///         #[tag(0x4F)]
///         aid: &'a [u8],
///         #[tag(0x5F52)]
///         historical: Option<&'a [u8]>,
///         #[tag(0xC1, repeated)]
///         algs: Vec<&'a [u8]>,
///     }
/// }
/// ```
///
/// Paired ISO/IEC 7816-4 header list (`#[header_list]` on the inner struct,
/// `#[header_list(tpl_tag, val_tag)]` on the enclosing struct's field):
///
/// ```
/// use sftcrd_tlv::{BerLength, BerTag, tlv_struct};
///
/// tlv_struct! {
///     #[derive(Debug, PartialEq)]
///     #[tag_type(BerTag)]
///     #[length(BerLength)]
///     #[header_list]
///     struct KeyFields<'a> {
///         #[tag(0x91)]
///         exp: &'a [u8],
///         #[tag(0x92)]
///         prime: &'a [u8],
///     }
/// }
///
/// tlv_struct! {
///     #[derive(Debug, PartialEq)]
///     #[tag_type(BerTag)]
///     #[length(BerLength)]
///     struct ExtendedHeaderList<'a> {
///         #[tag(0xB6)]
///         crt: &'a [u8],
///         #[header_list(0x7F48, 0x5F48)]
///         fields: KeyFields<'a>,
///     }
/// }
/// ```
#[macro_export]
macro_rules! tlv_struct {
    // Struct WITH a lifetime parameter (e.g. `struct Foo<'a>`)
    (
        $(#[$($attr:tt)*])*
        $vis:vis struct $name:ident <$lt:lifetime> {
            $($fields:tt)*
        }
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $crate::U8Tag ],
            length: [ $crate::U8Length ],
            mode: [ tlv ],
            impl_lt: [ $lt ],
            struct_lt: [ $lt ],
            retained: [],
            input: [ $(#[$($attr)*])* $vis struct $name <$lt> { $($fields)* } ]
        );
    };

    // Struct WITHOUT a lifetime parameter
    (
        $(#[$($attr:tt)*])*
        $vis:vis struct $name:ident {
            $($fields:tt)*
        }
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $crate::U8Tag ],
            length: [ $crate::U8Length ],
            mode: [ tlv ],
            impl_lt: [ 'a ],
            struct_lt: [],
            retained: [],
            input: [ $(#[$($attr)*])* $vis struct $name { $($fields)* } ]
        );
    };
}

/// Internal helper: munches struct attributes (`#[tag_type]`, `#[length]`, `#[header_list]`).
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_parse_attrs {
    (
        tag_type: [ $($tag_ty:tt)* ],
        length: [ $($len:tt)* ],
        mode: [ $mode:ident ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ #[length($len_ty:ty)] $($rest:tt)* ]
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $($tag_ty)* ],
            length: [ $len_ty ],
            mode: [ $mode ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            retained: [ $($retained)* ],
            input: [ $($rest)* ]
        );
    };

    (
        tag_type: [ $($tag_ty:tt)* ],
        length: [ $($len:tt)* ],
        mode: [ $mode:ident ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ #[tag_type($new_tag_ty:path)] $($rest:tt)* ]
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $new_tag_ty ],
            length: [ $($len)* ],
            mode: [ $mode ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            retained: [ $($retained)* ],
            input: [ $($rest)* ]
        );
    };

    (
        tag_type: [ $($tag_ty:tt)* ],
        length: [ $($len:tt)* ],
        mode: [ $mode:ident ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ #[header_list] $($rest:tt)* ]
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $($tag_ty)* ],
            length: [ $($len)* ],
            mode: [ header_list ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            retained: [ $($retained)* ],
            input: [ $($rest)* ]
        );
    };

    (
        tag_type: [ $($tag_ty:tt)* ],
        length: [ $($len:tt)* ],
        mode: [ $mode:ident ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ #[$($attr:tt)*] $($rest:tt)* ]
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $($tag_ty)* ],
            length: [ $($len)* ],
            mode: [ $mode ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            retained: [ $($retained)* #[$($attr)*] ],
            input: [ $($rest)* ]
        );
    };

    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        mode: [ $mode:ident ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ $vis:vis struct $name:ident $(<$ignore_lt:lifetime>)? { $($fields:tt)* } ]
    ) => {
        $crate::__tlv_parse_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            mode: [ $mode ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            header: [ $($retained)* $vis struct $name $(<$struct_lt>)? ],
            tlv_fields: [],
            hl_fields: [],
            remaining: [ $($fields)* ]
        );
    };
}

/// Internal helper: munches struct fields, separating normal TLV fields from header-list fields.
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_parse_fields {
    // Repeated TLV field (`Vec<T>`)
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        mode: [ $mode:ident ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        tlv_fields: [ $($tlv:tt)* ],
        hl_fields: [ $($hl:tt)* ],
        remaining: [
            #[tag($tag:expr, repeated)]
            $(#[$field_meta:meta])*
            $field_vis:vis $field_name:ident : Vec < $inner_ty:ty >
            $(, $($rest:tt)*)?
        ]
    ) => {
        $crate::__tlv_parse_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            mode: [ $mode ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            header: [ $($header)* ],
            tlv_fields: [
                $($tlv)*
                (rep, $tag, [ $(#[$field_meta])* ], $field_vis, $field_name, Vec<$inner_ty>, $inner_ty)
            ],
            hl_fields: [ $($hl)* ],
            remaining: [ $($($rest)*)? ]
        );
    };

    // Paired header-list field (`#[header_list(tpl_tag, val_tag)]`)
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        mode: [ $mode:ident ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        tlv_fields: [ $($tlv:tt)* ],
        hl_fields: [ $($hl:tt)* ],
        remaining: [
            #[header_list($tpl_tag:expr, $val_tag:expr)]
            $(#[$field_meta:meta])*
            $field_vis:vis $field_name:ident : $field_ty:ty
            $(, $($rest:tt)*)?
        ]
    ) => {
        $crate::__tlv_parse_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            mode: [ $mode ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            header: [ $($header)* ],
            tlv_fields: [ $($tlv)* ],
            hl_fields: [
                $($hl)*
                ($tpl_tag, $val_tag, [ $(#[$field_meta])* ], $field_vis, $field_name, $field_ty)
            ],
            remaining: [ $($($rest)*)? ]
        );
    };

    // Optional TLV field (`Option<T>`)
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        mode: [ $mode:ident ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        tlv_fields: [ $($tlv:tt)* ],
        hl_fields: [ $($hl:tt)* ],
        remaining: [
            #[tag($tag:expr)]
            $(#[$field_meta:meta])*
            $field_vis:vis $field_name:ident : Option < $inner_ty:ty >
            $(, $($rest:tt)*)?
        ]
    ) => {
        $crate::__tlv_parse_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            mode: [ $mode ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            header: [ $($header)* ],
            tlv_fields: [
                $($tlv)*
                (opt, $tag, [ $(#[$field_meta])* ], $field_vis, $field_name, Option<$inner_ty>, $inner_ty)
            ],
            hl_fields: [ $($hl)* ],
            remaining: [ $($($rest)*)? ]
        );
    };

    // Required TLV field (`T`)
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        mode: [ $mode:ident ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        tlv_fields: [ $($tlv:tt)* ],
        hl_fields: [ $($hl:tt)* ],
        remaining: [
            #[tag($tag:expr)]
            $(#[$field_meta:meta])*
            $field_vis:vis $field_name:ident : $field_ty:ty
            $(, $($rest:tt)*)?
        ]
    ) => {
        $crate::__tlv_parse_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            mode: [ $mode ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            header: [ $($header)* ],
            tlv_fields: [
                $($tlv)*
                (req, $tag, [ $(#[$field_meta])* ], $field_vis, $field_name, $field_ty, $field_ty)
            ],
            hl_fields: [ $($hl)* ],
            remaining: [ $($($rest)*)? ]
        );
    };

    // Base Case: emit struct definition and dispatch to the selected codec generator
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        mode: [ $mode:ident ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        header: [ $(#[$meta:meta])* $vis:vis struct $name:ident $(<$lt_header:lifetime>)? ],
        tlv_fields: [
            $( ( $kind:ident, $tag:expr, [ $(#[$tlv_meta:meta])* ], $tlv_vis:vis, $tlv_name:ident, $tlv_full_ty:ty, $tlv_parse_ty:ty ) )*
        ],
        hl_fields: [
            $( ( $tpl_tag:expr, $val_tag:expr, [ $(#[$hl_meta:meta])* ], $hl_vis:vis, $hl_name:ident, $hl_ty:ty ) )*
        ],
        remaining: []
    ) => {
        $(#[$meta])*
        $vis struct $name $(<$struct_lt>)? {
            $(
                $(#[$tlv_meta])*
                $tlv_vis $tlv_name : $tlv_full_ty,
            )*
            $(
                $(#[$hl_meta])*
                $hl_vis $hl_name : $hl_ty,
            )*
        }

        $crate::__tlv_emit_impls!(
            mode: [ $mode ],
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            name: [ $name ],
            tlv_fields: [ $( ( $kind, $tag, $tlv_name, $tlv_parse_ty ) )* ],
            hl_fields: [ $( ( $tpl_tag, $val_tag, $hl_name, $hl_ty ) )* ]
        );
    };
}

/// Internal helper: dispatches to `__tlv_impl_codec!` or `__tlv_impl_header_list!`.
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_emit_impls {
    (
        mode: [ tlv ],
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        name: [ $name:ident ],
        tlv_fields: [ $($tlv:tt)* ],
        hl_fields: [ $($hl:tt)* ]
    ) => {
        $crate::__tlv_impl_codec!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            name: [ $name ],
            tlv_fields: [ $($tlv)* ],
            hl_fields: [ $($hl)* ]
        );
    };

    (
        mode: [ header_list ],
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        name: [ $name:ident ],
        tlv_fields: [ $($tlv:tt)* ],
        hl_fields: []
    ) => {
        $crate::__tlv_impl_header_list!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            name: [ $name ],
            tlv_fields: [ $($tlv)* ]
        );
    };
}

/// Internal helper: implements `ValueDecoder` and `ValueEncoder` for `tlv_struct!`.
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_impl_codec {
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        name: [ $name:ident ],
        tlv_fields: [ $( ( $kind:ident, $tag:expr, $tlv_name:ident, $tlv_ty:ty ) )* ],
        hl_fields: [ $( ( $tpl_tag:expr, $val_tag:expr, $hl_name:ident, $hl_ty:ty ) )* ]
    ) => {
        impl <$impl_lt> $crate::ValueDecoder<$impl_lt> for $name $(<$struct_lt>)? {
            fn decode(input: &$impl_lt [u8]) -> Result<Self, $crate::DecodeError> {
                $( $crate::__tlv_field!(@init $kind, $tlv_name, $tlv_ty); )*
                $(
                    let mut $hl_name: (Option<&$impl_lt [u8]>, Option<&$impl_lt [u8]>) =
                        (None, None);
                )*

                for entry in $crate::Decoder::new(input).into_iter_tags::<$tag_ty, $len_ty>() {
                    let (tag, value_bytes) = entry?;
                    match tag {
                        $(
                            $tag_ty($tag) => {
                                $crate::__tlv_field!(@decode $kind, $tlv_name, $tlv_ty, value_bytes);
                            }
                        )*
                        $(
                            $tag_ty($tpl_tag) => {
                                if $hl_name.0.is_some() {
                                    return Err($crate::DecodeError::DuplicateTag);
                                }
                                $hl_name.0 = Some(value_bytes);
                            }
                            $tag_ty($val_tag) => {
                                if $hl_name.1.is_some() {
                                    return Err($crate::DecodeError::DuplicateTag);
                                }
                                $hl_name.1 = Some(value_bytes);
                            }
                        )*
                        _ => return Err($crate::DecodeError::InvalidTag),
                    }
                }

                Ok(Self {
                    $( $tlv_name: $crate::__tlv_field!(@unwrap $kind, $tlv_name), )*
                    $(
                        $hl_name: {
                            let (tpl, vals) = $hl_name;
                            let tpl = tpl.ok_or($crate::DecodeError::MissingRequiredField)?;
                            let vals = vals.ok_or($crate::DecodeError::MissingRequiredField)?;
                            <$hl_ty as $crate::HeaderListDecoder>::decode_header_list(tpl, vals)?
                        },
                    )*
                })
            }
        }

        impl <$impl_lt> $crate::ValueEncoder for $name $(<$struct_lt>)? {
            fn length(&self) -> usize {
                let mut length = 0;
                $(
                    for value in $crate::__tlv_field!(@as_slice $kind, &self.$tlv_name) {
                        let value_len = <$tlv_ty as $crate::ValueEncoder>::length(value);
                        let length_len = <$len_ty as $crate::Length>::length(value_len) as usize;
                        let tag_length = $crate::Tag::length(&$tag_ty($tag));
                        length += tag_length + length_len + value_len;
                    }
                )*
                $(
                    let (tpl_len, val_len) =
                        <$hl_ty as $crate::HeaderListEncoder>::header_list_lengths(&self.$hl_name);
                    length += $crate::Tag::length(&$tag_ty($tpl_tag))
                        + <$len_ty as $crate::Length>::length(tpl_len) as usize
                        + tpl_len
                        + $crate::Tag::length(&$tag_ty($val_tag))
                        + <$len_ty as $crate::Length>::length(val_len) as usize
                        + val_len;
                )*
                length
            }

            fn encode(&self, buf: &mut [u8]) -> Result<(), $crate::EncodeError> {
                let mut encoder = $crate::Encoder::new(buf);
                $(
                    for value in $crate::__tlv_field!(@as_slice $kind, &self.$tlv_name) {
                        encoder.write_tlv::<$tag_ty, $len_ty, $tlv_ty>(&$tag_ty($tag), value)?;
                    }
                )*
                $(
                    let (tpl, vals) =
                        <$hl_ty as $crate::HeaderListEncoder>::encode_header_list(&self.$hl_name)?;
                    encoder.write_tlv::<$tag_ty, $len_ty, Vec<u8>>(&$tag_ty($tpl_tag), &tpl)?;
                    encoder.write_tlv::<$tag_ty, $len_ty, Vec<u8>>(&$tag_ty($val_tag), &vals)?;
                )*
                Ok(())
            }
        }
    };
}

/// Internal helper: implements `HeaderListDecoder` and `HeaderListEncoder` for
/// structs tagged with `#[header_list]`.
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_impl_header_list {
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        name: [ $name:ident ],
        tlv_fields: [ $( ( $kind:ident, $tag:expr, $tlv_name:ident, $tlv_ty:ty ) )* ]
    ) => {
        impl <$impl_lt> $crate::HeaderListDecoder<$impl_lt> for $name $(<$struct_lt>)? {
            fn decode_header_list(
                template: &$impl_lt [u8],
                values: &$impl_lt [u8],
            ) -> Result<Self, $crate::DecodeError> {
                $( $crate::__tlv_field!(@init $kind, $tlv_name, $tlv_ty); )*

                for entry in $crate::decode_header_list::<$tag_ty, $len_ty>(template, values) {
                    let (tag, value_bytes) = entry?;
                    match tag {
                        $(
                            $tag_ty($tag) => {
                                $crate::__tlv_field!(@decode $kind, $tlv_name, $tlv_ty, value_bytes);
                            }
                        )*
                        _ => return Err($crate::DecodeError::InvalidTag),
                    }
                }

                Ok(Self {
                    $( $tlv_name: $crate::__tlv_field!(@unwrap $kind, $tlv_name), )*
                })
            }
        }

        impl <$impl_lt> $crate::HeaderListEncoder for $name $(<$struct_lt>)? {
            fn header_list_lengths(&self) -> (usize, usize) {
                let mut tpl_len = 0;
                let mut val_len = 0;
                $(
                    for value in $crate::__tlv_field!(@as_slice $kind, &self.$tlv_name) {
                        let v_len = <$tlv_ty as $crate::ValueEncoder>::length(value);
                        let l_len = <$len_ty as $crate::Length>::length(v_len) as usize;
                        let t_len = $crate::Tag::length(&$tag_ty($tag));
                        tpl_len += t_len + l_len;
                        val_len += v_len;
                    }
                )*
                (tpl_len, val_len)
            }

            fn encode_header_list(&self) -> Result<(Vec<u8>, Vec<u8>), $crate::EncodeError> {
                let (tpl_len, val_len) = self.header_list_lengths();
                let mut template = vec![0u8; tpl_len];
                let mut values = vec![0u8; val_len];
                let mut tpl_enc = $crate::Encoder::new(&mut template);
                let mut val_enc = $crate::Encoder::new(&mut values);
                $(
                    for value in $crate::__tlv_field!(@as_slice $kind, &self.$tlv_name) {
                        let v_len = <$tlv_ty as $crate::ValueEncoder>::length(value);
                        tpl_enc.write_tag_length::<$tag_ty, $len_ty>(&$tag_ty($tag), v_len)?;
                        val_enc.write_value::<$tlv_ty>(value)?;
                    }
                )*
                Ok((template, values))
            }
        }
    };
}

/// Internal helper for per-field `req` / `opt` / `rep` operations.
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_field {
    (@init rep, $field_name:ident, $parse_ty:ty) => {
        let mut $field_name: Vec<$parse_ty> = Vec::new();
    };
    (@init $kind:ident, $field_name:ident, $parse_ty:ty) => {
        let mut $field_name: Option<$parse_ty> = None;
    };

    (@decode rep, $field_name:ident, $parse_ty:ty, $value_bytes:ident) => {
        $field_name.push(<$parse_ty as $crate::ValueDecoder>::decode($value_bytes)?);
    };
    (@decode $kind:ident, $field_name:ident, $parse_ty:ty, $value_bytes:ident) => {
        if $field_name.is_some() {
            return Err($crate::DecodeError::DuplicateTag);
        }
        $field_name = Some(<$parse_ty as $crate::ValueDecoder>::decode($value_bytes)?);
    };

    (@unwrap req, $field_name:ident) => {
        $field_name.ok_or($crate::DecodeError::MissingRequiredField)?
    };
    (@unwrap opt, $field_name:ident) => {
        $field_name
    };
    (@unwrap rep, $field_name:ident) => {
        $field_name
    };

    (@as_slice req, $field:expr) => {
        core::slice::from_ref($field)
    };
    (@as_slice opt, $field:expr) => {
        $field.as_slice()
    };
    (@as_slice rep, $field:expr) => {
        $field.as_slice()
    };
}

#[cfg(test)]
mod tests {
    use crate::{
        BerLength, BerTag, DecodeError, HeaderListDecoder, HeaderListEncoder, U16Tag, ValueDecoder,
        ValueEncoder,
    };

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
    fn test_tlv_struct_repeated() {
        tlv_struct! {
            #[derive(Debug, PartialEq)]
            #[tag_type(BerTag)]
            #[length(BerLength)]
            struct RepeatedPacket {
                #[tag(0xC1, repeated)]
                sig: Vec<Vec<u8>>,
                #[tag(0xC2, repeated)]
                dec: Vec<u16>,
            }
        }

        let packet = RepeatedPacket {
            sig: vec![vec![0xAA], vec![0xBB, 0xCC]],
            dec: vec![0x0102, 0x0304],
        };
        let encoded = packet.encode_top_level().unwrap();
        assert_eq!(
            encoded,
            [
                0xC1, 0x01, 0xAA, 0xC1, 0x02, 0xBB, 0xCC, 0xC2, 0x02, 0x01, 0x02, 0xC2, 0x02, 0x03,
                0x04
            ]
        );
        assert_eq!(RepeatedPacket::decode(&encoded), Ok(packet));
        assert_eq!(
            RepeatedPacket::decode(&[]),
            Ok(RepeatedPacket {
                sig: Vec::new(),
                dec: Vec::new(),
            })
        );
    }

    #[test]
    fn test_tlv_struct_header_list() {
        tlv_struct! {
            #[derive(Debug, PartialEq)]
            #[tag_type(BerTag)]
            #[length(BerLength)]
            #[header_list]
            struct KeyHeaderList<'a> {
                #[tag(0x91)]
                e: &'a [u8],
                #[tag(0x92)]
                p: &'a [u8],
                #[tag(0x97)]
                n: Option<&'a [u8]>,
            }
        }

        tlv_struct! {
            #[derive(Debug, PartialEq)]
            #[tag_type(BerTag)]
            #[length(BerLength)]
            struct OuterHeaderList<'a> {
                #[tag(0xB6)]
                crt: &'a [u8],
                #[header_list(0x7F48, 0x5F48)]
                key: KeyHeaderList<'a>,
            }
        }

        let outer = OuterHeaderList {
            crt: &[],
            key: KeyHeaderList {
                e: &[0x01, 0x00, 0x01],
                p: &[0xAA; 128],
                n: None,
            },
        };
        let encoded = outer.encode_top_level().unwrap();
        let mut expected_vals = vec![0x01, 0x00, 0x01];
        expected_vals.extend_from_slice(&[0xAA; 128]);
        let mut expected_encoded = vec![
            0xB6, 0x00, // crt
            0x7F, 0x48, 0x05, 0x91, 0x03, 0x92, 0x81, 0x80, // template
            0x5F, 0x48, 0x81, 0x83, // values header (3 + 128 = 131 = 0x83)
        ];
        expected_encoded.extend_from_slice(&expected_vals);
        assert_eq!(outer.length(), expected_encoded.len());
        assert_eq!(encoded, expected_encoded);
        assert_eq!(OuterHeaderList::decode(&encoded), Ok(outer));

        // Direct HeaderListDecoder / HeaderListEncoder
        let (tpl, vals) = KeyHeaderList {
            e: &[0x01, 0x00, 0x01],
            p: &[0xAA; 128],
            n: None,
        }
        .encode_header_list()
        .unwrap();
        assert_eq!(tpl, [0x91, 0x03, 0x92, 0x81, 0x80]);
        assert_eq!(vals, expected_vals);

        let mut extra = vals.clone();
        extra.push(0x00);
        assert_eq!(
            KeyHeaderList::decode_header_list(&tpl, &extra),
            Err(DecodeError::InvalidLength)
        );
        assert_eq!(
            KeyHeaderList::decode_header_list(&tpl, &vals[..10]),
            Err(DecodeError::BufferUnderrun)
        );
        assert_eq!(
            KeyHeaderList::decode_header_list(&[0x99, 0x01], &[0x00]),
            Err(DecodeError::InvalidTag)
        );
        assert_eq!(
            KeyHeaderList::decode_header_list(&[0x91, 0x01], &[0x03]),
            Err(DecodeError::MissingRequiredField)
        );
    }
}
