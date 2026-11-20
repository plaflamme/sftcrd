/// Declarative macro to generate a struct and corresponding [`crate::Decode`] /
/// [`crate::Encode`] implementations.
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
/// Paired ISO/IEC 7816-4 header list (`#[header_list(tpl_tag, val_tag)]` on the
/// enclosing struct's field):
///
/// ```
/// use sftcrd_tlv::{BerLength, BerTag, tlv_struct};
///
/// tlv_struct! {
///     #[derive(Debug, PartialEq)]
///     #[tag_type(BerTag)]
///     #[length(BerLength)]
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
            impl_lt: [ 'a ],
            struct_lt: [],
            retained: [],
            input: [ $(#[$($attr)*])* $vis struct $name { $($fields)* } ]
        );
    };
}

/// Internal helper: munches struct attributes (`#[tag_type]`, `#[length]`).
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_parse_attrs {
    (
        tag_type: [ $($tag_ty:tt)* ],
        length: [ $($len:tt)* ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ #[length($len_ty:ty)] $($rest:tt)* ]
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $($tag_ty)* ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            retained: [ $($retained)* ],
            input: [ $($rest)* ]
        );
    };

    (
        tag_type: [ $($tag_ty:tt)* ],
        length: [ $($len:tt)* ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ #[tag_type($new_tag_ty:path)] $($rest:tt)* ]
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $new_tag_ty ],
            length: [ $($len)* ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            retained: [ $($retained)* ],
            input: [ $($rest)* ]
        );
    };

    (
        tag_type: [ $($tag_ty:tt)* ],
        length: [ $($len:tt)* ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ #[$($attr:tt)*] $($rest:tt)* ]
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $($tag_ty)* ],
            length: [ $($len)* ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            retained: [ $($retained)* #[$($attr)*] ],
            input: [ $($rest)* ]
        );
    };

    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($struct_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ $vis:vis struct $name:ident $(<$ignore_lt:lifetime>)? { $($fields:tt)* } ]
    ) => {
        $crate::__tlv_parse_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            struct_lt: [ $($struct_lt)? ],
            header: [ $($retained)* $vis struct $name $(<$struct_lt>)? ],
            tlv_fields: [],
            hl_fields: [],
            remaining: [ $($fields)* ]
        );
    };

    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        struct_lt: [ $($enum_lt:lifetime)? ],
        retained: [ $($retained:tt)* ],
        input: [ $vis:vis enum $name:ident $(<$ignore_lt:lifetime>)? { $($variants:tt)* } ]
    ) => {
        $crate::__tlv_enum_parse_variants!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            enum_lt: [ $($enum_lt)? ],
            header: [ $($retained)* $vis enum $name $(<$enum_lt>)? ],
            name: [ $name ],
            variant_defs: [],
            decode_variants: [],
            remaining: [ $($variants)* ]
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

    // Base Case: emit struct definition and codec implementations
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
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

        $crate::__tlv_impl_codec!(
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

/// Internal helper: decodes a set of TLV and header-list fields from `$decoder` into `$ctor { ... }`.
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_decode_fields {
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        decoder: $decoder:ident,
        ctor: [ $($ctor:tt)+ ],
        tlv_fields: [ $( ( $kind:ident, $tag:expr, $tlv_name:ident, $tlv_ty:ty ) )* ],
        hl_fields: [ $( ( $tpl_tag:expr, $val_tag:expr, $hl_name:ident, $hl_ty:ty ) )* ]
    ) => {{
        $( $crate::__tlv_field!(@init $kind, $tlv_name, $tlv_ty); )*
        $(
            let mut $hl_name: (Option<&$impl_lt [u8]>, Option<&$impl_lt [u8]>) =
                (None, None);
        )*

        for entry in $decoder.iter_tags::<$tag_ty, $len_ty>() {
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

        Ok($($ctor)+ {
            $( $tlv_name: $crate::__tlv_field!(@unwrap $kind, $tlv_name), )*
            $(
                $hl_name: {
                    let (tpl, vals) = $hl_name;
                    let tpl = tpl.ok_or($crate::DecodeError::MissingRequiredField)?;
                    let vals = vals.ok_or($crate::DecodeError::MissingRequiredField)?;
                    $crate::Decoder::decode_header_list::<$hl_ty>(tpl, vals)?
                },
            )*
        })
    }};
}

/// Internal helper: implements `Decode` and `Encode` for `tlv_struct!`.
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
        impl <$impl_lt> $crate::Decode<$impl_lt> for $name $(<$struct_lt>)? {
            fn decode(decoder: &$crate::Decoder<$impl_lt>) -> Result<Self, $crate::DecodeError> {
                $crate::__tlv_decode_fields!(
                    tag_type: [ $tag_ty ],
                    length: [ $len_ty ],
                    impl_lt: [ $impl_lt ],
                    decoder: decoder,
                    ctor: [ Self ],
                    tlv_fields: [ $( ( $kind, $tag, $tlv_name, $tlv_ty ) )* ],
                    hl_fields: [ $( ( $tpl_tag, $val_tag, $hl_name, $hl_ty ) )* ]
                )
            }
        }

        impl <$impl_lt> $crate::Encode for $name $(<$struct_lt>)? {
            fn encode(&self, encoder: &mut $crate::Encoder<'_>) -> Result<(), $crate::EncodeError> {
                $(
                    for value in $crate::__tlv_field!(@as_slice $kind, &self.$tlv_name) {
                        encoder.write_tlv::<$tag_ty, $len_ty, $tlv_ty>(&$tag_ty($tag), value)?;
                    }
                )*
                $(
                    encoder.write_header_list::<$tag_ty, $len_ty, $hl_ty>(
                        &$tag_ty($tpl_tag),
                        &$tag_ty($val_tag),
                        &self.$hl_name,
                    )?;
                )*
                Ok(())
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
        $field_name.push($crate::Decoder::decode_tlv::<$parse_ty>($value_bytes)?);
    };
    (@decode $kind:ident, $field_name:ident, $parse_ty:ty, $value_bytes:ident) => {
        if $field_name.is_some() {
            return Err($crate::DecodeError::DuplicateTag);
        }
        $field_name = Some($crate::Decoder::decode_tlv::<$parse_ty>($value_bytes)?);
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

/// Declarative macro to generate an enum and corresponding [`crate::Decode`] /
/// [`crate::Encode`] implementations for non-discriminated TLV unions.
///
/// # Variant forms
///
/// Both of the following variant forms are supported and may be freely mixed in
/// the same enum:
///
/// - **Tuple (newtype) variants** (`Variant(InnerTy)`): delegate directly to
///   `InnerTy`'s [`crate::Decode`] and [`crate::Encode`] implementations.
/// - **Inline struct variants** (`Variant { ... }`): support the same field
///   syntax and attributes as [`tlv_struct!`] (`#[tag(expr)]`,
///   `#[tag(expr, repeated)]`, `#[header_list(tpl_tag, val_tag)]`, `Option<T>`,
///   and `Vec<T>`).
///
/// # Attributes and lifetimes
///
/// - `#[tag_type(...)]` (default [`crate::U8Tag`]) and `#[length(...)]`
///   (default [`crate::U8Length`]) configure the wire format for inline struct
///   variants.
/// - An optional single lifetime parameter (`enum Name<'a>`) is supported for
///   zero-copy borrowed fields.
/// - Other attributes (such as `#[derive(...)]` and doc comments) are preserved
///   on the generated enum, variants, and fields.
///
/// # Decoding semantics
///
/// [`crate::Decode::decode`] attempts each variant in declaration order against
/// the same [`crate::Decoder`] and returns the first one that succeeds. If no
/// variant matches, it returns `Err(`[`crate::DecodeError::InvalidValue`]`)`.
///
/// Because each inline struct variant (and [`tlv_struct!`]) rejects unknown
/// tags and missing required fields, variants with disjoint required tags are
/// unambiguous. When variants have overlapping tag sets (for instance, one
/// variant only adds optional fields on top of another), list the more specific
/// variant first.
///
/// Both standard TLV streams ([`crate::Decode::decode_tlv`] /
/// [`crate::Encode::encode_tlv`]) and ISO/IEC 7816-4 header lists
/// ([`crate::Decode::decode_header_list`] /
/// [`crate::Encode::encode_header_list`]) are supported automatically.
///
/// # Examples
///
/// Inline struct variants with custom length encoding:
///
/// ```
/// use sftcrd_tlv::{BerLength, Decode, DecodeError, Encode, tlv_enum};
///
/// tlv_enum! {
///     #[derive(Debug, PartialEq)]
///     #[length(BerLength)]
///     enum Payload<'a> {
///         Single {
///             #[tag(0x86)]
///             data: &'a [u8],
///         },
///         Pair {
///             #[tag(0x81)]
///             first: &'a [u8],
///             #[tag(0x82)]
///             second: &'a [u8],
///         },
///     }
/// }
///
/// let pair = Payload::Pair { first: &[0xAA], second: &[0x01, 0x00, 0x01] };
/// let encoded = pair.encode_tlv().unwrap();
/// assert_eq!(Payload::decode_tlv(&encoded), Ok(pair));
/// assert_eq!(Payload::decode_tlv(&[0x99, 0x01, 0x00]), Err(DecodeError::InvalidValue));
/// ```
///
/// Mixing a tuple variant (wrapping a [`tlv_struct!`]) with an inline struct
/// variant, decoded from an ISO/IEC 7816-4 header list:
///
/// ```
/// use sftcrd_tlv::{BerLength, BerTag, Decode, Encode, tlv_enum, tlv_struct};
///
/// tlv_struct! {
///     #[derive(Debug, PartialEq)]
///     #[tag_type(BerTag)]
///     #[length(BerLength)]
///     struct FullRecord<'a> {
///         #[tag(0x91)]
///         a: &'a [u8],
///         #[tag(0x92)]
///         b: &'a [u8],
///         #[tag(0x93)]
///         c: &'a [u8],
///     }
/// }
///
/// tlv_enum! {
///     #[derive(Debug, PartialEq)]
///     #[tag_type(BerTag)]
///     #[length(BerLength)]
///     enum Record<'a> {
///         Full(FullRecord<'a>),
///         Compact {
///             #[tag(0x92)]
///             b: &'a [u8],
///             #[tag(0x99)]
///             extra: Option<&'a [u8]>,
///         },
///     }
/// }
///
/// let record = Record::Compact { b: &[0x11, 0x22], extra: None };
/// let (tpl, vals) = record.encode_header_list().unwrap();
/// assert_eq!(Record::decode_header_list(&tpl, &vals), Ok(record));
/// ```
#[macro_export]
macro_rules! tlv_enum {
    // Enum WITH a lifetime parameter (e.g. `enum Foo<'a>`)
    (
        $(#[$($attr:tt)*])*
        $vis:vis enum $name:ident <$lt:lifetime> {
            $($variants:tt)*
        }
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $crate::U8Tag ],
            length: [ $crate::U8Length ],
            impl_lt: [ $lt ],
            struct_lt: [ $lt ],
            retained: [],
            input: [ $(#[$($attr)*])* $vis enum $name <$lt> { $($variants)* } ]
        );
    };

    // Enum WITHOUT a lifetime parameter
    (
        $(#[$($attr:tt)*])*
        $vis:vis enum $name:ident {
            $($variants:tt)*
        }
    ) => {
        $crate::__tlv_parse_attrs!(
            tag_type: [ $crate::U8Tag ],
            length: [ $crate::U8Length ],
            impl_lt: [ 'a ],
            struct_lt: [],
            retained: [],
            input: [ $(#[$($attr)*])* $vis enum $name { $($variants)* } ]
        );
    };
}

/// Internal helper: munches enum variants for `tlv_enum!`.
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_enum_parse_variants {
    // Tuple variant: `Variant(InnerTy)`
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        enum_lt: [ $($enum_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        name: [ $name:ident ],
        variant_defs: [ $($defs:tt)* ],
        decode_variants: [ $($codec:tt)* ],
        remaining: [
            $(#[$v_meta:meta])*
            $v_name:ident ( $v_ty:ty )
            $(, $($rest:tt)*)?
        ]
    ) => {
        $crate::__tlv_enum_parse_variants!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            enum_lt: [ $($enum_lt)? ],
            header: [ $($header)* ],
            name: [ $name ],
            variant_defs: [
                $($defs)*
                $(#[$v_meta])*
                $v_name($v_ty),
            ],
            decode_variants: [
                $($codec)*
                (tuple, $v_name, $v_ty)
            ],
            remaining: [ $($($rest)*)? ]
        );
    };

    // Inline struct variant: `Variant { ... }`
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        enum_lt: [ $($enum_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        name: [ $name:ident ],
        variant_defs: [ $($defs:tt)* ],
        decode_variants: [ $($codec:tt)* ],
        remaining: [
            $(#[$v_meta:meta])*
            $v_name:ident { $($v_fields:tt)* }
            $(, $($rest:tt)*)?
        ]
    ) => {
        $crate::__tlv_enum_parse_struct_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            enum_lt: [ $($enum_lt)? ],
            header: [ $($header)* ],
            name: [ $name ],
            variant_defs: [ $($defs)* ],
            decode_variants: [ $($codec)* ],
            v_meta: [ $(#[$v_meta])* ],
            v_name: [ $v_name ],
            tlv_fields: [],
            hl_fields: [],
            v_remaining: [ $($v_fields)* ],
            rest_variants: [ $($($rest)*)? ]
        );
    };

    // Base case: emit enum definition and Decode/Encode impls
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        enum_lt: [ $($enum_lt:lifetime)? ],
        header: [ $(#[$meta:meta])* $vis:vis enum $name_header:ident $(<$lt_header:lifetime>)? ],
        name: [ $name:ident ],
        variant_defs: [ $($defs:tt)* ],
        decode_variants: [ $($codec:tt)* ],
        remaining: []
    ) => {
        $(#[$meta])*
        $vis enum $name $(<$enum_lt>)? {
            $($defs)*
        }

        impl <$impl_lt> $crate::Decode<$impl_lt> for $name $(<$enum_lt>)? {
            fn decode(decoder: &$crate::Decoder<$impl_lt>) -> Result<Self, $crate::DecodeError> {
                $crate::__tlv_enum_decode!(
                    tag_type: [ $tag_ty ],
                    length: [ $len_ty ],
                    impl_lt: [ $impl_lt ],
                    decoder: decoder,
                    remaining: [ $($codec)* ]
                )
            }
        }

        impl <$impl_lt> $crate::Encode for $name $(<$enum_lt>)? {
            fn encode(&self, encoder: &mut $crate::Encoder<'_>) -> Result<(), $crate::EncodeError> {
                $crate::__tlv_enum_encode!(
                    self: self,
                    encoder: encoder,
                    tag_type: [ $tag_ty ],
                    length: [ $len_ty ],
                    arms: [],
                    remaining: [ $($codec)* ]
                )
            }
        }
    };
}

/// Internal helper: munches fields of an inline struct variant in `tlv_enum!`.
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_enum_parse_struct_fields {
    // Repeated TLV field (`Vec<T>`)
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        enum_lt: [ $($enum_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        name: [ $name:ident ],
        variant_defs: [ $($defs:tt)* ],
        decode_variants: [ $($codec:tt)* ],
        v_meta: [ $($v_meta:tt)* ],
        v_name: [ $v_name:ident ],
        tlv_fields: [ $($tlv:tt)* ],
        hl_fields: [ $($hl:tt)* ],
        v_remaining: [
            #[tag($tag:expr, repeated)]
            $(#[$field_meta:meta])*
            $field_name:ident : Vec < $inner_ty:ty >
            $(, $($v_rest:tt)*)?
        ],
        rest_variants: [ $($rest:tt)* ]
    ) => {
        $crate::__tlv_enum_parse_struct_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            enum_lt: [ $($enum_lt)? ],
            header: [ $($header)* ],
            name: [ $name ],
            variant_defs: [ $($defs)* ],
            decode_variants: [ $($codec)* ],
            v_meta: [ $($v_meta)* ],
            v_name: [ $v_name ],
            tlv_fields: [
                $($tlv)*
                (rep, $tag, [ $(#[$field_meta])* ], $field_name, Vec<$inner_ty>, $inner_ty)
            ],
            hl_fields: [ $($hl)* ],
            v_remaining: [ $($($v_rest)*)? ],
            rest_variants: [ $($rest)* ]
        );
    };

    // Paired header-list field (`#[header_list(tpl_tag, val_tag)]`)
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        enum_lt: [ $($enum_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        name: [ $name:ident ],
        variant_defs: [ $($defs:tt)* ],
        decode_variants: [ $($codec:tt)* ],
        v_meta: [ $($v_meta:tt)* ],
        v_name: [ $v_name:ident ],
        tlv_fields: [ $($tlv:tt)* ],
        hl_fields: [ $($hl:tt)* ],
        v_remaining: [
            #[header_list($tpl_tag:expr, $val_tag:expr)]
            $(#[$field_meta:meta])*
            $field_name:ident : $field_ty:ty
            $(, $($v_rest:tt)*)?
        ],
        rest_variants: [ $($rest:tt)* ]
    ) => {
        $crate::__tlv_enum_parse_struct_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            enum_lt: [ $($enum_lt)? ],
            header: [ $($header)* ],
            name: [ $name ],
            variant_defs: [ $($defs)* ],
            decode_variants: [ $($codec)* ],
            v_meta: [ $($v_meta)* ],
            v_name: [ $v_name ],
            tlv_fields: [ $($tlv)* ],
            hl_fields: [
                $($hl)*
                ($tpl_tag, $val_tag, [ $(#[$field_meta])* ], $field_name, $field_ty)
            ],
            v_remaining: [ $($($v_rest)*)? ],
            rest_variants: [ $($rest)* ]
        );
    };

    // Optional TLV field (`Option<T>`)
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        enum_lt: [ $($enum_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        name: [ $name:ident ],
        variant_defs: [ $($defs:tt)* ],
        decode_variants: [ $($codec:tt)* ],
        v_meta: [ $($v_meta:tt)* ],
        v_name: [ $v_name:ident ],
        tlv_fields: [ $($tlv:tt)* ],
        hl_fields: [ $($hl:tt)* ],
        v_remaining: [
            #[tag($tag:expr)]
            $(#[$field_meta:meta])*
            $field_name:ident : Option < $inner_ty:ty >
            $(, $($v_rest:tt)*)?
        ],
        rest_variants: [ $($rest:tt)* ]
    ) => {
        $crate::__tlv_enum_parse_struct_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            enum_lt: [ $($enum_lt)? ],
            header: [ $($header)* ],
            name: [ $name ],
            variant_defs: [ $($defs)* ],
            decode_variants: [ $($codec)* ],
            v_meta: [ $($v_meta)* ],
            v_name: [ $v_name ],
            tlv_fields: [
                $($tlv)*
                (opt, $tag, [ $(#[$field_meta])* ], $field_name, Option<$inner_ty>, $inner_ty)
            ],
            hl_fields: [ $($hl)* ],
            v_remaining: [ $($($v_rest)*)? ],
            rest_variants: [ $($rest)* ]
        );
    };

    // Required TLV field (`T`)
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        enum_lt: [ $($enum_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        name: [ $name:ident ],
        variant_defs: [ $($defs:tt)* ],
        decode_variants: [ $($codec:tt)* ],
        v_meta: [ $($v_meta:tt)* ],
        v_name: [ $v_name:ident ],
        tlv_fields: [ $($tlv:tt)* ],
        hl_fields: [ $($hl:tt)* ],
        v_remaining: [
            #[tag($tag:expr)]
            $(#[$field_meta:meta])*
            $field_name:ident : $field_ty:ty
            $(, $($v_rest:tt)*)?
        ],
        rest_variants: [ $($rest:tt)* ]
    ) => {
        $crate::__tlv_enum_parse_struct_fields!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            enum_lt: [ $($enum_lt)? ],
            header: [ $($header)* ],
            name: [ $name ],
            variant_defs: [ $($defs)* ],
            decode_variants: [ $($codec)* ],
            v_meta: [ $($v_meta)* ],
            v_name: [ $v_name ],
            tlv_fields: [
                $($tlv)*
                (req, $tag, [ $(#[$field_meta])* ], $field_name, $field_ty, $field_ty)
            ],
            hl_fields: [ $($hl)* ],
            v_remaining: [ $($($v_rest)*)? ],
            rest_variants: [ $($rest)* ]
        );
    };

    // Base case: return parsed struct variant back to `__tlv_enum_parse_variants!`
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        enum_lt: [ $($enum_lt:lifetime)? ],
        header: [ $($header:tt)* ],
        name: [ $name:ident ],
        variant_defs: [ $($defs:tt)* ],
        decode_variants: [ $($codec:tt)* ],
        v_meta: [ $($v_meta:tt)* ],
        v_name: [ $v_name:ident ],
        tlv_fields: [
            $( ( $kind:ident, $tag:expr, [ $(#[$tlv_meta:meta])* ], $tlv_name:ident, $tlv_full_ty:ty, $tlv_parse_ty:ty ) )*
        ],
        hl_fields: [
            $( ( $tpl_tag:expr, $val_tag:expr, [ $(#[$hl_meta:meta])* ], $hl_name:ident, $hl_ty:ty ) )*
        ],
        v_remaining: [],
        rest_variants: [ $($rest:tt)* ]
    ) => {
        $crate::__tlv_enum_parse_variants!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            enum_lt: [ $($enum_lt)? ],
            header: [ $($header)* ],
            name: [ $name ],
            variant_defs: [
                $($defs)*
                $($v_meta)*
                $v_name {
                    $(
                        $(#[$tlv_meta])*
                        $tlv_name : $tlv_full_ty,
                    )*
                    $(
                        $(#[$hl_meta])*
                        $hl_name : $hl_ty,
                    )*
                },
            ],
            decode_variants: [
                $($codec)*
                (
                    struct,
                    $v_name,
                    [ $( ( $kind, $tag, $tlv_name, $tlv_parse_ty ) )* ],
                    [ $( ( $tpl_tag, $val_tag, $hl_name, $hl_ty ) )* ]
                )
            ],
            remaining: [ $($rest)* ]
        );
    };
}

/// Internal helper: emits first-match-wins decode attempts for `tlv_enum!`.
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_enum_decode {
    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        decoder: $decoder:ident,
        remaining: [ (tuple, $v_name:ident, $v_ty:ty) $($rest:tt)* ]
    ) => {{
        if let Ok(value) = <$v_ty as $crate::Decode<$impl_lt>>::decode($decoder) {
            return Ok(Self::$v_name(value));
        }
        $crate::__tlv_enum_decode!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            decoder: $decoder,
            remaining: [ $($rest)* ]
        )
    }};

    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        decoder: $decoder:ident,
        remaining: [
            (
                struct,
                $v_name:ident,
                [ $( ( $kind:ident, $tag:expr, $tlv_name:ident, $tlv_ty:ty ) )* ],
                [ $( ( $tpl_tag:expr, $val_tag:expr, $hl_name:ident, $hl_ty:ty ) )* ]
            )
            $($rest:tt)*
        ]
    ) => {{
        let decode_variant = |d: &$crate::Decoder<$impl_lt>| -> Result<Self, $crate::DecodeError> {
            $crate::__tlv_decode_fields!(
                tag_type: [ $tag_ty ],
                length: [ $len_ty ],
                impl_lt: [ $impl_lt ],
                decoder: d,
                ctor: [ Self::$v_name ],
                tlv_fields: [ $( ( $kind, $tag, $tlv_name, $tlv_ty ) )* ],
                hl_fields: [ $( ( $tpl_tag, $val_tag, $hl_name, $hl_ty ) )* ]
            )
        };
        if let Ok(value) = decode_variant($decoder) {
            return Ok(value);
        }
        $crate::__tlv_enum_decode!(
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            impl_lt: [ $impl_lt ],
            decoder: $decoder,
            remaining: [ $($rest)* ]
        )
    }};

    (
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        impl_lt: [ $impl_lt:lifetime ],
        decoder: $decoder:ident,
        remaining: []
    ) => {
        Err($crate::DecodeError::InvalidValue)
    };
}

/// Internal helper: emits `match self` encoding for `tlv_enum!`.
#[doc(hidden)]
#[macro_export]
macro_rules! __tlv_enum_encode {
    (
        self: $self:ident,
        encoder: $encoder:ident,
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        arms: [ $($arms:tt)* ],
        remaining: [ (tuple, $v_name:ident, $v_ty:ty) $($rest:tt)* ]
    ) => {
        $crate::__tlv_enum_encode!(
            self: $self,
            encoder: $encoder,
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            arms: [
                $($arms)*
                Self::$v_name(value) => $crate::Encode::encode(value, $encoder),
            ],
            remaining: [ $($rest)* ]
        )
    };

    (
        self: $self:ident,
        encoder: $encoder:ident,
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        arms: [ $($arms:tt)* ],
        remaining: [
            (
                struct,
                $v_name:ident,
                [ $( ( $kind:ident, $tag:expr, $tlv_name:ident, $tlv_ty:ty ) )* ],
                [ $( ( $tpl_tag:expr, $val_tag:expr, $hl_name:ident, $hl_ty:ty ) )* ]
            )
            $($rest:tt)*
        ]
    ) => {
        $crate::__tlv_enum_encode!(
            self: $self,
            encoder: $encoder,
            tag_type: [ $tag_ty ],
            length: [ $len_ty ],
            arms: [
                $($arms)*
                Self::$v_name { $($tlv_name,)* $($hl_name,)* } => {
                    let _ = &mut *$encoder;
                    $(
                        for value in $crate::__tlv_field!(@as_slice $kind, $tlv_name) {
                            $encoder.write_tlv::<$tag_ty, $len_ty, $tlv_ty>(&$tag_ty($tag), value)?;
                        }
                    )*
                    $(
                        $encoder.write_header_list::<$tag_ty, $len_ty, $hl_ty>(
                            &$tag_ty($tpl_tag),
                            &$tag_ty($val_tag),
                            $hl_name,
                        )?;
                    )*
                    Ok(())
                }
            ],
            remaining: [ $($rest)* ]
        )
    };

    (
        self: $self:ident,
        encoder: $encoder:ident,
        tag_type: [ $tag_ty:path ],
        length: [ $len_ty:ty ],
        arms: [ $($arms:tt)* ],
        remaining: []
    ) => {
        match $self {
            $($arms)*
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::{BerLength, BerTag, Decode, DecodeError, Encode, U16Tag};

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
            Packet::decode_tlv(&[0x01, 0x01, 0xFF, 0x02, 0x02, 0xFF, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: 0xFFFE,
                opt: None
            })
        );
        assert_eq!(
            Packet::decode_tlv(&[0x01, 0x01, 0xFF, 0x02, 0x02, 0xFF, 0xFE, 0x04, 0x00]),
            Err(DecodeError::InvalidTag)
        );
        assert_eq!(
            Packet::decode_tlv(&[
                0x01, 0x01, 0xFF, 0x02, 0x02, 0xFF, 0xFE, 0x01, 0x01, 0xFF
            ]),
            Err(DecodeError::DuplicateTag)
        );
        assert_eq!(
            Packet::decode_tlv(&[0x01, 0x01]),
            Err(DecodeError::BufferUnderrun)
        );
        assert_eq!(
            Packet::decode_tlv(&[0x01, 0x01, 0xFF]),
            Err(DecodeError::MissingRequiredField)
        );

        // encode
        assert_eq!(
            Packet {
                version: 0xFF,
                payload_len: 0xFFFE,
                opt: None
            }
            .encode_tlv(),
            Ok(vec![0x01, 0x01, 0xFF, 0x02, 0x02, 0xFF, 0xFE])
        );
        assert_eq!(
            Packet {
                version: 0xFF,
                payload_len: 0xFFFE,
                opt: Some(0xFDFC)
            }
            .encode_tlv(),
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
            Packet::decode_tlv(&[0x01, 0x01, 0x01, 0xFF, 0x01, 0x02, 0x01, 0xFE]),
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
            .encode_tlv(),
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
        assert_eq!(Packet::decode_tlv(&bytes), Ok(packet));

        // decoding in a different order works
        assert_eq!(
            Packet::decode_tlv(&[0x5F, 0x52, 0x01, 0x00, 0x4F, 0x01, 0xD2]),
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
        assert_eq!(packet.encoded_length(), Ok(16));
        assert_eq!(
            packet.encode_tlv(),
            Ok(vec![
                0x4F, 0x02, 0xD2, 0x76, 0x5F, 0x52, 0x01, 0x00, 0x7F, 0x49, 0x02, 0x86, 0x00, 0xC5,
                0x01, 0xAA,
            ])
        );

        // unknown 2-byte tag
        assert_eq!(
            Packet::decode_tlv(&[0x4F, 0x00, 0x5F, 0x2D, 0x00]),
            Err(DecodeError::InvalidTag)
        );
        // duplicate 2-byte tag
        assert_eq!(
            Packet::decode_tlv(&[0x4F, 0x00, 0x5F, 0x52, 0x00, 0x5F, 0x52, 0x00]),
            Err(DecodeError::DuplicateTag)
        );
        // truncated multi-byte tag
        assert_eq!(
            Packet::decode_tlv(&[0x4F, 0x00, 0x5F]),
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
            Packet::decode_tlv(&[0x01, 0x01, 0xFF, 0x02, 0x81, 0x01, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: vec![0xFE],
            })
        );
        assert_eq!(
            Packet::decode_tlv(&[0x01, 0x01, 0xFF, 0x02, 0x82, 0x00, 0x01, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: vec![0xFE],
            })
        );
        assert_eq!(
            Packet::decode_tlv(&[0x01, 0x01, 0xFF, 0x02, 0x80, 0xFE, 0x00, 0x00]),
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
            Packet::decode_tlv(&[0x01, 0x01, 0xFF, 0x02, 0x81, 0x01, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: &[0xFE],
            })
        );
        assert_eq!(
            Packet::decode_tlv(&[0x01, 0x01, 0xFF, 0x02, 0x82, 0x00, 0x01, 0xFE]),
            Ok(Packet {
                version: 0xFF,
                payload_len: &[0xFE],
            })
        );
        assert_eq!(
            Packet::decode_tlv(&[0x01, 0x01, 0xFF, 0x02, 0x80, 0xFE, 0x00, 0x00]),
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
        let encoded = packet.encode_tlv().unwrap();
        assert_eq!(
            encoded,
            [
                0xC1, 0x01, 0xAA, 0xC1, 0x02, 0xBB, 0xCC, 0xC2, 0x02, 0x01, 0x02, 0xC2, 0x02, 0x03,
                0x04
            ]
        );
        assert_eq!(RepeatedPacket::decode_tlv(&encoded), Ok(packet));
        assert_eq!(
            RepeatedPacket::decode_tlv(&[]),
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
        let encoded = outer.encode_tlv().unwrap();
        let mut expected_vals = vec![0x01, 0x00, 0x01];
        expected_vals.extend_from_slice(&[0xAA; 128]);
        let mut expected_encoded = vec![
            0xB6, 0x00, // crt
            0x7F, 0x48, 0x05, 0x91, 0x03, 0x92, 0x81, 0x80, // template
            0x5F, 0x48, 0x81, 0x83, // values header (3 + 128 = 131 = 0x83)
        ];
        expected_encoded.extend_from_slice(&expected_vals);
        assert_eq!(outer.encoded_length(), Ok(expected_encoded.len()));
        assert_eq!(encoded, expected_encoded);
        assert_eq!(OuterHeaderList::decode_tlv(&encoded), Ok(outer));

        // Direct Decode::decode_header_list / Encode::encode_header_list
        let key = KeyHeaderList {
            e: &[0x01, 0x00, 0x01],
            p: &[0xAA; 128],
            n: None,
        };
        let (tpl, vals) = key.encode_header_list().unwrap();
        assert_eq!(tpl, [0x91, 0x03, 0x92, 0x81, 0x80]);
        assert_eq!(vals, expected_vals);

        // Same struct also decodes/encodes as standard TLV
        let tlv_encoded = key.encode_tlv().unwrap();
        assert_eq!(KeyHeaderList::decode_tlv(&tlv_encoded), Ok(key));

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

    #[test]
    fn test_tlv_enum_inline_struct_variants() {
        tlv_enum! {
            #[derive(Debug, PartialEq)]
            #[length(BerLength)]
            enum PublicKey<'a> {
                Ec {
                    #[tag(0x86)]
                    point: &'a [u8],
                },
                Rsa {
                    #[tag(0x81)]
                    modulus: &'a [u8],
                    #[tag(0x82)]
                    exponent: &'a [u8],
                },
            }
        }

        let ec = PublicKey::Ec {
            point: &[0x04, 0x11, 0x22],
        };
        let ec_encoded = ec.encode_tlv().unwrap();
        assert_eq!(ec_encoded, [0x86, 0x03, 0x04, 0x11, 0x22]);
        assert_eq!(PublicKey::decode_tlv(&ec_encoded), Ok(ec));

        let rsa = PublicKey::Rsa {
            modulus: &[0xAA; 128],
            exponent: &[0x01, 0x00, 0x01],
        };
        let rsa_encoded = rsa.encode_tlv().unwrap();
        assert_eq!(PublicKey::decode_tlv(&rsa_encoded), Ok(rsa));

        // Missing required field for RSA and wrong tag for EC
        assert_eq!(
            PublicKey::decode_tlv(&[0x81, 0x01, 0xAA]),
            Err(DecodeError::InvalidValue)
        );
        // Mixed EC + RSA tags match neither branch
        assert_eq!(
            PublicKey::decode_tlv(&[0x86, 0x01, 0x04, 0x81, 0x01, 0xAA, 0x82, 0x01, 0x03]),
            Err(DecodeError::InvalidValue)
        );
        // Unknown tag
        assert_eq!(
            PublicKey::decode_tlv(&[0x99, 0x01, 0x00]),
            Err(DecodeError::InvalidValue)
        );
    }

    #[test]
    fn test_tlv_enum_tuple_and_mixed_variants() {
        tlv_struct! {
            #[derive(Debug, PartialEq)]
            #[tag_type(BerTag)]
            #[length(BerLength)]
            struct Alpha<'a> {
                #[tag(0x5F20)]
                name: &'a [u8],
            }
        }

        tlv_enum! {
            #[derive(Debug, PartialEq)]
            #[tag_type(BerTag)]
            #[length(BerLength)]
            enum Mixed<'a> {
                Alpha(Alpha<'a>),
                Beta {
                    #[tag(0x81)]
                    code: u8,
                    #[tag(0x82)]
                    extra: Option<u16>,
                },
            }
        }

        let a = Mixed::Alpha(Alpha { name: b"hi" });
        let a_enc = a.encode_tlv().unwrap();
        assert_eq!(a_enc, [0x5F, 0x20, 0x02, b'h', b'i']);
        assert_eq!(Mixed::decode_tlv(&a_enc), Ok(a));

        let b = Mixed::Beta {
            code: 0x07,
            extra: Some(0x1234),
        };
        let b_enc = b.encode_tlv().unwrap();
        assert_eq!(b_enc, [0x81, 0x01, 0x07, 0x82, 0x02, 0x12, 0x34]);
        assert_eq!(Mixed::decode_tlv(&b_enc), Ok(b));
    }

    #[test]
    fn test_tlv_enum_header_list_and_branch_order() {
        tlv_enum! {
            #[derive(Debug, PartialEq)]
            #[tag_type(BerTag)]
            #[length(BerLength)]
            enum KeyFields<'a> {
                Rsa {
                    #[tag(0x91)]
                    exp: &'a [u8],
                    #[tag(0x92)]
                    p: &'a [u8],
                    #[tag(0x93)]
                    q: &'a [u8],
                },
                Ecc {
                    #[tag(0x92)]
                    scalar: &'a [u8],
                    #[tag(0x99)]
                    public: Option<&'a [u8]>,
                },
            }
        }

        let rsa = KeyFields::Rsa {
            exp: &[0x01, 0x00, 0x01],
            p: &[0x11, 0x22],
            q: &[0x33, 0x44],
        };
        let (tpl, vals) = rsa.encode_header_list().unwrap();
        assert_eq!(KeyFields::decode_header_list(&tpl, &vals), Ok(rsa));

        let ecc = KeyFields::Ecc {
            scalar: &[0xAA; 32],
            public: None,
        };
        let (tpl, vals) = ecc.encode_header_list().unwrap();
        assert_eq!(KeyFields::decode_header_list(&tpl, &vals), Ok(ecc));

        // Branch order precedence: when two variants can decode the same input,
        // the first declared variant wins.
        tlv_enum! {
            #[derive(Debug, PartialEq)]
            enum OrderTest {
                First {
                    #[tag(0x01)]
                    a: u8,
                    #[tag(0x02)]
                    b: Option<u8>,
                },
                Second {
                    #[tag(0x01)]
                    a: u8,
                },
            }
        }

        assert_eq!(
            OrderTest::decode_tlv(&[0x01, 0x01, 0x42]),
            Ok(OrderTest::First { a: 0x42, b: None })
        );
    }
}
