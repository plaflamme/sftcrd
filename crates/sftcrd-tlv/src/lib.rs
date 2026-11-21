//! Tag-Length-Value (TLV) and ISO/IEC 7816-4 header-list codecs.
//!
//! # Tags and lengths
//!
//! Wire formats are parameterized over [`Tag`] and [`Length`] implementations:
//!
//! - [`Tag`]: [`U8Tag`] (1-byte), [`U16Tag`] (2-byte big-endian), and [`BerTag`] (BER-TLV
//!   multi-byte tags).
//! - [`Length`]: [`U8Length`] (1-byte) and [`BerLength`] (BER-TLV definite-form lengths).
//!
//! ```
//! use sftcrd_tlv::{BerLength, BerTag, Length, Tag};
//!
//! let tag = BerTag(0x5F52);
//! let mut tag_buf = vec![0; tag.length()];
//! tag.encode(&mut tag_buf).unwrap();
//! assert_eq!(tag_buf, [0x5F, 0x52]);
//! assert_eq!(BerTag::decode(&tag_buf), Ok((tag, 2)));
//!
//! let len_bytes = BerLength::length(128) as usize;
//! let mut len_buf = vec![0; len_bytes];
//! BerLength::encode(128, &mut len_buf).unwrap();
//! assert_eq!(len_buf, [0x81, 0x80]);
//! assert_eq!(BerLength::decode(&len_buf), Ok((128, 2)));
//! ```
//!
//! # Decoding and encoding values
//!
//! Types implement [`Decode`] and [`Encode`] to read from a [`Decoder`] and write to an
//! [`Encoder`]. Primitive leaf types (`()`, `bool`, `u8`, `u16`, `u32`, `&[u8]`, `Vec<u8>`,
//! `&str`, `String`) implement these traits out of the box; composite types iterate over
//! `(tag, value_bytes)` pairs via [`Decoder::iter_tags`] and write fields via
//! [`Encoder::write_tlv`].
//!
//! Because `Decoder` and `Encoder` abstract over standard TLV streams and ISO/IEC 7816-4
//! header-list `(template, values)` pairs, the same [`Decode`] / [`Encode`] implementation
//! supports both formats via [`Decode::decode_tlv`] / [`Encode::encode_tlv`] and
//! [`Decode::decode_header_list`] / [`Encode::encode_header_list`]:
//!
//! ```
//! use sftcrd_tlv::{
//!     Decode, DecodeError, Decoder, Encode, EncodeError, Encoder, U8Length, U8Tag,
//! };
//!
//! #[derive(Debug, PartialEq)]
//! struct Record {
//!     version: u8,
//!     payload: Vec<u8>,
//! }
//!
//! impl Decode<'_> for Record {
//!     fn decode(decoder: &Decoder<'_>) -> Result<Self, DecodeError> {
//!         let mut version = None;
//!         let mut payload = None;
//!         for entry in decoder.iter_tags::<U8Tag, U8Length>() {
//!             match entry? {
//!                 (U8Tag(0x01), bytes) => version = Some(u8::decode_tlv(bytes)?),
//!                 (U8Tag(0x02), bytes) => payload = Some(Vec::<u8>::decode_tlv(bytes)?),
//!                 _ => return Err(DecodeError::InvalidTag),
//!             }
//!         }
//!         Ok(Self {
//!             version: version.ok_or(DecodeError::MissingRequiredField)?,
//!             payload: payload.ok_or(DecodeError::MissingRequiredField)?,
//!         })
//!     }
//! }
//!
//! impl Encode for Record {
//!     fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
//!         encoder.write_tlv::<U8Tag, U8Length, u8>(&U8Tag(0x01), &self.version)?;
//!         encoder.write_tlv::<U8Tag, U8Length, Vec<u8>>(&U8Tag(0x02), &self.payload)?;
//!         Ok(())
//!     }
//! }
//!
//! let record = Record { version: 1, payload: vec![0xAA, 0xBB] };
//!
//! // Standard TLV stream
//! let bytes = record.encode_tlv().unwrap();
//! assert_eq!(bytes, [0x01, 0x01, 0x01, 0x02, 0x02, 0xAA, 0xBB]);
//! assert_eq!(Record::decode_tlv(&bytes), Ok(Record { version: 1, payload: vec![0xAA, 0xBB] }));
//!
//! // ISO/IEC 7816-4 header list
//! let (tpl, vals) = record.encode_header_list().unwrap();
//! assert_eq!(tpl, [0x01, 0x01, 0x02, 0x02]);
//! assert_eq!(vals, [0x01, 0xAA, 0xBB]);
//! assert_eq!(Record::decode_header_list(&tpl, &vals), Ok(record));
//! ```
//!
//! ## Custom leaf types
//!
//! Implement [`DecodeValue`] and [`EncodeValue`] for primitive or domain leaf types.
//! Blanket implementations provide [`Decode`] and [`Encode`] automatically (and reject
//! header-list mode with [`DecodeError::InvalidValue`] / [`EncodeError::InvalidValue`]):
//!
//! ```
//! use sftcrd_tlv::{Decode, DecodeError, DecodeValue, Encode, EncodeError, EncodeValue};
//!
//! #[derive(Debug, PartialEq)]
//! struct Flag(bool);
//!
//! impl DecodeValue<'_> for Flag {
//!     fn decode_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
//!         Ok(Self(bool::decode_bytes(bytes)?))
//!     }
//! }
//!
//! impl EncodeValue for Flag {
//!     fn length(&self) -> usize {
//!         self.0.length()
//!     }
//!
//!     fn encode_bytes(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
//!         self.0.encode_bytes(buf)
//!     }
//! }
//!
//! let encoded = Flag(true).encode_tlv().unwrap();
//! assert_eq!(encoded, [0x01]);
//! assert_eq!(Flag::decode_tlv(&encoded), Ok(Flag(true)));
//! ```
//!
//! # Defining TLV structs with `tlv_struct!`
//!
//! Use [`tlv_struct!`] to generate a struct with [`Decode`] and [`Encode`] implementations.
//! By default, fields use [`U8Tag`] and [`U8Length`]; override them with `#[tag_type(...)]`
//! and `#[length(...)]` (for example [`BerTag`], [`U16Tag`], [`BerLength`]). Enclosing structs
//! can also embed a paired header list using `#[header_list(tpl_tag, val_tag)]`:
//!
//! ```
//! use sftcrd_tlv::{BerLength, BerTag, Decode, Encode, tlv_struct};
//!
//! tlv_struct! {
//!     #[derive(Debug, PartialEq)]
//!     #[tag_type(BerTag)]
//!     #[length(BerLength)]
//!     struct KeyFields<'a> {
//!         #[tag(0x91)]
//!         exp: &'a [u8],
//!         #[tag(0x92)]
//!         prime: &'a [u8],
//!     }
//! }
//!
//! tlv_struct! {
//!     #[derive(Debug, PartialEq)]
//!     #[tag_type(BerTag)]
//!     #[length(BerLength)]
//!     struct ExtendedHeaderList<'a> {
//!         #[tag(0xB6)]
//!         crt: &'a [u8],
//!         #[header_list(0x7F48, 0x5F48)]
//!         fields: KeyFields<'a>,
//!     }
//! }
//!
//! let fields = KeyFields { exp: &[0x01, 0x00, 0x01], prime: &[0xAA] };
//! let (tpl, vals) = fields.encode_header_list().unwrap();
//! assert_eq!(KeyFields::decode_header_list(&tpl, &vals), Ok(fields));
//! ```
//!
//! # Defining TLV unions with `tlv_enum!`
//!
//! Use [`tlv_enum!`] to generate an enum with [`Decode`] and [`Encode`] implementations.
//! Two union styles are supported depending on whether variants carry a `#[tag(...)]`
//! attribute:
//!
//! ## Discriminated (tagged) unions
//!
//! Annotate every variant with `#[tag(expr)]` to wrap each variant in a single outer TLV
//! whose tag identifies the variant. Unit variants (empty value), tuple variants (any
//! [`Decode`] / [`Encode`] payload), and inline struct variants (nested TLV fields) are
//! all supported. Decoding performs a single-pass dispatch on the outer tag and preserves
//! exact [`DecodeError`] variants (`InvalidTag`, `MissingRequiredField`, `DuplicateTag`,
//! `InvalidValue`, `BufferUnderrun`):
//!
//! ```
//! use sftcrd_tlv::{BerLength, Decode, DecodeError, Encode, tlv_enum};
//!
//! tlv_enum! {
//!     #[derive(Debug, PartialEq)]
//!     #[length(BerLength)]
//!     enum Message {
//!         #[tag(0x01)]
//!         Ping,
//!         #[tag(0x02)]
//!         Data(Vec<u8>),
//!         #[tag(0xFF)]
//!         Error {
//!             #[tag(0x01)]
//!             code: u8,
//!             #[tag(0x02)]
//!             detail: Option<String>,
//!         },
//!     }
//! }
//!
//! let ping = Message::Ping.encode_tlv().unwrap();
//! assert_eq!(ping, [0x01, 0x00]);
//! assert_eq!(Message::decode_tlv(&ping), Ok(Message::Ping));
//!
//! let err = Message::Error { code: 0x05, detail: Some("boom".into()) };
//! let bytes = err.encode_tlv().unwrap();
//! assert_eq!(Message::decode_tlv(&bytes), Ok(err));
//! assert_eq!(Message::decode_tlv(&[0x99, 0x00]), Err(DecodeError::InvalidTag));
//! ```
//!
//! ## Non-discriminated (untagged) unions
//!
//! Omit `#[tag(...)]` on variants for untagged unions, such as mutually exclusive sets of
//! TLVs or header lists whose tag layout varies by variant. Variants may be **inline
//! struct variants** or **tuple variants** wrapping any existing [`Decode`] / [`Encode`]
//! type, and both forms can be mixed in the same enum. Decoding tries each variant in
//! declaration order against the same [`Decoder`] and returns the first one that succeeds,
//! or [`DecodeError::InvalidValue`] if all variants fail.
//!
//! Like [`tlv_struct!`], both discriminated and non-discriminated enums work in standard
//! TLV and ISO/IEC 7816-4 header-list modes:
//!
//! ```
//! use sftcrd_tlv::{BerLength, Decode, DecodeError, Encode, tlv_enum, tlv_struct};
//!
//! tlv_struct! {
//!     #[derive(Debug, PartialEq)]
//!     #[length(BerLength)]
//!     struct Pair<'a> {
//!         #[tag(0x81)]
//!         first: &'a [u8],
//!         #[tag(0x82)]
//!         second: &'a [u8],
//!     }
//! }
//!
//! tlv_enum! {
//!     #[derive(Debug, PartialEq)]
//!     #[length(BerLength)]
//!     enum Payload<'a> {
//!         Single {
//!             #[tag(0x86)]
//!             data: &'a [u8],
//!         },
//!         Pair(Pair<'a>),
//!     }
//! }
//!
//! let single = Payload::Single { data: &[0x04, 0xAA, 0xBB] };
//! let bytes = single.encode_tlv().unwrap();
//! assert_eq!(Payload::decode_tlv(&bytes), Ok(single));
//!
//! let pair = Payload::Pair(Pair { first: &[0xAA], second: &[0x01, 0x00, 0x01] });
//! let (tpl, vals) = pair.encode_header_list().unwrap();
//! assert_eq!(Payload::decode_header_list(&tpl, &vals), Ok(pair));
//!
//! assert_eq!(Payload::decode_tlv(&[0x99, 0x01, 0x00]), Err(DecodeError::InvalidValue));
//! ```

mod decoder;
mod encoder;
mod error;
mod length;
mod macros;
mod tag;
mod value;

pub use decoder::{Decoder, TagIter};
#[doc(hidden)]
pub use encoder::__EncodeFn;
pub use encoder::Encoder;
pub use error::{DecodeError, EncodeError};
pub use length::{BerLength, Length, U8Length};
pub use tag::{BerTag, Tag, U8Tag, U16Tag};
pub use value::{ConstLength, Decode, DecodeValue, Encode, EncodeValue};
