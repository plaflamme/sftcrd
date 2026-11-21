//! Synchronous request/response wire protocol between the `sftcrd` PC/SC IFD
//! handler (`sftcrd-ifd`) and the `sftcrd` daemon over any byte stream
//! (`std::io::Read` / `std::io::Write`).
//!
//! # Wire Format
//!
//! Every message in both directions is a single self-delimiting TLV encoded
//! with [`sftcrd_tlv`] (`U8Tag` + [`U32Length`]):
//!
//! ```text
//! +----------+------------------+------------------+
//! | tag (1B) | length (4B BE)   | value (N bytes)  |
//! +----------+------------------+------------------+
//! ```
//!
//! * Fixed 5-byte headers allow reading `[tag, len]` in one header read, while
//!   32-bit lengths easily accommodate full ISO/IEC 7816-4 extended-length
//!   command APDUs (up to 65,544 bytes) and response APDUs (up to 65,538 bytes).
//! * Empty-body messages (such as [`Request::Presence`], [`Request::PowerOn`],
//!   [`Request::PowerOff`], [`Request::Reset`], [`Request::GetAtr`], and
//!   [`Response::Ok`]) encode as `[tag, 0x00, 0x00, 0x00, 0x00]`.
//! * Request tags (`0x01..=0x06`) and response tags (`0x80..=0x83`, `0xFF`) are
//!   disjoint so out-of-sync frames are detected immediately.
//! * Clean EOF on a frame boundary (0 bytes read for the tag) returns
//!   `Ok(None)`. EOF mid-header or mid-value returns [`Error::TruncatedFrame`].
//! * Frames whose total encoded size exceeds [`MAX_FRAME_LEN`] are rejected as
//!   [`Error::FrameTooLarge`] before allocating the value buffer.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};

use sftcrd_tlv::{
    ConstLength, Decode, DecodeError, DecodeValue, Encode, EncodeError, EncodeValue, Length,
    U32Length, tlv_enum,
};

/// Size of the fixed `[U8Tag][U32Length]` TLV header in bytes.
const HEADER_LEN: usize = 5;

/// Maximum permitted total TLV frame length in bytes (128 KiB).
///
/// This accommodates full ISO/IEC 7816-4 extended-length command APDUs
/// (up to 65,544 bytes) and response APDUs (up to 65,538 bytes) plus TLV
/// header overhead, while bounding memory allocation against malformed length
/// prefixes.
pub const MAX_FRAME_LEN: usize = 128 * 1024;

/// Convenience result alias for protocol operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Error returned by wire framing and TLV message codecs.
#[derive(Debug)]
pub enum Error {
    /// Underlying I/O error from the transport stream.
    Io(io::Error),
    /// Peer closed the connection when a response was expected.
    UnexpectedEof,
    /// Peer closed the connection mid-header or mid-value.
    TruncatedFrame,
    /// Total TLV frame length exceeded [`MAX_FRAME_LEN`].
    FrameTooLarge {
        /// Actual or declared frame length in bytes.
        len: usize,
        /// Maximum permitted frame length in bytes.
        max: usize,
    },
    /// TLV decoding failed (malformed tag, length, or value).
    Decode(DecodeError),
    /// TLV encoding failed.
    Encode(EncodeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::UnexpectedEof => f.write_str("peer closed connection before sending response"),
            Self::TruncatedFrame => f.write_str("truncated TLV frame (unexpected EOF)"),
            Self::FrameTooLarge { len, max } => {
                write!(f, "frame length {len} exceeds maximum {max} bytes")
            }
            Self::Decode(err) => write!(f, "TLV decode error: {err:?}"),
            Self::Encode(err) => write!(f, "TLV encode error: {err:?}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Self {
        Self::Decode(err)
    }
}

impl From<EncodeError> for Error {
    fn from(err: EncodeError) -> Self {
        Self::Encode(err)
    }
}

/// Typed error codes returned by the daemon in [`Response::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ErrorCode {
    /// A command (such as [`Request::Transmit`]) was issued while the card is
    /// powered off.
    NotPowered = 0x01,
    /// No virtual card is currently present.
    CardAbsent = 0x02,
    /// The command APDU exceeds the card's maximum supported buffer size.
    ApduTooLarge = 0x03,
    /// The request was malformed or invalid in the current state.
    InvalidRequest = 0x04,
    /// An internal daemon or applet dispatch error occurred.
    Internal = 0x05,
    /// The requested operation is not supported.
    Unsupported = 0x06,
}

impl TryFrom<u8> for ErrorCode {
    type Error = DecodeError;

    fn try_from(value: u8) -> std::result::Result<Self, DecodeError> {
        match value {
            0x01 => Ok(Self::NotPowered),
            0x02 => Ok(Self::CardAbsent),
            0x03 => Ok(Self::ApduTooLarge),
            0x04 => Ok(Self::InvalidRequest),
            0x05 => Ok(Self::Internal),
            0x06 => Ok(Self::Unsupported),
            _ => Err(DecodeError::InvalidValue),
        }
    }
}

impl From<ErrorCode> for u8 {
    fn from(code: ErrorCode) -> Self {
        code as Self
    }
}

impl ConstLength for ErrorCode {
    const LENGTH: usize = 1;
}

impl DecodeValue<'_> for ErrorCode {
    fn decode_bytes(bytes: &[u8]) -> std::result::Result<Self, DecodeError> {
        Self::try_from(u8::decode_bytes(bytes)?)
    }
}

impl EncodeValue for ErrorCode {
    fn length(&self) -> usize {
        1
    }

    fn encode_bytes(&self, buf: &mut [u8]) -> std::result::Result<(), EncodeError> {
        u8::from(*self).encode_bytes(buf)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::NotPowered => "card not powered",
            Self::CardAbsent => "card absent",
            Self::ApduTooLarge => "APDU too large",
            Self::InvalidRequest => "invalid request",
            Self::Internal => "internal error",
            Self::Unsupported => "unsupported operation",
        };
        f.write_str(label)
    }
}

tlv_enum! {
    /// Request sent from the IFD handler to the `sftcrd` daemon.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[length(U32Length)]
    pub enum Request {
        /// Query whether a card is present and the daemon is responsive.
        #[tag(0x01)]
        Presence,
        /// Cold power-on the card and retrieve its ATR.
        #[tag(0x02)]
        PowerOn,
        /// Power off the card.
        #[tag(0x03)]
        PowerOff,
        /// Warm reset the card and retrieve its ATR.
        #[tag(0x04)]
        Reset,
        /// Retrieve the card's ATR without changing power state.
        #[tag(0x05)]
        GetAtr,
        /// Transmit a command APDU (short or extended length) to the card.
        #[tag(0x06)]
        Transmit(Vec<u8>),
    }
}

tlv_enum! {
    /// Response sent from the `sftcrd` daemon back to the IFD handler.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[length(U32Length)]
    pub enum Response {
        /// Operation succeeded with no payload (e.g. [`Request::PowerOff`]).
        #[tag(0x80)]
        Ok,
        /// Card presence result in response to [`Request::Presence`].
        #[tag(0x81)]
        Presence(bool),
        /// Card ATR bytes in response to [`Request::PowerOn`], [`Request::Reset`],
        /// or [`Request::GetAtr`].
        #[tag(0x82)]
        Atr(Vec<u8>),
        /// Response APDU bytes (response data + SW1/SW2) in response to
        /// [`Request::Transmit`].
        #[tag(0x83)]
        Apdu(Vec<u8>),
        /// Typed error response from the daemon.
        #[tag(0xFF)]
        Error {
            #[tag(0x01)]
            /// Machine-readable error code.
            code: ErrorCode,
            #[tag(0x02)]
            /// Optional UTF-8 diagnostic message.
            message: Option<String>,
        },
    }
}

impl Response {
    /// Construct a [`Response::Error`], omitting the diagnostic message field
    /// when `message` is empty.
    #[must_use]
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        let message = message.into();
        Self::Error {
            code,
            message: (!message.is_empty()).then_some(message),
        }
    }
}

/// Read one complete `[U8Tag][U32Length][Value]` TLV frame from `reader`.
///
/// Returns `Ok(None)` on a clean EOF at the frame boundary (0 bytes read).
///
/// # Errors
///
/// Returns [`Error::TruncatedFrame`] if EOF occurs mid-header or mid-value,
/// [`Error::FrameTooLarge`] if the total frame length exceeds
/// [`MAX_FRAME_LEN`], [`Error::Decode`] if the length header cannot be
/// decoded, or [`Error::Io`] on any other read failure.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; HEADER_LEN];

    // Read the first byte separately so a clean EOF at a frame boundary is
    // distinguished from a truncated 1..=4-byte header.
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(Error::Io(err)),
        }
    }

    read_exact_or_truncated(reader, &mut header[1..])?;

    let (val_len, _) = U32Length::decode(&header[1..])?;
    let total_len = HEADER_LEN.saturating_add(val_len);
    if total_len > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge {
            len: total_len,
            max: MAX_FRAME_LEN,
        });
    }

    let mut frame = vec![0u8; total_len];
    frame[..HEADER_LEN].copy_from_slice(&header);
    read_exact_or_truncated(reader, &mut frame[HEADER_LEN..])?;
    Ok(Some(frame))
}

/// Write a [`Request`] as a TLV frame to `writer` and flush it.
///
/// # Errors
///
/// Returns [`Error::FrameTooLarge`] if the encoded frame exceeds
/// [`MAX_FRAME_LEN`], [`Error::Encode`] on TLV encoding failure, or
/// [`Error::Io`] on write/flush failure.
pub fn write_request(writer: &mut impl Write, request: &Request) -> Result<()> {
    write_tlv(writer, request)
}

/// Read and decode a [`Request`] TLV frame from `reader`.
///
/// Returns `Ok(None)` on a clean EOF at the frame boundary.
///
/// # Errors
///
/// Returns any framing error from [`read_frame`] or TLV decoding error from
/// [`Request::decode`].
pub fn read_request(reader: &mut impl Read) -> Result<Option<Request>> {
    let Some(frame) = read_frame(reader)? else {
        return Ok(None);
    };
    Ok(Some(Request::decode_tlv(&frame)?))
}

/// Write a [`Response`] as a TLV frame to `writer` and flush it.
///
/// # Errors
///
/// Returns [`Error::FrameTooLarge`] if the encoded frame exceeds
/// [`MAX_FRAME_LEN`], [`Error::Encode`] on TLV encoding failure, or
/// [`Error::Io`] on write/flush failure.
pub fn write_response(writer: &mut impl Write, response: &Response) -> Result<()> {
    write_tlv(writer, response)
}

/// Read and decode a [`Response`] TLV frame from `reader`.
///
/// Returns `Ok(None)` on a clean EOF at the frame boundary.
///
/// # Errors
///
/// Returns any framing error from [`read_frame`] or TLV decoding error from
/// [`Response::decode`].
pub fn read_response(reader: &mut impl Read) -> Result<Option<Response>> {
    let Some(frame) = read_frame(reader)? else {
        return Ok(None);
    };
    Ok(Some(Response::decode_tlv(&frame)?))
}

/// Send a [`Request`] over `stream` and wait for the synchronous [`Response`].
///
/// # Errors
///
/// Returns [`Error::UnexpectedEof`] if the peer closes the connection before
/// replying, or any framing/codec/I/O error from [`write_request`] or
/// [`read_response`].
pub fn exchange(stream: &mut (impl Read + Write), request: &Request) -> Result<Response> {
    write_request(stream, request)?;
    read_response(stream)?.ok_or(Error::UnexpectedEof)
}

fn write_tlv(writer: &mut impl Write, value: &impl Encode) -> Result<()> {
    let len = value.encoded_length()?;
    if len > MAX_FRAME_LEN {
        return Err(Error::FrameTooLarge {
            len,
            max: MAX_FRAME_LEN,
        });
    }
    let encoded = value.encode_tlv()?;
    writer.write_all(&encoded)?;
    writer.flush()?;
    Ok(())
}

fn read_exact_or_truncated(reader: &mut impl Read, buf: &mut [u8]) -> Result<()> {
    reader.read_exact(buf).map_err(|err| {
        if err.kind() == ErrorKind::UnexpectedEof {
            Error::TruncatedFrame
        } else {
            Error::Io(err)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn request_round_trip_all_variants() {
        let requests = [
            Request::Presence,
            Request::PowerOn,
            Request::PowerOff,
            Request::Reset,
            Request::GetAtr,
            Request::Transmit(vec![
                0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08,
            ]),
            Request::Transmit(Vec::new()),
        ];

        // Empty-body commands encode as 5-byte [tag, 0x00, 0x00, 0x00, 0x00] TLVs.
        assert_eq!(
            Request::Presence.encode_tlv().unwrap(),
            [0x01, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            Request::PowerOn.encode_tlv().unwrap(),
            [0x02, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            Request::PowerOff.encode_tlv().unwrap(),
            [0x03, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            Request::Reset.encode_tlv().unwrap(),
            [0x04, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            Request::GetAtr.encode_tlv().unwrap(),
            [0x05, 0x00, 0x00, 0x00, 0x00]
        );

        let mut wire = Vec::new();
        for req in &requests {
            write_request(&mut wire, req).expect("write request");
        }

        let mut cursor = Cursor::new(wire);
        for expected in &requests {
            let decoded = read_request(&mut cursor)
                .expect("read request")
                .expect("present request");
            assert_eq!(&decoded, expected);

            let tlv = expected.encode_tlv().expect("encode_tlv");
            assert_eq!(Request::decode_tlv(&tlv).expect("decode_tlv"), *expected);
        }

        // Clean EOF after last frame.
        assert_eq!(read_request(&mut cursor).expect("clean EOF"), None);
    }

    #[test]
    fn response_round_trip_all_variants() {
        let responses = [
            Response::Ok,
            Response::Presence(false),
            Response::Presence(true),
            Response::Atr(vec![0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31]),
            Response::Apdu(vec![0x90, 0x00]),
            Response::error(ErrorCode::NotPowered, "card is powered off"),
            Response::error(ErrorCode::CardAbsent, ""),
            Response::error(ErrorCode::ApduTooLarge, "exceeds 3072 bytes"),
            Response::error(ErrorCode::InvalidRequest, "bad apdu"),
            Response::error(ErrorCode::Internal, "dispatch failure"),
            Response::error(ErrorCode::Unsupported, "not implemented"),
        ];

        assert_eq!(
            Response::Ok.encode_tlv().unwrap(),
            [0x80, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            Response::Presence(true).encode_tlv().unwrap(),
            [0x81, 0x00, 0x00, 0x00, 0x01, 0x01]
        );
        assert_eq!(
            Response::error(ErrorCode::CardAbsent, "")
                .encode_tlv()
                .unwrap(),
            [
                0xFF, 0x00, 0x00, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02
            ]
        );

        let mut wire = Vec::new();
        for resp in &responses {
            write_response(&mut wire, resp).expect("write response");
        }

        let mut cursor = Cursor::new(wire);
        for expected in &responses {
            let decoded = read_response(&mut cursor)
                .expect("read response")
                .expect("present response");
            assert_eq!(&decoded, expected);

            let tlv = expected.encode_tlv().expect("encode_tlv");
            assert_eq!(Response::decode_tlv(&tlv).expect("decode_tlv"), *expected);
        }

        // Clean EOF after last frame.
        assert_eq!(read_response(&mut cursor).expect("clean EOF"), None);
    }

    #[test]
    fn extended_length_apdu_round_trip() {
        // Maximum ISO/IEC 7816-4 extended-length command APDU:
        // 4-byte header + 3-byte Lc (65535) + 65535 data bytes + 2-byte Le = 65544 bytes.
        let mut cmd = Vec::with_capacity(65_544);
        cmd.extend_from_slice(&[0x00, 0xDB, 0x3F, 0xFF, 0x00, 0xFF, 0xFF]);
        cmd.resize(7 + 65_535, 0xA5);
        cmd.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(cmd.len(), 65_544);

        let mut wire = Vec::new();
        let req = Request::Transmit(cmd);
        write_request(&mut wire, &req).expect("write extended APDU request");
        // Tag 0x06 + U32Length 65544 (0x0001_0008)
        assert_eq!(&wire[..5], &[0x06, 0x00, 0x01, 0x00, 0x08]);

        let mut cursor = Cursor::new(wire);
        let decoded = read_request(&mut cursor)
            .expect("read extended APDU request")
            .expect("present");
        assert_eq!(decoded, req);

        // Maximum extended-length response APDU: 65536 bytes data + 2-byte SW = 65538 bytes.
        let mut resp_apdu = vec![0x5A; 65_536];
        resp_apdu.extend_from_slice(&[0x90, 0x00]);
        assert_eq!(resp_apdu.len(), 65_538);

        let mut resp_wire = Vec::new();
        let resp = Response::Apdu(resp_apdu);
        write_response(&mut resp_wire, &resp).expect("write extended APDU response");
        // Tag 0x83 + U32Length 65538 (0x0001_0002)
        assert_eq!(&resp_wire[..5], &[0x83, 0x00, 0x01, 0x00, 0x02]);

        let mut resp_cursor = Cursor::new(resp_wire);
        let decoded_resp = read_response(&mut resp_cursor)
            .expect("read extended APDU response")
            .expect("present");
        assert_eq!(decoded_resp, resp);
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert_eq!(read_frame(&mut empty).expect("clean EOF"), None);
        assert_eq!(read_request(&mut empty).expect("clean EOF"), None);
        assert_eq!(read_response(&mut empty).expect("clean EOF"), None);
    }

    #[test]
    fn truncated_header_and_value_return_error() {
        for partial_header in [
            vec![0x01],
            vec![0x01, 0x00],
            vec![0x01, 0x00, 0x00],
            vec![0x01, 0x00, 0x00, 0x00],
        ] {
            let mut cursor = Cursor::new(partial_header);
            assert!(matches!(
                read_frame(&mut cursor),
                Err(Error::TruncatedFrame)
            ));
        }

        // Declared 10 value bytes, only 3 provided.
        let mut cursor = Cursor::new(vec![0x06, 0x00, 0x00, 0x00, 0x0A, 0x00, 0xA4, 0x04]);
        assert!(matches!(
            read_request(&mut cursor),
            Err(Error::TruncatedFrame)
        ));
    }

    #[test]
    fn oversized_frame_rejected_on_read_and_write() {
        // Read: declared length exceeds MAX_FRAME_LEN (rejected before allocating).
        let val_len = u32::try_from(MAX_FRAME_LEN).expect("fits in u32");
        let mut header = vec![0x06];
        header.extend_from_slice(&val_len.to_be_bytes());
        let mut cursor = Cursor::new(header);
        assert!(matches!(
            read_frame(&mut cursor),
            Err(Error::FrameTooLarge { len, max }) if len == MAX_FRAME_LEN + HEADER_LEN && max == MAX_FRAME_LEN
        ));

        // Write: exact MAX_FRAME_LEN succeeds, MAX_FRAME_LEN + 1 fails without writing bytes.
        let max_req = Request::Transmit(vec![0u8; MAX_FRAME_LEN - HEADER_LEN]);
        let mut out = Vec::new();
        write_request(&mut out, &max_req).expect("exact MAX_FRAME_LEN succeeds");
        assert_eq!(out.len(), MAX_FRAME_LEN);

        let too_big_req = Request::Transmit(vec![0u8; MAX_FRAME_LEN - HEADER_LEN + 1]);
        let mut out = Vec::new();
        assert!(matches!(
            write_request(&mut out, &too_big_req),
            Err(Error::FrameTooLarge { len, max }) if len == MAX_FRAME_LEN + 1 && max == MAX_FRAME_LEN
        ));
        assert!(
            out.is_empty(),
            "oversized write must not emit partial bytes"
        );
    }

    #[test]
    fn malformed_frames_rejected() {
        // Empty slice.
        assert_eq!(Request::decode_tlv(&[]), Err(DecodeError::BufferUnderrun));
        assert_eq!(Response::decode_tlv(&[]), Err(DecodeError::BufferUnderrun));

        // Multiple top-level TLVs in a single decode call.
        assert_eq!(
            Request::decode_tlv(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00]),
            Err(DecodeError::InvalidValue)
        );
        assert_eq!(
            Response::decode_tlv(&[0x80, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00]),
            Err(DecodeError::InvalidValue)
        );

        // Unknown request tag (including response tags).
        assert_eq!(
            Request::decode_tlv(&[0x80, 0x00, 0x00, 0x00, 0x00]),
            Err(DecodeError::InvalidTag)
        );
        assert_eq!(
            Request::decode_tlv(&[0x42, 0x00, 0x00, 0x00, 0x00]),
            Err(DecodeError::InvalidTag)
        );

        // Non-empty body on empty-body requests.
        for tag in [0x01u8, 0x02, 0x03, 0x04, 0x05] {
            assert_eq!(
                Request::decode_tlv(&[tag, 0x00, 0x00, 0x00, 0x01, 0x00]),
                Err(DecodeError::InvalidValue)
            );
        }

        // Unknown response tag (including request tags).
        assert_eq!(
            Response::decode_tlv(&[0x01, 0x00, 0x00, 0x00, 0x00]),
            Err(DecodeError::InvalidTag)
        );

        // Non-empty body on Response::Ok.
        assert_eq!(
            Response::decode_tlv(&[0x80, 0x00, 0x00, 0x00, 0x01, 0x01]),
            Err(DecodeError::InvalidValue)
        );

        // Invalid presence responses.
        assert_eq!(
            Response::decode_tlv(&[0x81, 0x00, 0x00, 0x00, 0x00]),
            Err(DecodeError::BufferUnderrun)
        );
        assert_eq!(
            Response::decode_tlv(&[0x81, 0x00, 0x00, 0x00, 0x01, 0x02]),
            Err(DecodeError::InvalidValue)
        );
        assert_eq!(
            Response::decode_tlv(&[0x81, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00]),
            Err(DecodeError::BufferUnderrun)
        );

        // Malformed error responses.
        assert_eq!(
            Response::decode_tlv(&[0xFF, 0x00, 0x00, 0x00, 0x00]),
            Err(DecodeError::MissingRequiredField)
        );
        // Unknown ErrorCode 0x99.
        assert_eq!(
            Response::decode_tlv(&[
                0xFF, 0x00, 0x00, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x01, 0x99
            ]),
            Err(DecodeError::InvalidValue)
        );
        // Invalid UTF-8 in message.
        assert_eq!(
            Response::decode_tlv(&[
                0xFF, 0x00, 0x00, 0x00, 0x0D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x02, 0x00, 0x00,
                0x00, 0x02, 0xFF, 0xFE,
            ]),
            Err(DecodeError::InvalidValue)
        );
        // Duplicate code tag.
        assert_eq!(
            Response::decode_tlv(&[
                0xFF, 0x00, 0x00, 0x00, 0x0C, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00,
                0x00, 0x01, 0x05,
            ]),
            Err(DecodeError::DuplicateTag)
        );
        // Unknown nested tag inside error.
        assert_eq!(
            Response::decode_tlv(&[
                0xFF, 0x00, 0x00, 0x00, 0x0B, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x99, 0x00, 0x00,
                0x00, 0x00,
            ]),
            Err(DecodeError::InvalidTag)
        );
    }

    #[test]
    fn exchange_over_unix_stream_pair() {
        use std::os::unix::net::UnixStream;
        use std::thread;

        let (mut client, mut server) = UnixStream::pair().expect("UnixStream::pair");

        let handle = thread::spawn(move || {
            while let Some(req) = read_request(&mut server).expect("server read") {
                let resp = match req {
                    Request::Presence => Response::Presence(true),
                    Request::PowerOn | Request::Reset | Request::GetAtr => {
                        Response::Atr(vec![0x3B, 0x00])
                    }
                    Request::PowerOff => Response::Ok,
                    Request::Transmit(apdu) if apdu.is_empty() => {
                        Response::error(ErrorCode::InvalidRequest, "empty APDU")
                    }
                    Request::Transmit(_) => Response::Apdu(vec![0x90, 0x00]),
                };
                write_response(&mut server, &resp).expect("server write");
            }
        });

        assert_eq!(
            exchange(&mut client, &Request::Presence).expect("presence"),
            Response::Presence(true)
        );
        assert_eq!(
            exchange(&mut client, &Request::PowerOn).expect("power on"),
            Response::Atr(vec![0x3B, 0x00])
        );
        assert_eq!(
            exchange(
                &mut client,
                &Request::Transmit(vec![0x00, 0xA4, 0x04, 0x00])
            )
            .expect("transmit"),
            Response::Apdu(vec![0x90, 0x00])
        );
        assert_eq!(
            exchange(&mut client, &Request::Transmit(Vec::new())).expect("empty apdu error"),
            Response::error(ErrorCode::InvalidRequest, "empty APDU")
        );
        assert_eq!(
            exchange(&mut client, &Request::PowerOff).expect("power off"),
            Response::Ok
        );

        drop(client);
        handle.join().expect("server thread");
    }

    #[test]
    fn exchange_reports_unexpected_eof_when_server_drops() {
        use std::os::unix::net::UnixStream;

        let (mut client, server) = UnixStream::pair().expect("UnixStream::pair");
        drop(server);

        let err = exchange(&mut client, &Request::Presence).expect_err("must fail");
        assert!(matches!(err, Error::UnexpectedEof | Error::Io(_)));
    }
}
