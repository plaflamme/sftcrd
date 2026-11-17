//! APDU command and response wrappers.

use apdu_dispatch::Response as ApduResponse;
use iso7816::Status;

/// Borrowed view of an ISO 7816-4 APDU command.
pub type CommandView<'a> = iso7816::command::CommandView<'a>;

/// Response produced by an applet's APDU command handler.
#[derive(Debug)]
pub struct Response(ApduResponse);

impl Response {
    /// Unwrap into the underlying [`apdu_dispatch::Response`].
    #[must_use]
    pub fn into_inner(self) -> ApduResponse {
        self.0
    }

    /// Build a data response from a byte slice, returning [`Status::NotEnoughMemory`]
    /// if the payload exceeds the APDU buffer capacity.
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        let apdu_response = match apdu_dispatch::response::Data::from_slice(data) {
            Ok(data) => ApduResponse::Data(data),
            Err(_) => ApduResponse::Status(Status::NotEnoughMemory),
        };
        Self(apdu_response)
    }

    /// Return the response payload bytes, or an empty slice for status-only responses.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        match &self.0 {
            ApduResponse::Data(d) => d,
            ApduResponse::Status(_) => &[],
        }
    }

    /// Return [`Status::Success`] for data responses, or the contained [`Status`].
    #[must_use]
    pub fn status(&self) -> Status {
        match self.0 {
            ApduResponse::Data(_) => Status::Success,
            ApduResponse::Status(status) => status,
        }
    }
}

impl From<Status> for Response {
    fn from(value: Status) -> Self {
        Self(apdu_dispatch::Response::Status(value))
    }
}

impl From<Vec<u8>> for Response {
    fn from(value: Vec<u8>) -> Self {
        Self::from_slice(&value)
    }
}

impl From<&[u8]> for Response {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl<const N: usize> From<[u8; N]> for Response {
    fn from(value: [u8; N]) -> Self {
        Self::from_slice(&value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_response_has_empty_data_and_preserves_status() {
        let resp = Response::from(Status::ConditionsOfUseNotSatisfied);
        assert_eq!(resp.status(), Status::ConditionsOfUseNotSatisfied);
        assert_eq!(resp.data(), []);
    }

    #[test]
    fn data_response_preserves_bytes_and_success_status() {
        let resp = Response::from([0x90, 0x01, 0x02]);
        assert_eq!(resp.status(), Status::Success);
        assert_eq!(resp.data(), &[0x90, 0x01, 0x02]);
        assert!(matches!(resp.into_inner(), ApduResponse::Data(_)));
    }
}
