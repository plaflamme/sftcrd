use sftcrd_tlv::{ConstLength, DecodeError, EncodeError, ValueDecoder, ValueEncoder};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetiredIndex(u8);

impl RetiredIndex {
    /// Returns the retired slot's value in 0..20
    pub(crate) const fn value(self) -> u8 {
        self.0
    }

    const fn from_u8(value: u8) -> Self {
        Self(value - 0x82)
    }

    const fn into_u8(self) -> u8 {
        self.0 + 0x82
    }
}

/// The four PIV asymmetric key slots, identified by their key reference and the
/// certificate data object that holds the slot's X.509 certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// `9A` — PIV Authentication.
    Authentication,
    /// `9C` — Digital Signature.
    Signature,
    /// `9D` — Key Management (decryption).
    KeyManagement,
    /// `9E` — Card Authentication.
    CardAuthentication,
    /// Yubico retired key-management slots (fw 5.7+). 0x82..=0x95 (represented as Retired(0..20))
    Retired(RetiredIndex),
}

impl Slot {
    /// The key-reference byte (`9A`/`9C`/`9D`/`9E`, or `82`..=`95` for retired).
    #[must_use]
    pub const fn into_u8(self) -> u8 {
        match self {
            Slot::Authentication => 0x9A,
            Slot::Signature => 0x9C,
            Slot::KeyManagement => 0x9D,
            Slot::CardAuthentication => 0x9E,
            Slot::Retired(n) => n.into_u8(),
        }
    }

    /// Checked constructor for a retired slot: `Some` for n in 1..=20, else `None`.
    /// All retired-slot construction must go through here so an invalid ref can
    /// never be built.
    #[must_use]
    pub(crate) fn retired(n: u8) -> Option<Slot> {
        if (1..=20).contains(&n) {
            Some(Self::Retired(RetiredIndex(n - 1)))
        } else {
            None
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x9A => Some(Self::Authentication),
            0x9C => Some(Self::Signature),
            0x9D => Some(Self::KeyManagement),
            0x9E => Some(Self::CardAuthentication),
            0x82..=0x95 => Some(Self::Retired(RetiredIndex::from_u8(value))),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn all() -> impl Iterator<Item = Slot> {
        let named = [
            Self::Authentication,
            Self::Signature,
            Self::KeyManagement,
            Self::CardAuthentication,
        ];
        let retired = (1..=20).filter_map(Slot::retired);
        std::iter::chain(named, retired)
    }
}

/// Management-key (9B) cipher algorithm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MgmtAlg {
    /// 3DES (TDEA) — pre-5.7 `YubiKey` default; 24-byte key, 8-byte block.
    TripleDes = 0x03,
    /// AES-128 — 16-byte key, 16-byte block.
    Aes128 = 0x08,
    /// AES-192 — 24-byte key, 16-byte block; the `YubiKey` 5.7+ default.
    Aes192 = 0x0A,
    /// AES-256 — 32-byte key, 16-byte block.
    Aes256 = 0x0C,
}

impl MgmtAlg {
    pub(crate) fn key_len(self) -> usize {
        #[allow(clippy::match_same_arms)]
        match self {
            MgmtAlg::TripleDes => 24,
            MgmtAlg::Aes128 => 16,
            MgmtAlg::Aes192 => 24,
            MgmtAlg::Aes256 => 32,
        }
    }

    pub(crate) fn block_size(self) -> usize {
        match self {
            MgmtAlg::TripleDes => 8,
            MgmtAlg::Aes128 | MgmtAlg::Aes192 | Self::Aes256 => 16,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x03 => Some(Self::TripleDes),
            0x08 => Some(Self::Aes128),
            0x0A => Some(Self::Aes192),
            0x0C => Some(Self::Aes256),
            _ => None,
        }
    }
}

pub use sftcrd_key::RsaBits;

/// PIV wire-format wrapper for [`sftcrd_key::KeyAlg`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PivKeyAlg(pub sftcrd_key::KeyAlg);

impl PivKeyAlg {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x06 => Some(Self(sftcrd_key::KeyAlg::Rsa(RsaBits::Rsa1024))),
            0x07 => Some(Self(sftcrd_key::KeyAlg::Rsa(RsaBits::Rsa2048))),
            0x05 => Some(Self(sftcrd_key::KeyAlg::Rsa(RsaBits::Rsa3072))),
            0x16 => Some(Self(sftcrd_key::KeyAlg::Rsa(RsaBits::Rsa4096))),
            0x11 => Some(Self(sftcrd_key::KeyAlg::P256)),
            0x14 => Some(Self(sftcrd_key::KeyAlg::P384)),
            0x15 => Some(Self(sftcrd_key::KeyAlg::P521)),
            0xE0 => Some(Self(sftcrd_key::KeyAlg::Ed25519)),
            0xE1 => Some(Self(sftcrd_key::KeyAlg::X25519)),
            _ => None,
        }
    }

    pub(crate) fn into_u8(self) -> u8 {
        match self.0 {
            sftcrd_key::KeyAlg::Rsa(RsaBits::Rsa1024) => 0x06,
            sftcrd_key::KeyAlg::Rsa(RsaBits::Rsa2048) => 0x07,
            sftcrd_key::KeyAlg::Rsa(RsaBits::Rsa3072) => 0x05,
            sftcrd_key::KeyAlg::Rsa(RsaBits::Rsa4096) => 0x16,
            sftcrd_key::KeyAlg::P256 => 0x11,
            sftcrd_key::KeyAlg::P384 => 0x14,
            sftcrd_key::KeyAlg::P521 => 0x15,
            sftcrd_key::KeyAlg::Ed25519 => 0xE0,
            sftcrd_key::KeyAlg::X25519 => 0xE1,
        }
    }
}

impl ValueDecoder<'_> for PivKeyAlg {
    fn decode(bytes: &[u8]) -> Result<Self, sftcrd_tlv::DecodeError> {
        u8::decode(bytes)
            .and_then(|value| Self::from_u8(value).ok_or(sftcrd_tlv::DecodeError::InvalidValue))
    }
}

impl ValueEncoder for PivKeyAlg {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        buf[0] = self.into_u8();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinPolicy {
    Never = 0x01,
    Once = 0x02,
    Always = 0x03,
}

impl PinPolicy {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Never),
            0x02 => Some(Self::Once),
            0x03 => Some(Self::Always),
            _ => None,
        }
    }
}

impl TryFrom<u8> for PinPolicy {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        PinPolicy::from_u8(value).ok_or(())
    }
}

impl ValueDecoder<'_> for PinPolicy {
    fn decode(bytes: &'_ [u8]) -> Result<Self, sftcrd_tlv::DecodeError> {
        PinPolicy::try_from(u8::decode(bytes)?).map_err(|()| sftcrd_tlv::DecodeError::InvalidValue)
    }
}

impl ConstLength for PinPolicy {
    const LENGTH: usize = 1;
}

impl ValueEncoder for PinPolicy {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        buf[0] = *self as u8;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchPolicy {
    Never = 0x01,
    Always = 0x02,
    Cached = 0x03,
}

impl TouchPolicy {
    pub(crate) fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Never),
            0x02 => Some(Self::Always),
            0x03 => Some(Self::Cached),
            _ => None,
        }
    }
}

impl TryFrom<u8> for TouchPolicy {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        TouchPolicy::from_u8(value).ok_or(())
    }
}

impl ValueDecoder<'_> for TouchPolicy {
    fn decode(bytes: &'_ [u8]) -> Result<Self, sftcrd_tlv::DecodeError> {
        TouchPolicy::try_from(u8::decode(bytes)?)
            .map_err(|()| sftcrd_tlv::DecodeError::InvalidValue)
    }
}

impl ConstLength for TouchPolicy {
    const LENGTH: usize = 1;
}

impl ValueEncoder for TouchPolicy {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        buf[0] = *self as u8;
        Ok(())
    }
}

/// Pin and Touch policies can be set to their "default" state.
/// But the "default" member is only ever used when writing the policy to the slot.
/// So instead of adding "Default" members to those enums, we use this type which can represent the default value
/// only when writing the policies. This eliminates the need to handle the "default" member later on when using the policies.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub enum Defaultable<T> {
    #[default]
    Default,
    Specified(T),
}

impl<T> TryFrom<u8> for Defaultable<T>
where
    T: TryFrom<u8>,
    (): std::convert::From<<T as std::convert::TryFrom<u8>>::Error>,
{
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Defaultable::Default),
            value => Ok(T::try_from(value).map(Defaultable::Specified)?),
        }
    }
}

impl<'a, T> ValueDecoder<'a> for Defaultable<T>
where
    T: TryFrom<u8>,
    (): std::convert::From<<T as std::convert::TryFrom<u8>>::Error>,
{
    fn decode(bytes: &'a [u8]) -> Result<Self, sftcrd_tlv::DecodeError> {
        match u8::decode(bytes) {
            Ok(value) => Ok(Self::try_from(value).map_err(|()| DecodeError::InvalidValue)?),
            Err(_) => Err(DecodeError::InvalidValue),
        }
    }
}

impl<T> ValueEncoder for Defaultable<T>
where
    T: ValueEncoder,
{
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        match self {
            Defaultable::Default => buf[0] = 0x00,
            Defaultable::Specified(value) => value.encode(buf)?,
        }
        Ok(())
    }
}
