//! Protocol-agnostic asymmetric slot keys and cryptographic operations for `sftcrd` applets.

mod pem;

use core::fmt;

use ecdsa::{DigestAlgorithm, SignatureEncoding as _, signature::hazmat::PrehashSigner};
use ed25519_dalek::Signer as _;
use elliptic_curve::{Generate as _, ecdh::diffie_hellman};
use rsa::{
    BoxedUint, Pkcs1v15Encrypt, Pkcs1v15Sign,
    hazmat::rsa_decrypt,
    traits::{PrivateKeyParts as _, PublicKeyParts as _},
};

/// Supported RSA modulus bit widths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RsaBits {
    /// 1024-bit RSA.
    Rsa1024 = 1024,
    /// 2048-bit RSA.
    Rsa2048 = 2048,
    /// 3072-bit RSA.
    Rsa3072 = 3072,
    /// 4096-bit RSA.
    Rsa4096 = 4096,
}

impl RsaBits {
    /// Convert a bit width to [`RsaBits`], returning `None` if unsupported.
    #[must_use]
    pub const fn from_u16(bits: u16) -> Option<Self> {
        match bits {
            1024 => Some(Self::Rsa1024),
            2048 => Some(Self::Rsa2048),
            3072 => Some(Self::Rsa3072),
            4096 => Some(Self::Rsa4096),
            _ => None,
        }
    }

    /// Return the modulus size in bytes.
    #[must_use]
    pub const fn modulus_bytes(self) -> usize {
        (self as usize) / 8
    }
}

/// Asymmetric key algorithm supported by [`SlotKey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlg {
    /// RSA with the given modulus size.
    Rsa(RsaBits),
    /// NIST P-256 (`secp256r1`).
    P256,
    /// NIST P-384 (`secp384r1`).
    P384,
    /// NIST P-521 (`secp521r1`).
    P521,
    /// Ed25519 (`EdDSA`).
    Ed25519,
    /// X25519 (ECDH).
    X25519,
}

/// Public key material extracted from a [`SlotKey`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// Uncompressed SEC1 EC point (NIST curves) or 32-byte raw key (Ed25519 / X25519).
    Point(Vec<u8>),
    /// RSA public key modulus `n` and public exponent `e` (big-endian bytes).
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

/// Output encoding for ECDSA signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaFormat {
    /// Fixed-width `r || s` concatenation (used by `OpenPGP`).
    Raw,
    /// ASN.1 DER `SEQUENCE { r INTEGER, s INTEGER }` (used by PIV).
    Der,
}

/// Mode for RSA signing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaSignMode {
    /// Apply EMSA-PKCS1-v1_5 type-1 padding to `data` and compute the signature (`OpenPGP`).
    Pkcs1v15,
    /// Raw RSA CRT operation on a full-modulus-width pre-encoded block (PIV).
    Raw,
}

/// Typed error returned by [`SlotKey`] operations so each applet can map
/// failures to its own ISO 7816 `Status` or config error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Input length does not match the key or algorithm requirements.
    InvalidLength,
    /// Input data, key material, or cryptographic parameters are invalid.
    InvalidData,
    /// Invalid data with a human-readable detail message (typically from PEM/DER parsing).
    InvalidDataWithMsg(String),
    /// Requested operation is not supported by this key type.
    UnsupportedOperation,
    /// Key generation or cryptographic backend failure.
    CryptoFailure,
    /// PEM decoding error.
    Pem(String),
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => f.write_str("invalid input length"),
            Self::InvalidData => f.write_str("invalid key data or parameters"),
            Self::InvalidDataWithMsg(msg) | Self::Pem(msg) => f.write_str(msg),
            Self::UnsupportedOperation => f.write_str("operation not supported for this key type"),
            Self::CryptoFailure => f.write_str("cryptographic operation failed"),
        }
    }
}

impl std::error::Error for KeyError {}

/// Asymmetric private key material held in an applet key slot.
pub enum SlotKey {
    /// RSA private key.
    Rsa(rsa::PrivateKey),
    /// NIST P-256 private key.
    P256(elliptic_curve::SecretKey<p256::NistP256>),
    /// NIST P-384 private key.
    P384(elliptic_curve::SecretKey<p384::NistP384>),
    /// NIST P-521 private key.
    P521(elliptic_curve::SecretKey<p521::NistP521>),
    /// Ed25519 signing key.
    Ed25519(ed25519_dalek::SigningKey),
    /// X25519 static secret.
    X25519(x25519_dalek::StaticSecret),
}

impl fmt::Debug for SlotKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa(key) => write!(f, "SlotKey::Rsa({})", key.n().bits_precision()),
            Self::P256(_) => f.write_str("SlotKey::P256"),
            Self::P384(_) => f.write_str("SlotKey::P384"),
            Self::P521(_) => f.write_str("SlotKey::P521"),
            Self::Ed25519(_) => f.write_str("SlotKey::Ed25519"),
            Self::X25519(_) => f.write_str("SlotKey::X25519"),
        }
    }
}

impl SlotKey {
    /// Generate a fresh key pair for `alg`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::CryptoFailure`] if RSA key generation fails.
    pub fn generate(alg: KeyAlg) -> Result<Self, KeyError> {
        match alg {
            KeyAlg::Rsa(bits) => {
                let key = rsa::PrivateKey::new(&mut rand::rng(), bits as usize)
                    .map_err(|_| KeyError::CryptoFailure)?;
                Ok(Self::Rsa(key))
            }
            KeyAlg::P256 => Ok(Self::P256(
                elliptic_curve::SecretKey::<p256::NistP256>::generate_from_rng(&mut rand::rng()),
            )),
            KeyAlg::P384 => Ok(Self::P384(
                elliptic_curve::SecretKey::<p384::NistP384>::generate_from_rng(&mut rand::rng()),
            )),
            KeyAlg::P521 => Ok(Self::P521(
                elliptic_curve::SecretKey::<p521::NistP521>::generate_from_rng(&mut rand::rng()),
            )),
            KeyAlg::Ed25519 => Ok(Self::Ed25519(ed25519_dalek::SigningKey::generate(
                &mut rand::rng(),
            ))),
            KeyAlg::X25519 => Ok(Self::X25519(x25519_dalek::StaticSecret::random_from_rng(
                &mut rand::rng(),
            ))),
        }
    }

    /// Return the [`KeyAlg`] corresponding to this key.
    ///
    /// # Panics
    ///
    /// Panics if an RSA key has a bit length other than 1024, 2048, 3072, or 4096.
    #[must_use]
    pub fn alg(&self) -> KeyAlg {
        match self {
            Self::Rsa(key) => {
                let bits = u16::try_from(key.n().bits_precision())
                    .ok()
                    .and_then(RsaBits::from_u16)
                    .expect("SlotKey::Rsa only holds supported RsaBits sizes");
                KeyAlg::Rsa(bits)
            }
            Self::P256(_) => KeyAlg::P256,
            Self::P384(_) => KeyAlg::P384,
            Self::P521(_) => KeyAlg::P521,
            Self::Ed25519(_) => KeyAlg::Ed25519,
            Self::X25519(_) => KeyAlg::X25519,
        }
    }

    /// Extract the public key material for this slot key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Rsa(key) => PublicKey::Rsa {
                n: key.n().to_be_bytes().to_vec(),
                e: key.e().to_be_bytes_trimmed_vartime().to_vec(),
            },
            Self::P256(secret) => PublicKey::Point(secret.public_key().to_sec1_bytes().to_vec()),
            Self::P384(secret) => PublicKey::Point(secret.public_key().to_sec1_bytes().to_vec()),
            Self::P521(secret) => PublicKey::Point(secret.public_key().to_sec1_bytes().to_vec()),
            Self::Ed25519(signing) => PublicKey::Point(signing.verifying_key().to_bytes().to_vec()),
            Self::X25519(secret) => {
                PublicKey::Point(x25519_dalek::PublicKey::from(secret).to_bytes().to_vec())
            }
        }
    }

    /// Encode the slot key's public material as an X.509 `SubjectPublicKeyInfo`.
    #[must_use]
    pub fn to_spki(&self) -> Option<x509_cert::SubjectPublicKeyInfo> {
        use rsa::pkcs8::EncodePublicKey as _;
        use x509_cert::der::Decode as _;

        match self {
            Self::P256(secret) => {
                x509_cert::SubjectPublicKeyInfo::from_key(&secret.public_key()).ok()
            }
            Self::P384(secret) => {
                x509_cert::SubjectPublicKeyInfo::from_key(&secret.public_key()).ok()
            }
            Self::P521(secret) => {
                x509_cert::SubjectPublicKeyInfo::from_key(&secret.public_key()).ok()
            }
            Self::Rsa(private_key) => {
                let der = private_key.to_public_key().to_public_key_der().ok()?;
                x509_cert::SubjectPublicKeyInfo::from_der(der.as_bytes()).ok()
            }
            Self::Ed25519(_) | Self::X25519(_) => {
                let PublicKey::Point(bytes) = self.public_key() else {
                    return None;
                };
                let oid = match self {
                    Self::Ed25519(_) => pem::OID_ED25519,
                    Self::X25519(_) => pem::OID_X25519,
                    _ => return None,
                };
                let subject_public_key =
                    x509_cert::der::asn1::BitString::from_bytes(&bytes).ok()?;
                Some(x509_cert::SubjectPublicKeyInfo {
                    algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
                        oid,
                        parameters: None,
                    },
                    subject_public_key,
                })
            }
        }
    }

    /// Sign `data` using this slot key.
    ///
    /// - RSA: either applies EMSA-PKCS1-v1_5 padding ([`RsaSignMode::Pkcs1v15`]) or
    ///   runs the raw CRT operation ([`RsaSignMode::Raw`]).
    /// - NIST P-256/P-384/P-521: signs pre-hashed `data` (allowing 64-byte SHA-512
    ///   left-padded to 66 bytes for P-521) and encodes as [`EcdsaFormat::Raw`] or
    ///   [`EcdsaFormat::Der`].
    /// - Ed25519: signs `data` and returns the 64-byte `R || S` signature.
    /// - X25519: returns [`KeyError::UnsupportedOperation`].
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::InvalidLength`] for mismatched input sizes,
    /// [`KeyError::UnsupportedOperation`] for X25519, or [`KeyError::InvalidData`] /
    /// [`KeyError::CryptoFailure`] on invalid inputs or backend errors.
    pub fn sign(
        &self,
        data: &[u8],
        rsa_mode: RsaSignMode,
        ecdsa_format: EcdsaFormat,
    ) -> Result<Vec<u8>, KeyError> {
        match self {
            Self::Rsa(key) => match rsa_mode {
                RsaSignMode::Pkcs1v15 => {
                    if data.is_empty() || data.len() + 11 > key.size() {
                        return Err(KeyError::InvalidLength);
                    }
                    key.sign(Pkcs1v15Sign::new_unprefixed(), data)
                        .map_err(|_| KeyError::InvalidData)
                }
                RsaSignMode::Raw => rsa_raw_crt(key, data),
            },
            Self::P256(secret) => {
                let sig = sign_ecdsa::<p256::NistP256>(secret, data, false)?;
                Ok(encode_ecdsa_sig(&sig, ecdsa_format))
            }
            Self::P384(secret) => {
                let sig = sign_ecdsa::<p384::NistP384>(secret, data, false)?;
                Ok(encode_ecdsa_sig(&sig, ecdsa_format))
            }
            Self::P521(secret) => {
                let sig = sign_ecdsa::<p521::NistP521>(secret, data, true)?;
                Ok(encode_ecdsa_sig(&sig, ecdsa_format))
            }
            Self::Ed25519(signing_key) => Ok(signing_key.sign(data).to_bytes().to_vec()),
            Self::X25519(_) => Err(KeyError::UnsupportedOperation),
        }
    }

    /// Decrypt a PKCS#1 v1.5 RSA ciphertext block.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::UnsupportedOperation`] for non-RSA keys,
    /// [`KeyError::InvalidLength`] if `ciphertext.len() != modulus_bytes`, or
    /// [`KeyError::InvalidData`] if decryption fails.
    pub fn decrypt_rsa_pkcs1v15(&self, ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let Self::Rsa(key) = self else {
            return Err(KeyError::UnsupportedOperation);
        };
        if ciphertext.len() != key.size() {
            return Err(KeyError::InvalidLength);
        }
        key.decrypt(Pkcs1v15Encrypt, ciphertext)
            .map_err(|_| KeyError::InvalidData)
    }

    /// Perform ECDH / X25519 key agreement against `peer` public key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::UnsupportedOperation`] for RSA and Ed25519 keys, or
    /// [`KeyError::InvalidData`] if the peer key is malformed or non-contributory.
    pub fn ecdh(&self, peer: &[u8]) -> Result<Vec<u8>, KeyError> {
        match self {
            Self::P256(secret) => ecdh_curve::<p256::NistP256>(secret, peer),
            Self::P384(secret) => ecdh_curve::<p384::NistP384>(secret, peer),
            Self::P521(secret) => ecdh_curve::<p521::NistP521>(secret, peer),
            Self::X25519(secret) => {
                let peer_bytes: [u8; 32] = peer.try_into().map_err(|_| KeyError::InvalidData)?;
                let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer_bytes));
                if !shared.was_contributory() {
                    return Err(KeyError::InvalidData);
                }
                Ok(shared.as_bytes().to_vec())
            }
            Self::Rsa(_) | Self::Ed25519(_) => Err(KeyError::UnsupportedOperation),
        }
    }

    /// Import an EC / Ed25519 / X25519 private key from raw scalar/seed bytes,
    /// optionally verifying that the derived public key matches `expected_public`.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::UnsupportedOperation`] for [`KeyAlg::Rsa`], or
    /// [`KeyError::InvalidData`] if the scalar/seed is invalid or does not match
    /// `expected_public`.
    pub fn from_ec_scalar(
        alg: KeyAlg,
        scalar: &[u8],
        expected_public: Option<&[u8]>,
    ) -> Result<Self, KeyError> {
        match alg {
            KeyAlg::P256 => {
                let secret = elliptic_curve::SecretKey::<p256::NistP256>::from_slice(scalar)
                    .map_err(|_| KeyError::InvalidData)?;
                if expected_public.is_some_and(|p| p != secret.public_key().to_sec1_bytes().as_ref())
                {
                    return Err(KeyError::InvalidData);
                }
                Ok(Self::P256(secret))
            }
            KeyAlg::P384 => {
                let secret = elliptic_curve::SecretKey::<p384::NistP384>::from_slice(scalar)
                    .map_err(|_| KeyError::InvalidData)?;
                if expected_public.is_some_and(|p| p != secret.public_key().to_sec1_bytes().as_ref())
                {
                    return Err(KeyError::InvalidData);
                }
                Ok(Self::P384(secret))
            }
            KeyAlg::P521 => {
                let secret = elliptic_curve::SecretKey::<p521::NistP521>::from_slice(scalar)
                    .map_err(|_| KeyError::InvalidData)?;
                if expected_public.is_some_and(|p| p != secret.public_key().to_sec1_bytes().as_ref())
                {
                    return Err(KeyError::InvalidData);
                }
                Ok(Self::P521(secret))
            }
            KeyAlg::Ed25519 => {
                let seed: [u8; 32] = scalar.try_into().map_err(|_| KeyError::InvalidData)?;
                let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
                if expected_public.is_some_and(|p| p != signing.verifying_key().as_bytes()) {
                    return Err(KeyError::InvalidData);
                }
                Ok(Self::Ed25519(signing))
            }
            KeyAlg::X25519 => {
                let raw: [u8; 32] = scalar.try_into().map_err(|_| KeyError::InvalidData)?;
                let secret = x25519_dalek::StaticSecret::from(raw);
                if expected_public
                    .is_some_and(|p| p != x25519_dalek::PublicKey::from(&secret).to_bytes())
                {
                    return Err(KeyError::InvalidData);
                }
                Ok(Self::X25519(secret))
            }
            KeyAlg::Rsa(_) => Err(KeyError::UnsupportedOperation),
        }
    }

    /// Reconstruct and validate an RSA private key from primes `p`, `q`, public
    /// exponent `e`, and optional `n`, `dP`, `dQ` consistency checks.
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::InvalidData`] if the primes, exponent, modulus size,
    /// or optional CRT consistency checks fail.
    pub fn from_rsa_components(
        bits: RsaBits,
        p: &[u8],
        q: &[u8],
        e: &[u8],
        n: Option<&[u8]>,
        dp: Option<&[u8]>,
        dq: Option<&[u8]>,
    ) -> Result<Self, KeyError> {
        if p.is_empty() || q.is_empty() || e.is_empty() {
            return Err(KeyError::InvalidData);
        }
        let mut key = rsa::PrivateKey::from_p_q(
            BoxedUint::from_be_slice_vartime(p),
            BoxedUint::from_be_slice_vartime(q),
            BoxedUint::from_be_slice_vartime(e),
        )
        .map_err(|_| KeyError::InvalidData)?;

        if key.n().to_be_bytes().len() != bits.modulus_bytes() {
            return Err(KeyError::InvalidData);
        }
        key.precompute().map_err(|_| KeyError::InvalidData)?;

        if let Some(n_bytes) = n
            && (n_bytes.is_empty()
                || key.n().clone().get() != BoxedUint::from_be_slice_vartime(n_bytes))
        {
            return Err(KeyError::InvalidData);
        }
        if let Some(dp_bytes) = dp
            && (dp_bytes.is_empty() || key.dp() != Some(&BoxedUint::from_be_slice_vartime(dp_bytes)))
        {
            return Err(KeyError::InvalidData);
        }
        if let Some(dq_bytes) = dq
            && (dq_bytes.is_empty() || key.dq() != Some(&BoxedUint::from_be_slice_vartime(dq_bytes)))
        {
            return Err(KeyError::InvalidData);
        }

        Ok(Self::Rsa(key))
    }
}

fn rsa_raw_crt(key: &rsa::PrivateKey, block: &[u8]) -> Result<Vec<u8>, KeyError> {
    let n = key.n().to_be_bytes();
    if block.len() != n.len() {
        return Err(KeyError::InvalidLength);
    }
    let c = BoxedUint::from_be_slice_vartime(block);
    if c >= key.n().clone().get() {
        return Err(KeyError::InvalidData);
    }
    let m = rsa_decrypt::<rand::rngs::SysRng>(None, key, &c).map_err(|_| KeyError::InvalidData)?;
    let m_be = m.to_be_bytes();
    let mut out = vec![0u8; n.len()];
    let offset = n.len() - m_be.len();
    out[offset..].copy_from_slice(&m_be);
    Ok(out)
}

fn sign_ecdsa<C>(
    secret: &elliptic_curve::SecretKey<C>,
    digest: &[u8],
    allow_64_byte_p521: bool,
) -> Result<ecdsa::Signature<C>, KeyError>
where
    C: elliptic_curve::CurveArithmetic + DigestAlgorithm,
    ecdsa::SigningKey<C>: PrehashSigner<ecdsa::Signature<C>>,
{
    let field_len = size_of::<elliptic_curve::FieldBytes<C>>();
    let padded;
    let prehash = if allow_64_byte_p521 && digest.len() == 64 && field_len == 66 {
        padded = [&[0x00, 0x00], digest].concat();
        padded.as_slice()
    } else if digest.len() == field_len {
        digest
    } else {
        return Err(KeyError::InvalidLength);
    };

    let signing_key = ecdsa::SigningKey::<C>::from(secret);
    signing_key
        .sign_prehash(prehash)
        .map_err(|_| KeyError::InvalidData)
}

fn encode_ecdsa_sig<C>(sig: &ecdsa::Signature<C>, format: EcdsaFormat) -> Vec<u8>
where
    C: ecdsa::EcdsaCurve,
    ecdsa::SignatureSize<C>: core::ops::Add<ecdsa::der::MaxOverhead> + elliptic_curve::array::ArraySize,
    ecdsa::der::MaxSize<C>: elliptic_curve::array::ArraySize,
    ecdsa::Signature<C>: ecdsa::SignatureEncoding,
    ecdsa::der::Signature<C>: ecdsa::SignatureEncoding,
{
    match format {
        EcdsaFormat::Raw => sig.to_vec(),
        EcdsaFormat::Der => sig.to_der().to_vec(),
    }
}

fn ecdh_curve<C>(secret: &elliptic_curve::SecretKey<C>, peer: &[u8]) -> Result<Vec<u8>, KeyError>
where
    C: elliptic_curve::CurveArithmetic,
    C::AffinePoint:
        elliptic_curve::sec1::FromSec1Point<C> + elliptic_curve::sec1::ToSec1Point<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let peer = elliptic_curve::PublicKey::<C>::from_sec1_bytes(peer)
        .map_err(|_| KeyError::InvalidData)?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Ok(shared.raw_secret_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use ecdsa::signature::hazmat::PrehashVerifier as _;
    use elliptic_curve::Generate as _;
    use rsa::{BoxedUint, traits::PublicKeyParts as _};

    use super::{EcdsaFormat, KeyAlg, KeyError, RsaBits, RsaSignMode, SlotKey};

    #[test]
    fn slot_key_sign_and_decrypt_rsa() {
        let slot_key = SlotKey::generate(KeyAlg::Rsa(RsaBits::Rsa2048)).unwrap();
        let SlotKey::Rsa(ref rsa_key) = slot_key else {
            panic!("expected RSA key");
        };
        let pub_key = rsa_key.to_public_key();
        let k = pub_key.size();

        // PKCS#1 v1.5 signing
        let digest_info = [0x42u8; 32];
        let sig = slot_key
            .sign(&digest_info, RsaSignMode::Pkcs1v15, EcdsaFormat::Raw)
            .unwrap();
        assert_eq!(sig.len(), k);
        let em = rsa::hazmat::rsa_encrypt(&pub_key, &BoxedUint::from_be_slice_vartime(&sig))
            .unwrap()
            .to_be_bytes();
        assert_eq!(em.len(), k);
        assert_eq!(em[0], 0x00);
        assert_eq!(em[1], 0x01);
        let ps_len = k - digest_info.len() - 3;
        assert!(em[2..2 + ps_len].iter().all(|&b| b == 0xFF));
        assert_eq!(em[2 + ps_len], 0x00);
        assert_eq!(&em[2 + ps_len + 1..], &digest_info);

        // Raw RSA CRT signing
        let mut raw_block = vec![0x11u8; k];
        raw_block[0] = 0x00;
        let raw_sig = slot_key
            .sign(&raw_block, RsaSignMode::Raw, EcdsaFormat::Der)
            .unwrap();
        assert_eq!(raw_sig.len(), k);
        let recovered =
            rsa::hazmat::rsa_encrypt(&pub_key, &BoxedUint::from_be_slice_vartime(&raw_sig))
                .unwrap()
                .to_be_bytes();
        assert_eq!(recovered.as_ref(), &raw_block[..]);

        // Decrypt PKCS#1 v1.5 ciphertext block
        let plaintext = b"slot-key-rsa-decipher";
        let pad_len = k - plaintext.len() - 3;
        let mut block = Vec::with_capacity(k);
        block.extend_from_slice(&[0x00, 0x02]);
        block.resize(2 + pad_len, 0xA5);
        block.push(0x00);
        block.extend_from_slice(plaintext);
        let ct = rsa::hazmat::rsa_encrypt(&pub_key, &BoxedUint::from_be_slice_vartime(&block))
            .unwrap()
            .to_be_bytes();
        assert_eq!(slot_key.decrypt_rsa_pkcs1v15(&ct).unwrap(), plaintext);

        // Error cases
        assert_eq!(
            slot_key
                .sign(&[], RsaSignMode::Pkcs1v15, EcdsaFormat::Raw)
                .unwrap_err(),
            KeyError::InvalidLength
        );
        assert_eq!(
            slot_key.decrypt_rsa_pkcs1v15(&[0x01]).unwrap_err(),
            KeyError::InvalidLength
        );
        assert_eq!(
            slot_key.ecdh(&[0u8; 32]).unwrap_err(),
            KeyError::UnsupportedOperation
        );
    }

    #[test]
    fn slot_key_sign_and_ecdh_nist_curves() {
        // P-256 (Raw + DER)
        let p256_key = SlotKey::generate(KeyAlg::P256).unwrap();
        let SlotKey::P256(ref secret) = p256_key else {
            panic!("expected P-256 key");
        };
        let digest = [0x11u8; 32];
        let sig_raw = p256_key
            .sign(&digest, RsaSignMode::Pkcs1v15, EcdsaFormat::Raw)
            .unwrap();
        assert_eq!(sig_raw.len(), 64);
        p256::ecdsa::VerifyingKey::from(secret.public_key())
            .verify_prehash(
                &digest,
                &p256::ecdsa::Signature::from_slice(&sig_raw).unwrap(),
            )
            .unwrap();
        let sig_der = p256_key
            .sign(&digest, RsaSignMode::Raw, EcdsaFormat::Der)
            .unwrap();
        p256::ecdsa::VerifyingKey::from(secret.public_key())
            .verify_prehash(
                &digest,
                &p256::ecdsa::Signature::from_der(&sig_der).unwrap(),
            )
            .unwrap();

        let eph = p256::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
        let expected = eph.diffie_hellman(&secret.public_key());
        let shared = p256_key.ecdh(&eph.public_key().to_sec1_bytes()).unwrap();
        assert_eq!(shared, expected.raw_secret_bytes().as_slice());

        // P-384
        let p384_key = SlotKey::generate(KeyAlg::P384).unwrap();
        let SlotKey::P384(ref secret) = p384_key else {
            panic!("expected P-384 key");
        };
        let digest = [0x22u8; 48];
        let sig = p384_key
            .sign(&digest, RsaSignMode::Pkcs1v15, EcdsaFormat::Raw)
            .unwrap();
        assert_eq!(sig.len(), 96);
        p384::ecdsa::VerifyingKey::from(secret.public_key())
            .verify_prehash(&digest, &p384::ecdsa::Signature::from_slice(&sig).unwrap())
            .unwrap();

        // P-521 (64-byte SHA-512 and 66-byte field width)
        let p521_key = SlotKey::generate(KeyAlg::P521).unwrap();
        let SlotKey::P521(ref secret) = p521_key else {
            panic!("expected P-521 key");
        };
        let sha512 = [0x33u8; 64];
        let sig64 = p521_key
            .sign(&sha512, RsaSignMode::Pkcs1v15, EcdsaFormat::Raw)
            .unwrap();
        assert_eq!(sig64.len(), 132);
        let padded = [&[0x00, 0x00], sha512.as_slice()].concat();
        p521::ecdsa::VerifyingKey::from(secret.public_key())
            .verify_prehash(
                &padded,
                &p521::ecdsa::Signature::from_slice(&sig64).unwrap(),
            )
            .unwrap();
        assert_eq!(
            p521_key
                .sign(&[0u8; 32], RsaSignMode::Pkcs1v15, EcdsaFormat::Raw)
                .unwrap_err(),
            KeyError::InvalidLength
        );
    }

    #[test]
    fn slot_key_ed25519_and_x25519() {
        let ed_key = SlotKey::generate(KeyAlg::Ed25519).unwrap();
        let SlotKey::Ed25519(ref signing) = ed_key else {
            panic!("expected Ed25519 key");
        };
        let msg = b"slot-key-ed25519";
        let sig = ed_key
            .sign(msg, RsaSignMode::Pkcs1v15, EcdsaFormat::Raw)
            .unwrap();
        assert_eq!(sig.len(), 64);
        signing
            .verifying_key()
            .verify_strict(msg, &ed25519_dalek::Signature::from_slice(&sig).unwrap())
            .unwrap();
        assert_eq!(
            ed_key.ecdh(&[0u8; 32]).unwrap_err(),
            KeyError::UnsupportedOperation
        );

        let x_key = SlotKey::generate(KeyAlg::X25519).unwrap();
        let SlotKey::X25519(ref secret) = x_key else {
            panic!("expected X25519 key");
        };
        let eph = x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::rng());
        let eph_pub = x25519_dalek::PublicKey::from(&eph);
        let expected = eph.diffie_hellman(&x25519_dalek::PublicKey::from(secret));
        let shared = x_key.ecdh(eph_pub.as_bytes()).unwrap();
        assert_eq!(shared, expected.as_bytes());
        assert_eq!(
            x_key
                .sign(msg, RsaSignMode::Pkcs1v15, EcdsaFormat::Raw)
                .unwrap_err(),
            KeyError::UnsupportedOperation
        );
        assert_eq!(x_key.ecdh(&[0u8; 31]).unwrap_err(), KeyError::InvalidData);
    }
}
