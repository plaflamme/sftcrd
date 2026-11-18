//! PEM, PKCS#8, PKCS#1, and SEC1 private key parsing.

use pkcs8::DecodePrivateKey as _;
use rsa::{pkcs1::DecodeRsaPrivateKey as _, traits::PublicKeyParts as _};

use crate::{KeyError, RsaBits, SlotKey};

/// OID for Ed25519 (`1.3.101.112`, RFC 8410).
pub(crate) const OID_ED25519: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112");

/// OID for X25519 (`1.3.101.110`, RFC 8410).
pub(crate) const OID_X25519: pkcs8::ObjectIdentifier =
    pkcs8::ObjectIdentifier::new_unwrap("1.3.101.110");

impl SlotKey {
    /// Parse a PEM-encoded private key (`PRIVATE KEY`, `RSA PRIVATE KEY`, or `EC PRIVATE KEY`).
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::Pem`] if PEM decoding fails, or [`KeyError::InvalidData`] if the
    /// PEM label or inner DER key material is unsupported or malformed.
    pub fn from_pem(pem_str: &str) -> Result<Self, KeyError> {
        let (label, der) =
            pem_rfc7468::decode_vec(pem_str.as_bytes()).map_err(|e| KeyError::Pem(e.to_string()))?;

        match label {
            "PRIVATE KEY" => Self::from_pkcs8_der(&der),
            "RSA PRIVATE KEY" => Self::from_pkcs1_der(&der),
            "EC PRIVATE KEY" => Self::from_sec1_der(&der),
            other => Err(KeyError::InvalidDataWithMsg(format!(
                "unsupported PEM type '{other}', expected 'PRIVATE KEY', 'RSA PRIVATE KEY', or 'EC PRIVATE KEY'"
            ))),
        }
    }

    /// Parse a PKCS#8 DER-encoded private key (RSA, P-256, P-384, P-521, Ed25519, or X25519).
    ///
    /// # Errors
    ///
    /// Returns an error if the DER bytes are not a valid or supported PKCS#8 private key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, KeyError> {
        if let Ok(rsa_key) = rsa::PrivateKey::from_pkcs8_der(der) {
            validate_rsa_bits(&rsa_key)?;
            return Ok(Self::Rsa(rsa_key));
        }
        if let Ok(sk) = elliptic_curve::SecretKey::<p256::NistP256>::from_pkcs8_der(der) {
            return Ok(Self::P256(sk));
        }
        if let Ok(sk) = elliptic_curve::SecretKey::<p384::NistP384>::from_pkcs8_der(der) {
            return Ok(Self::P384(sk));
        }
        if let Ok(sk) = elliptic_curve::SecretKey::<p521::NistP521>::from_pkcs8_der(der) {
            return Ok(Self::P521(sk));
        }
        if let Ok(info) = pkcs8::PrivateKeyInfoRef::try_from(der) {
            if info.algorithm.oid == OID_ED25519 {
                let seed = unwrap_curve25519_octet_string(info.private_key.as_bytes())?;
                return Ok(Self::Ed25519(ed25519_dalek::SigningKey::from_bytes(&seed)));
            }
            if info.algorithm.oid == OID_X25519 {
                let raw = unwrap_curve25519_octet_string(info.private_key.as_bytes())?;
                return Ok(Self::X25519(x25519_dalek::StaticSecret::from(raw)));
            }
        }

        Err(KeyError::InvalidDataWithMsg(
            "failed to parse PKCS#8 private key as RSA, P-256, P-384, P-521, Ed25519, or X25519"
                .to_string(),
        ))
    }

    /// Parse a PKCS#1 DER-encoded RSA private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the DER bytes are not a valid PKCS#1 RSA private key.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, KeyError> {
        let rsa_key = rsa::PrivateKey::from_pkcs1_der(der)
            .map_err(|e| KeyError::InvalidDataWithMsg(format!("invalid PKCS#1 RSA private key: {e}")))?;
        validate_rsa_bits(&rsa_key)?;
        Ok(Self::Rsa(rsa_key))
    }

    /// Parse a SEC1 DER-encoded EC private key (P-256, P-384, or P-521).
    ///
    /// # Errors
    ///
    /// Returns an error if the DER bytes are not a valid SEC1 EC private key for a supported curve.
    pub fn from_sec1_der(der: &[u8]) -> Result<Self, KeyError> {
        if let Ok(sk) = elliptic_curve::SecretKey::<p256::NistP256>::from_sec1_der(der) {
            return Ok(Self::P256(sk));
        }
        if let Ok(sk) = elliptic_curve::SecretKey::<p384::NistP384>::from_sec1_der(der) {
            return Ok(Self::P384(sk));
        }
        if let Ok(sk) = elliptic_curve::SecretKey::<p521::NistP521>::from_sec1_der(der) {
            return Ok(Self::P521(sk));
        }

        Err(KeyError::InvalidDataWithMsg(
            "failed to parse SEC1 EC private key as P-256, P-384, or P-521".to_string(),
        ))
    }
}

fn validate_rsa_bits(rsa_key: &rsa::PrivateKey) -> Result<RsaBits, KeyError> {
    let bits = rsa_key.n().bits_precision();
    u16::try_from(bits)
        .ok()
        .and_then(RsaBits::from_u16)
        .ok_or_else(|| {
            KeyError::InvalidDataWithMsg(format!(
                "unsupported RSA key size {bits} bits (supported: 1024, 2048, 3072, 4096)"
            ))
        })
}

/// Unwrap RFC 8410 Curve25519 `CurvePrivateKey` (`OCTET STRING` of 32 bytes: `0x04 0x20 <32 bytes>`).
fn unwrap_curve25519_octet_string(bytes: &[u8]) -> Result<[u8; 32], KeyError> {
    if bytes.len() == 34 && bytes[0] == 0x04 && bytes[1] == 0x20 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes[2..]);
        Ok(out)
    } else {
        Err(KeyError::InvalidData)
    }
}

#[cfg(test)]
mod tests {
    use crate::{KeyAlg, KeyError, PublicKey, SlotKey};

    // RFC 8410 Section 7 Ed25519 test key (seed: 0xD4..=0x7F)
    const TEST_ED25519_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----";

    // X25519 PKCS#8 private key
    const TEST_X25519_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4
-----END PRIVATE KEY-----";

    #[test]
    fn parse_ed25519_and_x25519_pkcs8_pem() {
        let ed = SlotKey::from_pem(TEST_ED25519_PKCS8).expect("valid ed25519 pkcs8");
        assert_eq!(ed.alg(), KeyAlg::Ed25519);
        let PublicKey::Point(ed_pub) = ed.public_key() else {
            panic!("expected point");
        };
        assert_eq!(ed_pub.len(), 32);

        let x = SlotKey::from_pem(TEST_X25519_PKCS8).expect("valid x25519 pkcs8");
        assert_eq!(x.alg(), KeyAlg::X25519);
        let PublicKey::Point(x_pub) = x.public_key() else {
            panic!("expected point");
        };
        assert_eq!(x_pub.len(), 32);
    }

    #[test]
    fn parse_pem_rejects_unknown_label_and_bad_der() {
        let bad_label = "\
-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----";
        assert!(matches!(
            SlotKey::from_pem(bad_label),
            Err(KeyError::InvalidDataWithMsg(_))
        ));
        assert!(matches!(SlotKey::from_pem("not pem"), Err(KeyError::Pem(_))));
        assert!(matches!(
            SlotKey::from_pkcs8_der(&[0x30, 0x00]),
            Err(KeyError::InvalidDataWithMsg(_))
        ));
    }
}
