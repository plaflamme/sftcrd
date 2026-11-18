//! `OpenPGP` Card v3.4 key-slot types and cryptographic operations.

use ecdsa::{DigestAlgorithm, signature::hazmat::PrehashSigner};
use ed25519_dalek::Signer as _;
use elliptic_curve::Generate as _;
use iso7816::Status;
use rsa::{Pkcs1v15Encrypt, Pkcs1v15Sign, traits::PublicKeyParts as _};

use crate::pgp::RsaBits;

/// Resolved key-slot algorithm from `C1`/`C2`/`C3` algorithm attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotAlg {
    Rsa { n_bits: RsaBits, e_bits: u16 },
    P256,
    P384,
    P521,
    Ed25519,
    X25519,
}

/// Public key material extracted from a [`SlotKey`].
pub(crate) enum PublicKey {
    Point(Vec<u8>),
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

/// Asymmetric private key material held in an `OpenPGP` key slot.
pub(crate) enum SlotKey {
    Rsa(RsaBits, rsa::PrivateKey),
    P256(elliptic_curve::SecretKey<p256::NistP256>),
    P384(elliptic_curve::SecretKey<p384::NistP384>),
    P521(elliptic_curve::SecretKey<p521::NistP521>),
    Ed25519(ed25519_dalek::SigningKey),
    X25519(x25519_dalek::StaticSecret),
}

impl core::fmt::Debug for SlotKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Rsa(bits, _) => write!(f, "SlotKey::Rsa({})", *bits as u16),
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
    pub(crate) fn generate(alg: SlotAlg) -> Result<Self, Status> {
        match alg {
            SlotAlg::Rsa { n_bits, .. } => {
                let key = rsa::PrivateKey::new(&mut rand::rng(), n_bits as usize)
                    .map_err(|_| Status::IncorrectDataParameter)?;
                Ok(Self::Rsa(n_bits, key))
            }
            SlotAlg::P256 => Ok(Self::P256(
                elliptic_curve::SecretKey::<p256::NistP256>::generate_from_rng(&mut rand::rng()),
            )),
            SlotAlg::P384 => Ok(Self::P384(
                elliptic_curve::SecretKey::<p384::NistP384>::generate_from_rng(&mut rand::rng()),
            )),
            SlotAlg::P521 => Ok(Self::P521(
                elliptic_curve::SecretKey::<p521::NistP521>::generate_from_rng(&mut rand::rng()),
            )),
            SlotAlg::Ed25519 => Ok(Self::Ed25519(ed25519_dalek::SigningKey::generate(
                &mut rand::rng(),
            ))),
            SlotAlg::X25519 => Ok(Self::X25519(x25519_dalek::StaticSecret::random_from_rng(
                &mut rand::rng(),
            ))),
        }
    }

    /// Extract the public key material for this slot key.
    pub(crate) fn public_key(&self) -> PublicKey {
        match self {
            Self::Rsa(_, key) => PublicKey::Rsa {
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

    /// Sign `data` using this slot key (`PSO:CDS` or `INTERNAL AUTHENTICATE`).
    ///
    /// - RSA: applies EMSA-PKCS1-v1_5 type-1 padding to `data` (expected to be a
    ///   `DigestInfo` or raw hash) and computes the raw RSA signature.
    /// - NIST P-256/P-384/P-521: signs pre-hashed `data` and returns raw
    ///   fixed-width `r || s`.
    /// - Ed25519: signs `data` and returns the 64-byte `R || S` signature.
    pub(crate) fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Status> {
        match self {
            Self::Rsa(_, key) => {
                if data.is_empty() || data.len() + 11 > key.size() {
                    return Err(Status::WrongLength);
                }
                key.sign(Pkcs1v15Sign::new_unprefixed(), data)
                    .map_err(|_| Status::IncorrectDataParameter)
            }
            Self::P256(secret) => sign_ecdsa::<p256::NistP256>(secret, data, false),
            Self::P384(secret) => sign_ecdsa::<p384::NistP384>(secret, data, false),
            Self::P521(secret) => sign_ecdsa::<p521::NistP521>(secret, data, true),
            Self::Ed25519(signing_key) => Ok(signing_key.sign(data).to_bytes().to_vec()),
            Self::X25519(_) => Err(Status::ConditionsOfUseNotSatisfied),
        }
    }

    /// Decrypt a PKCS#1 v1.5 RSA ciphertext block (`PSO:DECIPHER`).
    pub(crate) fn decrypt_rsa(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Status> {
        let Self::Rsa(_, key) = self else {
            return Err(Status::ConditionsOfUseNotSatisfied);
        };
        if ciphertext.len() != key.size() {
            return Err(Status::WrongLength);
        }
        key.decrypt(Pkcs1v15Encrypt, ciphertext)
            .map_err(|_| Status::IncorrectDataParameter)
    }

    /// Perform ECDH key agreement against `peer` public point bytes (`PSO:DECIPHER`).
    pub(crate) fn ecdh(&self, peer: &[u8]) -> Result<Vec<u8>, Status> {
        match self {
            Self::P256(secret) => {
                let peer = elliptic_curve::PublicKey::<p256::NistP256>::from_sec1_bytes(peer)
                    .map_err(|_| Status::IncorrectDataParameter)?;
                let shared = elliptic_curve::ecdh::diffie_hellman(
                    secret.to_nonzero_scalar(),
                    peer.as_affine(),
                );
                Ok(shared.raw_secret_bytes().to_vec())
            }
            Self::P384(secret) => {
                let peer = elliptic_curve::PublicKey::<p384::NistP384>::from_sec1_bytes(peer)
                    .map_err(|_| Status::IncorrectDataParameter)?;
                let shared = elliptic_curve::ecdh::diffie_hellman(
                    secret.to_nonzero_scalar(),
                    peer.as_affine(),
                );
                Ok(shared.raw_secret_bytes().to_vec())
            }
            Self::P521(secret) => {
                let peer = elliptic_curve::PublicKey::<p521::NistP521>::from_sec1_bytes(peer)
                    .map_err(|_| Status::IncorrectDataParameter)?;
                let shared = elliptic_curve::ecdh::diffie_hellman(
                    secret.to_nonzero_scalar(),
                    peer.as_affine(),
                );
                Ok(shared.raw_secret_bytes().to_vec())
            }
            Self::X25519(secret) => {
                let Ok(peer_bytes) = <[u8; 32]>::try_from(peer) else {
                    return Err(Status::IncorrectDataParameter);
                };
                let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer_bytes));
                if !shared.was_contributory() {
                    return Err(Status::IncorrectDataParameter);
                }
                Ok(shared.as_bytes().to_vec())
            }
            Self::Rsa(_, _) | Self::Ed25519(_) => Err(Status::ConditionsOfUseNotSatisfied),
        }
    }
}

fn sign_ecdsa<C>(
    secret: &elliptic_curve::SecretKey<C>,
    digest: &[u8],
    allow_64_byte_p521: bool,
) -> Result<Vec<u8>, Status>
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
        return Err(Status::WrongLength);
    };

    let signing_key = ecdsa::SigningKey::<C>::from(secret);
    let sig = signing_key
        .sign_prehash(prehash)
        .map_err(|_| Status::IncorrectDataParameter)?;
    Ok(sig.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use ecdsa::signature::hazmat::PrehashVerifier as _;
    use elliptic_curve::Generate as _;
    use iso7816::Status;
    use rsa::{BoxedUint, traits::PublicKeyParts as _};

    use super::{SlotAlg, SlotKey};
    use crate::pgp::RsaBits;

    #[test]
    fn slot_key_sign_and_decrypt_rsa() {
        let slot_key = SlotKey::generate(SlotAlg::Rsa {
            n_bits: RsaBits::Rsa2048,
            e_bits: 32,
        })
        .unwrap();
        let SlotKey::Rsa(_, ref rsa_key) = slot_key else {
            panic!("expected RSA key");
        };
        let pub_key = rsa_key.to_public_key();
        let k = pub_key.size();

        // Sign DigestInfo and verify PKCS#1 v1.5 block
        let digest_info = [0x42u8; 32];
        let sig = slot_key.sign(&digest_info).unwrap();
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
        assert_eq!(slot_key.decrypt_rsa(&ct).unwrap(), plaintext);

        // Error cases
        assert_eq!(slot_key.sign(&[]).unwrap_err(), Status::WrongLength);
        assert_eq!(
            slot_key.decrypt_rsa(&[0x01]).unwrap_err(),
            Status::WrongLength
        );
        assert_eq!(
            slot_key.ecdh(&[0u8; 32]).unwrap_err(),
            Status::ConditionsOfUseNotSatisfied
        );
    }

    #[test]
    fn slot_key_sign_and_ecdh_nist_curves() {
        // P-256
        let p256_key = SlotKey::generate(SlotAlg::P256).unwrap();
        let SlotKey::P256(ref secret) = p256_key else {
            panic!("expected P-256 key");
        };
        let digest = [0x11u8; 32];
        let sig = p256_key.sign(&digest).unwrap();
        assert_eq!(sig.len(), 64);
        p256::ecdsa::VerifyingKey::from(secret.public_key())
            .verify_prehash(&digest, &p256::ecdsa::Signature::from_slice(&sig).unwrap())
            .unwrap();
        let eph = p256::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
        let expected = eph.diffie_hellman(&secret.public_key());
        let shared = p256_key.ecdh(&eph.public_key().to_sec1_bytes()).unwrap();
        assert_eq!(shared, expected.raw_secret_bytes().as_slice());

        // P-384
        let p384_key = SlotKey::generate(SlotAlg::P384).unwrap();
        let SlotKey::P384(ref secret) = p384_key else {
            panic!("expected P-384 key");
        };
        let digest = [0x22u8; 48];
        let sig = p384_key.sign(&digest).unwrap();
        assert_eq!(sig.len(), 96);
        p384::ecdsa::VerifyingKey::from(secret.public_key())
            .verify_prehash(&digest, &p384::ecdsa::Signature::from_slice(&sig).unwrap())
            .unwrap();

        // P-521 (64-byte SHA-512 and 66-byte field width)
        let p521_key = SlotKey::generate(SlotAlg::P521).unwrap();
        let SlotKey::P521(ref secret) = p521_key else {
            panic!("expected P-521 key");
        };
        let sha512 = [0x33u8; 64];
        let sig64 = p521_key.sign(&sha512).unwrap();
        assert_eq!(sig64.len(), 132);
        let padded = [&[0x00, 0x00], sha512.as_slice()].concat();
        p521::ecdsa::VerifyingKey::from(secret.public_key())
            .verify_prehash(
                &padded,
                &p521::ecdsa::Signature::from_slice(&sig64).unwrap(),
            )
            .unwrap();
        assert_eq!(p521_key.sign(&[0u8; 32]).unwrap_err(), Status::WrongLength);
    }

    #[test]
    fn slot_key_ed25519_and_x25519() {
        let ed_key = SlotKey::generate(SlotAlg::Ed25519).unwrap();
        let SlotKey::Ed25519(ref signing) = ed_key else {
            panic!("expected Ed25519 key");
        };
        let msg = b"slot-key-ed25519";
        let sig = ed_key.sign(msg).unwrap();
        assert_eq!(sig.len(), 64);
        signing
            .verifying_key()
            .verify_strict(msg, &ed25519_dalek::Signature::from_slice(&sig).unwrap())
            .unwrap();
        assert_eq!(
            ed_key.ecdh(&[0u8; 32]).unwrap_err(),
            Status::ConditionsOfUseNotSatisfied
        );

        let x_key = SlotKey::generate(SlotAlg::X25519).unwrap();
        let SlotKey::X25519(ref secret) = x_key else {
            panic!("expected X25519 key");
        };
        let eph = x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::rng());
        let eph_pub = x25519_dalek::PublicKey::from(&eph);
        let expected = eph.diffie_hellman(&x25519_dalek::PublicKey::from(secret));
        let shared = x_key.ecdh(eph_pub.as_bytes()).unwrap();
        assert_eq!(shared, expected.as_bytes());
        assert_eq!(
            x_key.sign(msg).unwrap_err(),
            Status::ConditionsOfUseNotSatisfied
        );
        assert_eq!(
            x_key.ecdh(&[0u8; 31]).unwrap_err(),
            Status::IncorrectDataParameter
        );
    }
}
