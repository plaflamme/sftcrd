//! The key slots: the 24-slot table with its factory state and the two
//! gates every key-slot command applies.
//!
//! The slots are the SP 800-73-4 key references minus the two that are not
//! key slots: `9B` is the management key (its session state lives in
//! [`crate::management`]) and `F9` is the attestation key reference. The
//! table order is `9A`, `9C`, `9D`, `9E`, then retired `1..=20` (key refs
//! `82`..=`95`), the mapping the host crate's `Slot::retired(n)`
//! implements.
//!
//! Every slot carries its PIN policy (the factory values: `ONCE` for 9A,
//! `ALWAYS` for 9C, `ONCE` for 9D, `NEVER` for 9E and for every retired
//! slot), its touch policy (`0` at the factory) and, once a key lands, the
//! key itself and its certificate data object. The two gates:
//!
//! - [`PivApplet::management_unlocked`] — the 9B session must be unlocked
//!   ([`iso7816::Status::SecurityStatusNotSatisfied`] otherwise); a read-only consultation
//!   of the management state, not a second challenge.
//! - [`PivApplet::slot_pin_gate`] — the slot's PIN policy, enforced with
//!   the session's `pin.verified` flag and the [`PivApplet::pin_always_armed`]
//!   latch; [`iso7816::Status::SecurityStatusNotSatisfied`] otherwise.

use std::ops::{Index, IndexMut};

use crate::piv::{KeyAlg, PinPolicy, TouchPolicy};
use ecdsa::SignatureEncoding;
use elliptic_curve::Generate;
use iso7816::Status;
use rsa::{
    BoxedUint,
    signature::hazmat::PrehashSigner,
    traits::{PrivateKeyParts, PublicKeyParts},
};

use crate::PivApplet;

/// Public RSA exponent
const RSA_EXPONENT: u64 = 65537;

/// One key slot: its key material (or the absence of one), its policies
/// and its certificate data object.
///
/// The fields the key-slot commands read and write land with them:
/// `key` with the key-generation commands, `cert` with GET/PUT DATA,
/// `touch_policy` with GENERATE and GET METADATA, `imported` with GENERATE
/// and MOVE KEY.
pub(crate) struct Slot {
    /// The slot's key, or `None` for an empty slot.
    // read by slot GA (T3) and GET METADATA (T5).
    pub(crate) key: Option<SlotKey>,
    /// The PIN policy GENERATE KEY (re)sets for this slot; the factory
    /// value per slot.
    pub(crate) pin_policy: PinPolicy,
    /// The touch policy GENERATE KEY (re)sets for this slot: a raw
    /// [`keyroost_piv::TouchPolicy`] id, `0` (default) at the factory.
    #[allow(dead_code)] // (re)set by GENERATE/IMPORT/MOVE, read by GET METADATA (T5).
    pub(crate) touch_policy: TouchPolicy,
    /// Whether the current key was imported by the host (`true`, origin
    /// `0x02`) or generated on the card (`false`, origin `0x01`).
    #[allow(dead_code)] // set by GENERATE/IMPORT/MOVE, read by GET METADATA (T5).
    pub(crate) imported: bool,
    /// The slot's certificate as stored under its data object (the `53`-
    /// wrapped value GET DATA returns verbatim), or `None` when the slot
    /// holds no certificate.
    pub(crate) cert: Option<Vec<u8>>,
}

pub(crate) enum KeyMaterial {
    Scalar(Vec<u8>),
    Rsa {
        p: Vec<u8>,
        q: Vec<u8>,
        dp: Vec<u8>,
        dq: Vec<u8>,
        n: Vec<u8>,
    },
}

/// A key held in a slot.
///
/// An EC key's material is the curve's private scalar — a zeroized
/// big-endian value, 32 bytes (P-256), 48 (P-384) or 66 (P-521), in
/// `secret`. An RSA key's material is the key's PKCS#1 ("`RSAPrivateKey`")
/// DER encoding — the `rsa` crate's `RsaPrivateKey` via `to_pkcs1_der`,
/// modulus, private exponent and the prime factors — and the card keeps
/// only that byte string, deserializing it for each use (the raw GA sign
/// and `public_inner` both read it).
// read by slot GA (T3) and GET METADATA (T5).
pub(crate) enum SlotKey {
    EccP256(elliptic_curve::SecretKey<p256::NistP256>),
    EccP384(elliptic_curve::SecretKey<p384::NistP384>),
    EccP521(elliptic_curve::SecretKey<p521::NistP521>),
    Rsa(usize, rsa::PrivateKey),
}

fn encode_public_point(point: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(2 + point.len());
    crate::data::push_tlv(&mut inner, &[0x86], point);
    inner
}

impl SlotKey {
    pub(crate) fn generate(alg: KeyAlg) -> Result<Self, iso7816::Status> {
        match alg {
            KeyAlg::EccP256 => Ok(SlotKey::EccP256(
                elliptic_curve::SecretKey::<p256::NistP256>::generate_from_rng(&mut rand::rng()),
            )),
            KeyAlg::EccP384 => Ok(SlotKey::EccP384(
                elliptic_curve::SecretKey::<p384::NistP384>::generate_from_rng(&mut rand::rng()),
            )),
            KeyAlg::EccP521 => Ok(SlotKey::EccP521(
                elliptic_curve::SecretKey::<p521::NistP521>::generate_from_rng(&mut rand::rng()),
            )),
            KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
                let bits = match alg {
                    KeyAlg::Rsa1024 => 1024,
                    KeyAlg::Rsa2048 => 2048,
                    KeyAlg::Rsa3072 => 3072,
                    KeyAlg::Rsa4096 => 4096,
                    _ => unreachable!("alg is an RSA key size"),
                };
                let Ok(key) = rsa::PrivateKey::new(&mut rand::rng(), bits) else {
                    return Err(iso7816::Status::IncorrectDataParameter);
                };
                Ok(Self::Rsa(bits, key))
            }
            _ => Err(iso7816::Status::IncorrectDataParameter),
        }
    }

    pub(crate) fn alg(&self) -> KeyAlg {
        match self {
            SlotKey::EccP256(_) => KeyAlg::EccP256,
            SlotKey::EccP384(_) => KeyAlg::EccP384,
            SlotKey::EccP521(_) => KeyAlg::EccP521,
            SlotKey::Rsa(1024, _) => KeyAlg::Rsa1024,
            SlotKey::Rsa(2048, _) => KeyAlg::Rsa2048,
            SlotKey::Rsa(3072, _) => KeyAlg::Rsa3072,
            SlotKey::Rsa(4096, _) => KeyAlg::Rsa4096,
            SlotKey::Rsa(bits, _) => unreachable!("invalid RSA bits {bits}"),
        }
    }

    /// The `7F49`-inner public-key TLVs this key reports — the same shape
    /// GENERATE's answer, the GET METADATA `04` member and the host's
    /// `parse_public_key`/`parse_metadata` all carry: the uncompressed
    /// point under `86` for EC keys, the modulus under `81` and the
    /// exponent under `82` for RSA keys. `None` for an algorithm this
    /// applet does not store.
    pub(crate) fn public_inner(&self) -> Vec<u8> {
        match self {
            SlotKey::EccP256(secret) => encode_public_point(&secret.public_key().to_sec1_bytes()),
            SlotKey::EccP384(secret) => encode_public_point(&secret.public_key().to_sec1_bytes()),
            SlotKey::EccP521(secret) => encode_public_point(&secret.public_key().to_sec1_bytes()),
            SlotKey::Rsa(_, secret) => {
                let (n, e) = (
                    secret.n().to_be_bytes(),
                    secret.e().to_be_bytes_trimmed_vartime(), // NOTE: keyroost is sensitive to leading zeroes.
                );
                let mut inner = Vec::with_capacity(2 + n.len() + 5);
                crate::data::push_tlv(&mut inner, &[0x81], &n);
                crate::data::push_tlv(&mut inner, &[0x82], &e);
                inner
            }
        }
    }

    /// Sign the specified digest with this key.
    /// For ECDSA, the host sends the pre-hashed digest, this returns the DER-encoded signature.
    /// For RSA, runs the raw CRT operation, this returns the pre-encoded `DigestInfo` block.
    pub(crate) fn sign_prehash(&self, digest: &[u8]) -> Result<Vec<u8>, iso7816::Status> {
        match self {
            SlotKey::EccP256(secret_key) => {
                let Ok(bytes) = p256::FieldBytes::try_from(digest) else {
                    return Err(iso7816::Status::IncorrectDataParameter);
                };
                let sig: ecdsa::Signature<p256::NistP256> = ecdsa::SigningKey::from(secret_key)
                    .sign_prehash(&bytes)
                    .map_err(|_| iso7816::Status::IncorrectDataParameter)?;
                Ok(sig.to_der().to_vec())
            }
            SlotKey::EccP384(secret_key) => {
                let Ok(bytes) = p384::FieldBytes::try_from(digest) else {
                    return Err(iso7816::Status::IncorrectDataParameter);
                };
                let sig: ecdsa::Signature<p384::NistP384> = ecdsa::SigningKey::from(secret_key)
                    .sign_prehash(&bytes)
                    .map_err(|_| iso7816::Status::IncorrectDataParameter)?;
                Ok(sig.to_der().to_vec())
            }
            SlotKey::EccP521(secret_key) => {
                // NOTE: P521 is not part of the PIV standard, so some implementations may require 66 bytes (521 bit) while others accept 64.
                // Let's accept both, and left-pad 64 bytes to 66.
                let digest = if digest.len() == 64 {
                    [&[0x00, 0x00], digest].concat()
                } else {
                    digest.to_vec()
                };
                let Ok(bytes) = p521::FieldBytes::try_from(digest) else {
                    return Err(iso7816::Status::IncorrectDataParameter);
                };
                let sig: ecdsa::Signature<p521::NistP521> = ecdsa::SigningKey::from(secret_key)
                    .sign_prehash(&bytes)
                    .map_err(|_| iso7816::Status::IncorrectDataParameter)?;
                Ok(sig.to_der().to_vec())
            }
            SlotKey::Rsa(_, key) => {
                use rsa::BoxedUint;
                use rsa::hazmat::rsa_decrypt;
                use rsa::traits::PublicKeyParts;

                let n = key.n().to_be_bytes();
                if digest.len() != n.len() {
                    return Err(iso7816::Status::IncorrectDataParameter);
                }

                let c = BoxedUint::from_be_slice_vartime(digest);
                if c >= key.n().clone().get() {
                    return Err(iso7816::Status::IncorrectDataParameter);
                }

                let Ok(m) = rsa_decrypt::<rand::rngs::SysRng>(None, key, &c) else {
                    return Err(iso7816::Status::IncorrectDataParameter);
                };

                // Zero-extend the residue to the full modulus size.
                let m_be = m.to_be_bytes();
                let mut out = vec![0u8; n.len()];
                let offset = n.len() - m_be.len();
                out[offset..].copy_from_slice(&m_be);
                Ok(out)
            }
        }
    }

    /// Runs Elliptic-Curve Diffie-Hellman (ECDH) key agreement.
    /// Returns the raw shared secret bytes.
    pub(crate) fn ecdh(&self, peer: &[u8]) -> Result<Vec<u8>, iso7816::Status> {
        match self {
            SlotKey::EccP256(secret_key) => {
                let Ok(peer) = elliptic_curve::PublicKey::<p256::NistP256>::from_sec1_bytes(peer)
                else {
                    return Err(iso7816::Status::IncorrectDataParameter);
                };
                let shared = elliptic_curve::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    peer.as_affine(),
                );
                Ok(shared.raw_secret_bytes().to_vec())
            }
            SlotKey::EccP384(secret_key) => {
                let Ok(peer) = elliptic_curve::PublicKey::<p384::NistP384>::from_sec1_bytes(peer)
                else {
                    return Err(iso7816::Status::IncorrectDataParameter);
                };
                let shared = elliptic_curve::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    peer.as_affine(),
                );
                Ok(shared.raw_secret_bytes().to_vec())
            }
            SlotKey::EccP521(secret_key) => {
                let Ok(peer) = elliptic_curve::PublicKey::<p521::NistP521>::from_sec1_bytes(peer)
                else {
                    return Err(iso7816::Status::IncorrectDataParameter);
                };
                let shared = elliptic_curve::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    peer.as_affine(),
                );
                Ok(shared.raw_secret_bytes().to_vec())
            }
            SlotKey::Rsa(_, _) => Err(iso7816::Status::IncorrectDataParameter),
        }
    }
}

impl TryFrom<(KeyAlg, KeyMaterial)> for SlotKey {
    type Error = ();

    fn try_from((key_alg, key_material): (KeyAlg, KeyMaterial)) -> Result<Self, Self::Error> {
        match key_material {
            KeyMaterial::Scalar(scalar) => {
                let slot_key = match key_alg {
                    KeyAlg::EccP256 => elliptic_curve::SecretKey::<p256::NistP256>::from_bytes(
                        &p256::FieldBytes::try_from(scalar).map_err(|_| ())?,
                    )
                    .map(SlotKey::EccP256),
                    KeyAlg::EccP384 => elliptic_curve::SecretKey::<p384::NistP384>::from_bytes(
                        &p384::FieldBytes::try_from(scalar).map_err(|_| ())?,
                    )
                    .map(SlotKey::EccP384),
                    KeyAlg::EccP521 => elliptic_curve::SecretKey::<p521::NistP521>::from_bytes(
                        &p521::FieldBytes::try_from(scalar).map_err(|_| ())?,
                    )
                    .map(SlotKey::EccP521),
                    _ => return Err(()),
                };
                slot_key.map_err(|_| ())
            }
            KeyMaterial::Rsa { p, q, dp, dq, n } => match key_alg {
                KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096 => {
                    let Some(slot_key) = import_rsa_secret(key_alg, &p, &q, &dp, &dq, &n) else {
                        return Err(());
                    };
                    Ok(slot_key)
                }
                _ => Err(()),
            },
        }
    }
}

/// An imported RSA key validated against its modulus size and rebuilt as
/// the card's PKCS#1 storage form. The on-wire set is the reference
/// applet's CRT member set — `01 p`, `02 q`, `03 dP`, `04 dQ`, `05 n`:
/// every component present, `p`/`q` exactly half the modulus size, `n`
/// the full size, `dP`/`dQ` non-zero and at most half the size,
/// `p`/`q`/`n` odd and greater than 1, `p != q` and `p * q == n` (checked
/// numerically with `BigUint`). Stricter than the reference applet, which
/// does none of this — a broken CRT set would otherwise be stored and fail
/// on first use. The exponent is assumed to be the PIV standard 65537
/// (see `RSA_EXPONENT`).
///
/// The wire carries the CRT halves but the card stores the full key, so
/// the private exponent is rebuilt from the primes instead:
/// `RsaPrivateKey::from_p_q` derives `d = e^{-1} mod lcm(p-1, q-1)`
/// (NIST SP 800-56B 6.2.1) and the modulus `n = p * q` itself, validates
/// the full key (`d * e ≡ 1` modulo both prime orders) and precomputes the
/// CRT exponents `to_pkcs1_der` needs. The on-wire `dP`/`dQ` are then only
/// checked for consistency with the derived `d` (`d ≡ dP (mod p-1)`,
/// `d ≡ dQ (mod q-1)`) — a mismatched set is refused, never stored.
fn import_rsa_secret(
    alg: KeyAlg,
    p: &[u8],
    q: &[u8],
    dp: &[u8],
    dq: &[u8],
    n: &[u8],
) -> Option<SlotKey> {
    let (bits, modulus_len) = match alg {
        KeyAlg::Rsa1024 => (1024, 128),
        KeyAlg::Rsa2048 => (2048, 256),
        KeyAlg::Rsa3072 => (3072, 384),
        KeyAlg::Rsa4096 => (4096, 512),
        _ => return None,
    };
    let half = modulus_len / 2;
    if p.len() != half
        || q.len() != half
        || n.len() != modulus_len
        || dp.is_empty()
        || dq.is_empty()
        || dp.len() > half
        || dq.len() > half
    {
        return None;
    }
    let (p, q) = (
        BoxedUint::from_be_slice_vartime(p),
        BoxedUint::from_be_slice_vartime(q),
    );

    let mut key = rsa::PrivateKey::from_p_q(p, q, BoxedUint::from(RSA_EXPONENT)).ok()?;

    if key.n().clone().get() != BoxedUint::from_be_slice_vartime(n) {
        return None;
    }

    key.precompute().ok()?;
    if key.dp()? != &BoxedUint::from_be_slice_vartime(dp) {
        return None;
    }
    if key.dq()? != &BoxedUint::from_be_slice_vartime(dq) {
        return None;
    }

    Some(SlotKey::Rsa(bits, key))
}

impl Slot {
    /// The factory state of a slot: empty, the given PIN policy, no touch
    /// policy, no certificate.
    pub(crate) const fn factory(pin_policy: PinPolicy) -> Self {
        Slot {
            key: None,
            pin_policy,
            touch_policy: TouchPolicy::Never,
            imported: false,
            cert: None,
        }
    }
}

/// The table order of the 24 key slots, one entry per slot: `9A`, `9C`,
/// `9D`, `9E`, then retired `1..=20` (key refs `82`..=`95`).
const fn factory_slots() -> [Slot; 24] {
    [
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Always),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Never),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
        Slot::factory(PinPolicy::Once),
    ]
}

/// The factory PIN policy of the slot at `index`: `ALWAYS` for 9C (index 1),
/// `NEVER` for 9E (index 3) and `ONCE` for every other slot — the per-slot
/// column of [`factory_slots`], exposed so GET METADATA can report whether a
/// slot still holds its factory policies.
pub(crate) const fn factory_pin_policy(slot: crate::piv::Slot) -> PinPolicy {
    match slot {
        crate::piv::Slot::Signature => PinPolicy::Always,
        crate::piv::Slot::CardAuthentication => PinPolicy::Never,
        _ => PinPolicy::Once,
    }
}

/// Map a key reference to its table index.
const fn slot_index(slot: crate::piv::Slot) -> usize {
    match slot {
        crate::piv::Slot::Authentication => 0,
        crate::piv::Slot::Signature => 1,
        crate::piv::Slot::KeyManagement => 2,
        crate::piv::Slot::CardAuthentication => 3,
        crate::piv::Slot::Retired(index) => index.value() as usize + 4,
    }
}

pub(crate) struct Slots([Slot; 24]);

impl Slots {
    fn new() -> Self {
        Self(factory_slots())
    }
}

impl Default for Slots {
    fn default() -> Self {
        Self::new()
    }
}

impl Index<crate::piv::Slot> for Slots {
    type Output = Slot;

    fn index(&self, index: crate::piv::Slot) -> &Self::Output {
        &self.0[slot_index(index)]
    }
}

impl IndexMut<crate::piv::Slot> for Slots {
    fn index_mut(&mut self, index: crate::piv::Slot) -> &mut Self::Output {
        self.0.index_mut(slot_index(index))
    }
}

impl PivApplet {
    /// The management gate: the 9B session must be unlocked.
    ///
    /// A read-only consultation of [`MgmtKey::unlocked`](crate::management)
    /// — the 9B exchange itself stays in GENERAL AUTHENTICATE. Answers
    /// [`iso7816::Status::SecurityStatusNotSatisfied.into()`].
    ///
    /// Consulted by the key-slot commands (GENERATE, IMPORT, MOVE KEY) and
    /// PUT DATA.
    pub(crate) fn management_unlocked(&self) -> Result<(), Status> {
        if self.mgmt.unlocked() {
            Ok(())
        } else {
            Err(iso7816::Status::SecurityStatusNotSatisfied)
        }
    }

    /// The slot's PIN gate: enforce the slot's PIN policy.
    ///
    /// `NEVER` is ungated; `ONCE` needs the PIN verified in this session;
    /// `ALWAYS` needs the PIN verified and this APDU to be the one right
    /// after the successful VERIFY (the [`PivApplet::pin_always_armed`]
    /// latch, which the dispatch consumes with this APDU). A
    /// not-satisfied policy answers [`iso7816::Status::SecurityStatusNotSatisfied.into()`].
    /// Slots never hold the `DEFAULT` policy — GENERATE KEY always stores
    /// one of the three concrete values — so `DEFAULT` is unreachable here.
    pub(crate) fn slot_pin_gate(&self, slot: crate::piv::Slot) -> Result<(), Status> {
        let satisfied = match self.slots[slot].pin_policy {
            PinPolicy::Never => true,
            PinPolicy::Once => self.pin.verified(),
            PinPolicy::Always => self.pin.verified_previous(),
        };
        if satisfied {
            Ok(())
        } else {
            Err(iso7816::Status::SecurityStatusNotSatisfied)
        }
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use crate::general_auth::tests::mgmt_handshake;

    /// A case-1 GA APDU: `00 87 00 <p2>`, the shape the host's
    /// `general_auth` builders emit when there is no payload yet.
    fn ga_apdu(p2: u8) -> Vec<u8> {
        vec![0x00, 0x87, 0x00, p2]
    }

    /// The host's VERIFY: `00 20 00 80` with the PIN 0xFF-padded to the
    /// 8-byte field, as the host's `verify_pin` builder emits it.
    fn verify_pin(pin: &[u8]) -> Vec<u8> {
        let mut body = [0xFFu8; 8];
        body[..pin.len()].copy_from_slice(pin);
        let mut apdu = vec![0x00, 0x20, 0x00, 0x80, 0x08];
        apdu.extend_from_slice(&body);
        apdu
    }

    #[test]
    fn factory_slot_table_has_the_plan_policies() {
        let slots = Slots::new();
        // 9A, 9C, 9D, 9E: once, always, once, never.
        assert_eq!(
            slots[crate::piv::Slot::Authentication].pin_policy,
            PinPolicy::Once
        );
        assert_eq!(
            slots[crate::piv::Slot::Signature].pin_policy,
            PinPolicy::Always
        );
        assert_eq!(
            slots[crate::piv::Slot::KeyManagement].pin_policy,
            PinPolicy::Once
        );
        assert_eq!(
            slots[crate::piv::Slot::CardAuthentication].pin_policy,
            PinPolicy::Never
        );
        // All 20 retired slots: once.
        for slot in 1..=20 {
            assert_eq!(
                slots[crate::piv::Slot::retired(slot).unwrap()].pin_policy,
                PinPolicy::Once
            );
        }
    }

    #[test]
    fn factory_pin_policy_matches_the_table() {
        let slots = factory_slots();
        for slot in crate::piv::Slot::all() {
            assert_eq!(slots[slot_index(slot)].pin_policy, factory_pin_policy(slot));
        }
    }

    #[test]
    fn factory_slots_are_empty() {
        let slots = Slots::default();
        for slot in &slots.0 {
            assert!(slot.key.is_none());
            assert!(slot.cert.is_none());
            assert!(!slot.imported);
            assert_eq!(slot.touch_policy, TouchPolicy::Never);
        }
    }

    #[test]
    fn management_gate_answers_6982_until_unlocked() {
        let mut applet = PivApplet::new();
        assert_eq!(
            applet.management_unlocked(),
            Err(iso7816::Status::SecurityStatusNotSatisfied)
        );
        mgmt_handshake(&mut applet);
        assert!(applet.management_unlocked().is_ok());
        // A witness request re-locks the session — the gate locks with it.
        let r = applet.process(&[0x00, 0x87, 0x03, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00, 0x00]);
        assert_eq!(r.status(), iso7816::Status::Success);
        assert_eq!(
            applet.management_unlocked(),
            Err(iso7816::Status::SecurityStatusNotSatisfied)
        );
    }

    #[test]
    fn once_policy_gates_on_the_pin_session_flag() {
        let mut applet = PivApplet::new();
        // 9A is ONCE: locked before the PIN is verified...
        assert_eq!(
            applet.slot_pin_gate(crate::piv::Slot::Authentication),
            Err(iso7816::Status::SecurityStatusNotSatisfied)
        );
        // ...and open after.
        let r = applet.process(&verify_pin(b"123456"));
        assert_eq!(r.status(), iso7816::Status::Success);
        assert!(
            applet
                .slot_pin_gate(crate::piv::Slot::Authentication)
                .is_ok()
        );
    }

    #[test]
    fn always_policy_needs_the_arm_after_verify() {
        let mut applet = PivApplet::new();
        // Locked before the PIN is verified...
        assert_eq!(
            applet.slot_pin_gate(crate::piv::Slot::Signature),
            Err(iso7816::Status::SecurityStatusNotSatisfied)
        );
        // ...and the APDU right after a successful VERIFY is the one that
        // gets through: the latch is set by the VERIFY and still set when
        // this slot GA runs.
        let r = applet.process(&verify_pin(b"123456"));
        assert_eq!(r.status(), iso7816::Status::Success);
        let r = applet.process(&ga_apdu(0x9C));
        assert_eq!(
            r.status(),
            iso7816::Status::IncorrectP1OrP2Parameter,
            "arm survives the VERIFY"
        );
        // The arm is consumed by that APDU: the next one is gated again
        // even though the PIN is still verified.
        let r = applet.process(&ga_apdu(0x9C));
        assert_eq!(r.status(), iso7816::Status::SecurityStatusNotSatisfied);
    }

    #[test]
    fn never_policy_is_ungated() {
        let mut applet = PivApplet::new();
        // 9E is NEVER: no PIN, no arm, always open.
        assert!(
            applet
                .slot_pin_gate(crate::piv::Slot::CardAuthentication)
                .is_ok()
        );
        let r = applet.process(&ga_apdu(0x9E));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
    }

    #[test]
    fn retired_slots_are_gated_by_their_own_policy() {
        let mut applet = PivApplet::new();
        // Retired 1 (82) and retired 20 (95) are ONCE.
        for (ref_, index) in [
            (crate::piv::Slot::retired(1).unwrap(), 4usize),
            (crate::piv::Slot::retired(20).unwrap(), 23usize),
        ] {
            assert_eq!(slot_index(ref_), index);
            assert_eq!(
                applet.process(&ga_apdu(ref_.into_u8())).status(),
                iso7816::Status::SecurityStatusNotSatisfied
            );
        }
        let r = applet.process(&verify_pin(b"123456"));
        assert_eq!(r.status(), iso7816::Status::Success);
        assert_eq!(
            applet.process(&ga_apdu(0x82)).status(),
            iso7816::Status::IncorrectP1OrP2Parameter
        );
        assert_eq!(
            applet.process(&ga_apdu(0x95)).status(),
            iso7816::Status::IncorrectP1OrP2Parameter
        );
    }

    #[test]
    fn non_slot_p2s_keep_their_answers() {
        let mut applet = PivApplet::new();
        // 9B: the management path — a bare APDU carries no witness member,
        // the shape is refused.
        let r = applet.process(&[0x00, 0x87, 0x03, 0x9B]);
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
        // The vendor-extension references are not slots: refused, and
        // ungated (no PIN needed).
        for p2 in [0xE0u8, 0xE1u8, 0xF9u8] {
            let r = applet.process(&ga_apdu(p2));
            assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
        }
    }
}
