//! The key-slot key commands: GENERATE ASYMMETRIC KEY PAIR (`0x47`),
//! IMPORT ASYMMETRIC KEY (`0xFE`) and MOVE KEY / DELETE (`0xF6`), the
//! first two for the NIST curves P-256, P-384 and P-521.
//!
//! Both commands need the 9B management session unlocked and both replace
//! what the slot holds: the key is overwritten, the requested policies
//! (a `DEFAULT` policy restores the slot's factory policy, an absent one
//! keeps what the slot had) are applied and the slot certificate is
//! cleared — the old one no longer matches the new key.
//!
//! GENERATE answers the new public point as a `7F 49 86 <point>` template
//! (the shape the host's `parse_public_key` reads); the host cannot know
//! a key it did not choose. IMPORT answers bare `9000` — the host already
//! knows the key it sent.
//!
//! The two control bodies share one member grammar: ordered TLVs, each
//! member at most once, in any order — a required member (the `80`
//! algorithm for GENERATE, the `06` scalar for IMPORT) and optional
//! `AA 01 <pin policy>` and `AB 01 <touch policy>` members, a broken
//! structure or an unknown or repeated member refusing the command with
//! `6A86`.

use elliptic_curve::Generate;

use crate::piv::Defaultable;
use crate::piv::Slot;
use crate::piv::{KeyAlg, PinPolicy, TouchPolicy};

use crate::PivApplet;
use crate::Response;
use crate::slot::KeyOrigin;
use crate::slot::PublicKey;
use crate::slot::{KeyMaterial, SlotKey};
use crate::tlv::BerLength;
use crate::tlv::DecodeError;
use crate::tlv::Encoder;
use crate::tlv::Length;
use crate::tlv::ValueDecoder;
use crate::tlv::ValueEncoder;
use crate::tlv::tlv_struct;

crate::tlv::tlv_struct! {
    #[tag_type(u16)]
    #[length(BerLength)]
    struct GenerateResponse {
        #[tag = 0x7F49]
        public_key: PublicKey,
    }
}

// TODO: support tlv_enum!{}
impl ValueEncoder for PublicKey {
    fn length(&self) -> usize {
        match self {
            PublicKey::Point(pt) => 1 + BerLength::length(pt.length()) + pt.length(),
            PublicKey::Rsa { n, e } => {
                1 + BerLength::length(n.length())
                    + n.length()
                    + 1
                    + BerLength::length(e.length())
                    + e.length()
            }
        }
    }

    fn encode(&self, buf: &mut [u8]) {
        let mut encoder = Encoder::new(buf);

        match self {
            PublicKey::Point(pt) => encoder.write_tlv::<u8, BerLength, Vec<u8>>(0x86, pt),
            PublicKey::Rsa { n, e } => {
                encoder.write_tlv::<u8, BerLength, Vec<u8>>(0x81, n);
                encoder.write_tlv::<u8, BerLength, Vec<u8>>(0x82, e);
            }
        }
    }
}

impl ValueDecoder<'_> for PublicKey {
    fn decode(_bytes: &'_ [u8]) -> Result<Self, DecodeError> {
        unreachable!()
    }
}

impl PivApplet {
    /// GENERATE ASYMMETRIC KEY PAIR (`0x47`): the host's `generate_key`
    /// APDU, `00 47 00 <slot> Lc AC <len> 80 01 <alg> [AA 01 <pin>]
    /// [AB 01 <touch>]`, case 4 with `Le 0x00`.
    ///
    /// The card generates the P-256 key with `OsRng`, stores the scalar
    /// (origin: on-card) and answers the public point. A slot that already
    /// holds a key is regenerated — its key and certificate are replaced
    /// and an absent policy request keeps the slot's current policy.
    pub(crate) fn process_generate_key_pair(
        &mut self,
        command: &crate::apdu::CommandView<'_>,
    ) -> Response {
        if let Err(sw) = self.management_unlocked() {
            return sw.into();
        }
        if command.p1 != 0x00 {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        }
        // Unwrap the `AC` control-reference template.
        let control = match command.data() {
            [0xAC, len, control @ ..] if usize::from(*len) == control.len() => control,
            _ => return iso7816::Status::IncorrectDataParameter.into(),
        };
        let Ok(ctrl) = Control::decode(control) else {
            return iso7816::Status::IncorrectDataParameter.into();
        };
        // The `F9` attestation key: P-256 only, and a regeneration
        // re-mints the self-signed certificate that describes it — the
        // reference applet leaves the certificate stale after a key
        // replacement, and a stale attestation CA would certify the wrong
        // key. The policy request is ignored: the self-signed certificate
        // keeps the reference applet's fixed policy bytes.
        if command.p2 == 0xF9 && ctrl.alg != KeyAlg::EccP256 {
            // The `F9` attestation key is P-256 only, not a slot of the
            // 24-slot table.
            return iso7816::Status::IncorrectDataParameter.into();
        }
        if command.p2 == 0xF9 {
            let secret =
                elliptic_curve::SecretKey::<p256::NistP256>::generate_from_rng(&mut rand::rng());
            let signing = ecdsa::SigningKey::<p256::NistP256>::from(&secret);
            let point = signing
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .to_vec();

            self.attestation.secret_key = secret;
            // NOTE: generating a new key in this slot breaks attestation until a new certificate is imported.
            // The imported certificate is normally signed by a
            self.attestation.cert = None;

            let response = GenerateResponse {
                public_key: PublicKey::Point(point),
            };
            return response.encode_top_level().into();
        }
        let Some(slot) = Slot::from_u8(command.p2) else {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        };
        let slot_key = match SlotKey::generate(ctrl.alg) {
            Ok(slot_key) => slot_key,
            Err(status) => return status.into(),
        };

        let response = GenerateResponse {
            public_key: slot_key.public_key(),
        };

        self.commit_slot_key(
            slot,
            slot_key,
            KeyOrigin::Generated,
            ctrl.pin_policy,
            ctrl.touch_policy,
        );

        response.encode_top_level().into()
    }

    /// IMPORT ASYMMETRIC KEY (`0xFE`): the host's
    /// `ykpriv`/`import` APDU, `00 FE <alg> <slot> Lc 06 20 <scalar>
    /// [AA 01 <pin>] [AB 01 <touch>]`, case 3 — no `Le`, the host keeps
    /// the key it sends and answers are bare `9000`.
    ///
    /// The scalar must be a 32-byte big-endian P-256 secret in
    /// `1..=n-1`; anything else refuses the command without touching the
    /// slot.
    pub(crate) fn process_import_key(
        &mut self,
        command: &crate::apdu::CommandView<'_>,
    ) -> Response {
        if let Err(sw) = self.management_unlocked() {
            return sw.into();
        }
        let Some(index) = crate::piv::Slot::from_u8(command.p2) else {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        };
        let alg = match KeyAlg::from_u8(command.p1) {
            Some(alg @ (KeyAlg::EccP256 | KeyAlg::EccP384 | KeyAlg::EccP521)) => alg,
            Some(alg @ (KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096)) => {
                alg
            }
            _ => return iso7816::Status::IncorrectDataParameter.into(),
        };
        let Ok(import) = ImportTemplate::decode(command.data()) else {
            return iso7816::Status::IncorrectDataParameter.into();
        };

        let Ok(key_material) = import.key_material(alg) else {
            return iso7816::Status::IncorrectDataParameter.into();
        };

        let Ok(slot_key) = SlotKey::try_from((alg, key_material)) else {
            return iso7816::Status::IncorrectDataParameter.into();
        };

        self.commit_slot_key(
            index,
            slot_key,
            KeyOrigin::Imported,
            import.pin_policy,
            import.touch_policy,
        );
        iso7816::Status::Success.into()
    }

    /// MOVE KEY (`0xF6`, Yubico extension): the host's `move_key` /
    /// `delete_key` APDU, `00 F6 <dest key_ref | 0xFF> <src key_ref>` —
    /// case 2, no body and no `Le`.
    ///
    /// A move relocates the source slot's key material and policies to the
    /// destination slot; the certificate objects are left untouched (the
    /// host contract — the host manages certificates through PUT DATA). The
    /// `0xFF` sentinel deletes the source key; policies and certificate are
    /// likewise left untouched.
    ///
    /// Refusals: locked `6982`; a non-slot reference in P1 (other than the
    /// `0xFF` delete sentinel) or P2 `6B00`; a source without a key `6A82`;
    /// a move into an occupied destination — the source itself included —
    /// `6A86` (R1: no silent key loss; the host pre-checks occupancy, so
    /// only an out-of-band tool can reach this answer).
    pub(crate) fn process_move_key(&mut self, command: &crate::apdu::CommandView<'_>) -> Response {
        if let Err(sw) = self.management_unlocked() {
            return sw.into();
        }
        let Some(source) = crate::piv::Slot::from_u8(command.p2) else {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        };
        let dest = match command.p1 {
            0xFF => None,
            reference => match crate::piv::Slot::from_u8(reference) {
                Some(index) => Some(index),
                None => return iso7816::Status::IncorrectP1OrP2Parameter.into(),
            },
        };
        if self.slots[source].key.is_none() {
            return iso7816::Status::NotFound.into();
        }
        if let Some(dest) = dest
            && self.slots[dest].key.is_some()
        {
            return iso7816::Status::IncorrectDataParameter.into();
        }

        let key = self.slots[source].key.take().expect("checked above");
        let (pin_policy, touch_policy, origin) = (
            self.slots[source].pin_policy,
            self.slots[source].touch_policy,
            self.slots[source].origin,
        );
        if let Some(dest) = dest {
            self.slots[dest].key = Some(key);
            self.slots[dest].pin_policy = pin_policy;
            self.slots[dest].touch_policy = touch_policy;
            self.slots[dest].origin = origin;
        }
        iso7816::Status::Success.into()
    }
}

impl ValueDecoder<'_> for KeyAlg {
    fn decode(bytes: &[u8]) -> Result<Self, crate::tlv::DecodeError> {
        u8::decode(bytes)
            .and_then(|value| KeyAlg::from_u8(value).ok_or(crate::tlv::DecodeError::InvalidValue))
    }
}

impl<'a, T> ValueDecoder<'a> for Defaultable<T>
where
    T: TryFrom<u8>,
{
    fn decode(bytes: &'a [u8]) -> Result<Self, crate::tlv::DecodeError> {
        match u8::decode(bytes) {
            Ok(0x00) => Ok(Defaultable::Default),
            Ok(value) => Ok(Defaultable::Specified(
                T::try_from(value).map_err(|_| DecodeError::InvalidValue)?,
            )),
            Err(_) => Err(DecodeError::InvalidValue),
        }
    }
}

impl ValueEncoder for KeyAlg {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) {
        buf[0] = *self as u8;
    }
}

impl ValueEncoder for PinPolicy {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) {
        buf[0] = *self as u8;
    }
}

impl ValueEncoder for TouchPolicy {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) {
        buf[0] = *self as u8;
    }
}

impl<T> ValueEncoder for Defaultable<T>
where
    T: ValueEncoder,
{
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) {
        match self {
            Defaultable::Default => buf[0] = 0x00,
            Defaultable::Specified(value) => value.encode(buf),
        }
    }
}

tlv_struct! {
    #[derive(Debug, PartialEq)]
    pub struct Control {
        #[tag = 0x80]
        alg: KeyAlg,
        #[tag = 0xAA]
        pin_policy: Option<Defaultable<PinPolicy>>,
        #[tag = 0xAB]
        touch_policy: Option<Defaultable<TouchPolicy>>,
    }
}

tlv_struct! {
    struct ImportTemplate<'a> {
        #[tag = 0x01]
        p: Option<&'a [u8]>,
        #[tag = 0x02]
        q: Option<&'a [u8]>,
        #[tag = 0x03]
        dp: Option<&'a [u8]>,
        #[tag = 0x04]
        dq: Option<&'a [u8]>,
        #[tag = 0x05]
        n: Option<&'a [u8]>,
        #[tag = 0x06]
        scalar: Option<&'a [u8]>,
        #[tag = 0xAA]
        pin_policy: Option<Defaultable<PinPolicy>>,
        #[tag = 0xAB]
        touch_policy: Option<Defaultable<TouchPolicy>>,
    }
}

impl ImportTemplate<'_> {
    fn key_material(&self, key_alg: KeyAlg) -> Result<KeyMaterial<'_>, ()> {
        let key_material = if matches!(
            key_alg,
            KeyAlg::Rsa1024 | KeyAlg::Rsa2048 | KeyAlg::Rsa3072 | KeyAlg::Rsa4096
        ) {
            // The EC scalar must not sneak in alongside the CRT set.
            if self.scalar.is_some() {
                return Err(());
            }
            match (self.p, self.q, self.dp, self.dq, self.n) {
                (Some(p), Some(q), Some(dp), Some(dq), Some(n)) => {
                    KeyMaterial::Rsa { p, q, dp, dq, n }
                }
                _ => return Err(()),
            }
        } else {
            // The RSA components must not sneak in alongside the scalar.
            if self.p.is_some()
                || self.q.is_some()
                || self.dp.is_some()
                || self.dq.is_some()
                || self.n.is_some()
            {
                return Err(());
            }
            let Some(scalar) = self.scalar else {
                return Err(());
            };
            KeyMaterial::Scalar(scalar)
        };
        Ok(key_material)
    }
}

impl PivApplet {
    /// Commit a freshly generated or imported key to the slot at `index`:
    /// replace the key material, record the algorithm and origin, apply
    /// the requested policies (a `DEFAULT` pin policy restores the slot's
    /// factory policy, an absent request keeps what the slot had) and
    /// clear the slot certificate (the R5 decision: a replaced key
    /// invalidates the old certificate).
    fn commit_slot_key(
        &mut self,
        slot: crate::piv::Slot,
        key: SlotKey,
        origin: KeyOrigin,
        pin_policy: Option<Defaultable<PinPolicy>>,
        touch_policy: Option<Defaultable<TouchPolicy>>,
    ) {
        let slot_state = &mut self.slots[slot];
        slot_state.key = Some(key);
        slot_state.origin = origin;
        slot_state.pin_policy = match pin_policy {
            Some(Defaultable::Default) => crate::slot::factory_pin_policy(slot),
            Some(Defaultable::Specified(policy)) => policy,
            None => slot_state.pin_policy,
        };
        slot_state.touch_policy = match touch_policy {
            Some(Defaultable::Default) => TouchPolicy::Never,
            Some(Defaultable::Specified(policy)) => policy,
            None => slot_state.touch_policy,
        };
        slot_state.cert = None;
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::items_after_statements)]
mod tests {
    use std::ops::Add;

    use super::*;
    use crate::general_auth::tests::mgmt_handshake;
    use crate::yubico::YubicoInstruction;
    use elliptic_curve::Curve;
    use elliptic_curve::sec1::ToSec1Point;
    use keyroost_piv::{
        CertInfo, PublicKey, Slot, encode_certificate, generate_key, get_data, parse_public_key,
        put_data,
    };
    use p256::ecdsa::SigningKey;
    use rsa::BoxedUint;
    use rsa::traits::{PrivateKeyParts, PublicKeyParts};

    /// A management-unlocked applet: the factory 3DES handshake ran, the
    /// 9B session is unlocked.
    fn unlocked() -> PivApplet {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        app
    }

    /// The host's GENERATE ASYMMETRIC KEY PAIR APDU for `slot`; a
    /// `DEFAULT` policy request is omitted, exactly as the host builds it.
    fn gen_apdu(slot: Slot) -> Vec<u8> {
        generate_key(
            slot,
            keyroost_piv::KeyAlg::EccP256.id(),
            keyroost_piv::PinPolicy::Default,
            keyroost_piv::TouchPolicy::Default,
        )
    }

    /// The host's `generate_key` APDU with explicit policies.
    fn gen_policies_apdu(
        slot: Slot,
        pin: keyroost_piv::PinPolicy,
        touch: keyroost_piv::TouchPolicy,
    ) -> Vec<u8> {
        generate_key(slot, keyroost_piv::KeyAlg::EccP256.id(), pin, touch)
    }

    /// A GENERATE APDU with a raw control-reference template (the
    /// broken-structure cases the host builder cannot express).
    fn gen_control_apdu(slot: Slot, control: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(control.len() + 3);
        data.extend_from_slice(&[0xAC, control.len() as u8]);
        data.extend_from_slice(control);
        let mut apdu = vec![0x00, 0x47, 0x00, slot.key_ref(), data.len() as u8];
        apdu.extend_from_slice(&data);
        apdu.push(0x00);
        apdu
    }

    /// A raw GENERATE APDU with an arbitrary P2 (slot reference): case 4,
    /// `Le 0x00`, with a one-member P-256 AC control template.
    fn gen_raw_p2(p2: u8) -> Vec<u8> {
        vec![
            0x00, 0x47, 0x00, p2, 0x05, 0xAC, 0x03, 0x80, 0x01, 0x11, 0x00,
        ]
    }

    /// An IMPORT body: `06 <len> <scalar>` plus optional `AA`/`AB` members.
    fn ec_body(scalar: &[u8], pin: Option<u8>, touch: Option<u8>) -> Vec<u8> {
        let mut body = vec![0x06, scalar.len() as u8];
        body.extend_from_slice(scalar);
        if let Some(pin) = pin {
            body.extend_from_slice(&[0xAA, 0x01, pin]);
        }
        if let Some(touch) = touch {
            body.extend_from_slice(&[0xAB, 0x01, touch]);
        }
        body
    }

    /// A raw IMPORT ASYMMETRIC KEY APDU.
    fn import_apdu(alg: u8, slot: u8, body: &[u8]) -> Vec<u8> {
        let mut apdu = vec![
            0x00,
            YubicoInstruction::ImportAsymmetricKey.to_code(),
            alg,
            slot,
        ];
        if body.len() <= 255 {
            apdu.push(body.len() as u8);
        } else {
            // Extended Lc: `00 LL HH`.
            apdu.extend_from_slice(&[0x00, (body.len() >> 8) as u8, body.len() as u8]);
        }
        apdu.extend_from_slice(body);
        apdu
    }

    fn fixed_scalar() -> [u8; 32] {
        let mut scalar = [0x2B; 32];
        scalar[31] = 0x01;
        scalar
    }

    /// The uncompressed point in the `7F 49 86` template.
    fn point_of(r: &Response) -> Vec<u8> {
        println!("{}", hex::encode(r.data()));
        match parse_public_key(r.data()).expect("a well-formed public-key template") {
            PublicKey::Ecc { point } => point,
            PublicKey::Rsa { .. } => panic!("expected an EC point"),
        }
    }

    #[test]
    fn generate_answers_the_uncompressed_point() {
        let mut app = unlocked();
        let r = app.process(&gen_apdu(Slot::Authentication));
        assert_eq!(r.status(), iso7816::Status::Success);
        let point = point_of(&r);
        assert_eq!(point.len(), 65);
        assert_eq!(point[0], 0x04);
        // A second generate on the same slot regenerates: a different point.
        let r2 = app.process(&gen_apdu(Slot::Authentication));
        assert_eq!(r2.status(), iso7816::Status::Success);
        assert_ne!(point_of(&r2), point);
    }

    #[test]
    fn generate_refusals() {
        // The management gate is checked before anything else.
        let mut app = PivApplet::new();
        assert_eq!(
            app.process(&gen_apdu(Slot::Authentication)).status(),
            iso7816::Status::SecurityStatusNotSatisfied
        );

        let mut app = unlocked();
        // A non-zero P1 is refused.
        let mut apdu = gen_apdu(Slot::Authentication);
        apdu[2] = 0x01;
        assert_eq!(
            app.process(&apdu).status(),
            iso7816::Status::IncorrectP1OrP2Parameter
        );
        // Non-slot P2s: the vendor-extension and PIN references.
        // `9B` (management) and `F9` (attestation) are valid GENERATE
        // targets — `F9` in particular, see
        // `attest::tests::generate_on_f9_mints_a_fresh_ca`.
        for p2 in [0xE0, 0xE1, 0x80, 0x00u8] {
            assert_eq!(
                app.process(&gen_raw_p2(p2)).status(),
                iso7816::Status::IncorrectP1OrP2Parameter,
                "P2 {p2:02X}",
            );
        }
        // `F9` with a non-P-256 algorithm is refused before the management
        // gate is reached.
        let mut f9_p384 = generate_key(
            Slot::Authentication,
            keyroost_piv::KeyAlg::EccP384.id(),
            keyroost_piv::PinPolicy::Default,
            keyroost_piv::TouchPolicy::Default,
        );
        f9_p384[3] = 0xF9;
        assert_eq!(
            app.process(&f9_p384).status(),
            iso7816::Status::IncorrectDataParameter
        );

        // A non-PIV CLA.
        let mut apdu = gen_apdu(Slot::Authentication);
        apdu[0] = 0x80;
        assert_eq!(
            app.process(&apdu).status(),
            iso7816::Status::ClaNotSupported
        );
        // Broken control templates: missing or truncated `80`, trailing
        // garbage, repeated members, unknown members.
        let broken: [&[u8]; 8] = [
            &b""[..],
            &b"\x80"[..],
            &b"\x80\x01"[..],
            &b"\x80\x00"[..],
            &b"\x80\x01\x11\x11"[..],
            &b"\x80\x01\x11\x80\x01\x11"[..],
            &b"\x80\x01\x11\xAA\x01\x02\xAA\x01\x03"[..],
            &b"\x80\x01\x11\x88\x01\x00"[..],
        ];
        for control in broken {
            assert_eq!(
                app.process(&gen_control_apdu(Slot::Authentication, control))
                    .status(),
                iso7816::Status::IncorrectDataParameter,
                "control template {control:02X?}",
            );
        }
        // An Lc overrun.
        let mut apdu = gen_apdu(Slot::Authentication);
        apdu[4] = 0x10;
        assert_eq!(app.process(&apdu).status(), iso7816::Status::WrongLength);
    }

    #[test]
    fn generate_applies_policies_and_origin() {
        let mut app = unlocked();
        let r = app.process(&gen_policies_apdu(
            Slot::Authentication,
            keyroost_piv::PinPolicy::Always,
            keyroost_piv::TouchPolicy::Always,
        ));
        assert_eq!(r.status(), iso7816::Status::Success);
        let slot = &app.slots[crate::piv::Slot::Authentication];
        assert!(slot.key.is_some());
        assert_eq!(slot.pin_policy, PinPolicy::Always);
        assert_eq!(slot.touch_policy, TouchPolicy::Always);
        assert_eq!(slot.origin, KeyOrigin::Generated);

        // Absent policy requests keep the slot's current policies.
        assert_eq!(
            app.process(&gen_apdu(Slot::Authentication)).status(),
            iso7816::Status::Success
        );
        assert_eq!(
            app.slots[crate::piv::Slot::Authentication].pin_policy,
            PinPolicy::Always
        );
        assert_eq!(
            app.slots[crate::piv::Slot::Authentication].touch_policy,
            TouchPolicy::Always
        );

        // Explicit `DEFAULT` policies restore the slot's factory policies.
        let control = [0x80, 0x01, 0x11, 0xAA, 0x01, 0x00, 0xAB, 0x01, 0x00];
        assert_eq!(
            app.process(&gen_control_apdu(Slot::Authentication, &control))
                .status(),
            iso7816::Status::Success
        );
        assert_eq!(
            app.slots[crate::piv::Slot::Authentication].pin_policy,
            PinPolicy::Once
        ); // 9A's factory
        assert_eq!(
            app.slots[crate::piv::Slot::Authentication].touch_policy,
            TouchPolicy::Never
        ); // factory: no touch policy
    }

    #[test]
    fn generate_replaces_the_key_and_clears_the_certificate() {
        let mut app = unlocked();
        let der: Vec<u8> = (0..100u32).map(|i| (i % 251) as u8).collect();
        let cert = encode_certificate(&der, CertInfo::Uncompressed);
        let tag = Slot::Authentication.cert_object_tag();
        assert_eq!(
            app.process(&put_data(&tag, &cert)).status(),
            iso7816::Status::Success
        );

        let first = app.process(&gen_apdu(Slot::Authentication));
        assert_eq!(first.status(), iso7816::Status::Success);
        let second = app.process(&gen_apdu(Slot::Authentication));
        assert_eq!(second.status(), iso7816::Status::Success);
        assert_ne!(point_of(&second), point_of(&first));

        // R5: the certificate object is cleared on regenerate.
        assert_eq!(
            app.process(&get_data(&tag)).status(),
            iso7816::Status::NotFound
        );
    }

    #[test]
    fn import_stores_the_scalar_with_origin_and_policies() {
        let mut app = unlocked();
        let scalar = fixed_scalar();
        let cert = encode_certificate(&[0x30, 0x82, 0x01, 0x00], CertInfo::Uncompressed);
        let tag = Slot::Authentication.cert_object_tag();
        assert_eq!(
            app.process(&put_data(&tag, &cert)).status(),
            iso7816::Status::Success
        );

        let r = app.process(&import_apdu(
            0x11,
            0x9A,
            &ec_body(&scalar, Some(0x02), Some(0x02)),
        ));
        assert_eq!(r.status(), iso7816::Status::Success);
        assert_eq!(r.data(), [] as [u8; 0]);

        let slot = &app.slots[crate::piv::Slot::Authentication];
        let key = slot.key.as_ref().expect("the imported key");
        assert_eq!(key.alg(), KeyAlg::EccP256);
        let SlotKey::EccP256(secret) = key else {
            panic!("invalid slot key")
        };
        assert_eq!(secret.to_bytes().to_vec(), &scalar[..]);
        assert_eq!(slot.origin, KeyOrigin::Imported);
        assert_eq!(slot.pin_policy, PinPolicy::Once);
        assert_eq!(slot.touch_policy, TouchPolicy::Always);

        // R5: import clears the stored certificate.
        assert_eq!(
            app.process(&get_data(&tag)).status(),
            iso7816::Status::NotFound
        );
    }

    #[test]
    fn import_refusals() {
        let scalar = fixed_scalar();
        // The management gate.
        let mut app = PivApplet::new();
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9A, &ec_body(&scalar, None, None)))
                .status(),
            iso7816::Status::SecurityStatusNotSatisfied
        );

        let mut app = unlocked();
        // Non-P-256 algorithm ids.
        for alg in [
            keyroost_piv::KeyAlg::Rsa3072.id(),
            keyroost_piv::KeyAlg::EccP384.id(),
            keyroost_piv::KeyAlg::Ed25519.id(),
        ] {
            assert_eq!(
                app.process(&import_apdu(alg, 0x9A, &ec_body(&scalar, None, None)))
                    .status(),
                iso7816::Status::IncorrectDataParameter
            );
        }
        // Non-slot P2s.
        for p2 in [0x9B, 0xF9u8] {
            assert_eq!(
                app.process(&import_apdu(0x11, p2, &ec_body(&scalar, None, None)))
                    .status(),
                iso7816::Status::IncorrectP1OrP2Parameter
            );
        }
        // A non-PIV CLA.
        let mut apdu = import_apdu(0x11, 0x9A, &ec_body(&scalar, None, None));
        apdu[0] = 0x80;
        assert_eq!(
            app.process(&apdu).status(),
            iso7816::Status::ClaNotSupported
        );
        // Broken bodies: no scalar, wrong lengths, trailing garbage,
        // repeated and unknown members.
        let mut with_trailing = ec_body(&scalar, None, None);
        with_trailing.push(0x11);
        let mut repeated = ec_body(&scalar, Some(0x02), None);
        repeated.extend_from_slice(&[0xAA, 0x01, 0x03]);
        let mut unknown = ec_body(&scalar, None, None);
        unknown.extend_from_slice(&[0x88, 0x01, 0x00]);
        let broken: [&[u8]; 7] = [
            b"",
            b"\xAA\x01\x02",
            b"\x06\x1F\x00",
            b"\x06\x21\x00",
            &with_trailing,
            &repeated,
            &unknown,
        ];
        for body in broken {
            assert_eq!(
                app.process(&import_apdu(0x11, 0x9A, body)).status(),
                iso7816::Status::IncorrectDataParameter
            );
        }
        // An Lc overrun.
        let mut apdu = import_apdu(0x11, 0x9A, &ec_body(&scalar, None, None));
        apdu[4] = 0x30;
        assert_eq!(app.process(&apdu).status(), iso7816::Status::WrongLength);
        // Refusals leave the slot empty.
        assert!(app.slots[crate::piv::Slot::Authentication].key.is_none());
    }

    #[test]
    fn import_rejects_out_of_range_scalars() {
        let mut app = unlocked();
        let zero = p256::U256::ZERO;
        let order = p256::NistP256::ORDER.get();
        let above = order.add(p256::U256::ONE);
        for scalar in [zero, order, above] {
            let r = app.process(&import_apdu(
                0x11,
                0x9A,
                &ec_body(&scalar.to_be_bytes(), None, None),
            ));
            assert_eq!(
                r.status(),
                iso7816::Status::IncorrectDataParameter,
                "{scalar:02X?}"
            );
        }
        assert!(app.slots[crate::piv::Slot::Authentication].key.is_none());
    }

    #[test]
    fn imported_key_signs_in_the_ga_path() {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        let scalar = fixed_scalar();
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9E, &ec_body(&scalar, None, None)))
                .status(),
            iso7816::Status::Success
        );
        // 9E is `NEVER` at the factory, so no VERIFY is needed: the GA
        // signing path signs the prehashed digest with the imported
        // scalar, verified under the point that scalar derives.
        let sk = SigningKey::from_slice(&scalar).expect("a valid scalar");
        let point = sk.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        crate::general_auth::tests::card_signature(&mut app, 0x9E, &point, &[0x2B; 32]);
    }

    /// The `81` modulus and `82` exponent in the `7F 49` template of an
    /// RSA GENERATE response.
    fn rsa_public_of(r: &Response) -> (Vec<u8>, Vec<u8>) {
        match parse_public_key(r.data()).expect("a well-formed public-key template") {
            PublicKey::Rsa { modulus, exponent } => (modulus, exponent),
            PublicKey::Ecc { .. } => panic!("expected an RSA modulus"),
        }
    }

    /// The GA sign round trip for an RSA slot: the host sends a raw block
    /// under the slot's algorithm id and the card's raw `m^d mod n` answer
    /// must satisfy `s^e == m (mod n)`.
    #[allow(clippy::many_single_char_names)]
    fn rsa_sign_check(
        app: &mut PivApplet,
        alg: keyroost_piv::KeyAlg,
        slot: u8,
        n: &[u8],
        e: &[u8],
        m: u8,
    ) {
        let mut block = vec![0u8; n.len()];
        block[n.len() - 1] = m;
        let r = app.process(&keyroost_piv::general_auth_sign(alg.id(), slot, &block));
        assert_eq!(r.status(), iso7816::Status::Success, "signing GA: {r:?}");
        let s = keyroost_piv::parse_general_auth(r.data(), 0x82).expect("an 82 answer");
        assert_eq!(
            s.len(),
            n.len(),
            "the answer is zero-extended to the modulus size"
        );
        assert_eq!(
            BoxedUint::from_be_slice_vartime(s).pow_mod(
                &BoxedUint::from_be_slice_vartime(e),
                &BoxedUint::from_be_slice_vartime(n)
                    .to_odd()
                    .expect("is odd")
            ),
            BoxedUint::from(m),
        );
    }

    /// An IMPORT body for the RSA branch: raw single-byte-length TLV members.
    fn rsa_members(members: &[(u8, &Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (tag, value) in members {
            body.push(*tag);
            body.push(value.len() as u8);
            body.extend_from_slice(value);
        }
        body
    }

    /// A host-side 1024-bit key with its CRT decomposition — the shape of
    /// the IMPORT body — and its private exponent.
    #[allow(unused)]
    struct HostRsa {
        p: Vec<u8>,
        q: Vec<u8>,
        dp: Vec<u8>,
        dq: Vec<u8>,
        d: Vec<u8>,
        n: Vec<u8>,
    }

    fn host_rsa_1024() -> HostRsa {
        let host = rsa::PrivateKey::new(&mut rand::rngs::SysRng, 1024).expect("a 1024-bit key");
        let (p, q) = (&host.primes()[0], &host.primes()[1]);
        HostRsa {
            p: p.to_be_bytes().to_vec(),
            q: q.to_be_bytes().to_vec(),
            dp: host.dp().expect("dp is valid").to_be_bytes().to_vec(),
            dq: host.dq().expect("dp is valid").to_be_bytes().to_vec(),
            d: host.d().to_be_bytes().to_vec(),
            n: host.n().to_be_bytes().to_vec(),
        }
    }

    #[test]
    fn generate_rsa1024_stores_pkcs1_and_signs() {
        let mut app = unlocked();
        let alg = keyroost_piv::KeyAlg::Rsa1024;
        // 9E is `NEVER` at the factory: the sign round trip needs no VERIFY.
        let r = app.process(&generate_key(
            Slot::CardAuthentication,
            alg.id(),
            keyroost_piv::PinPolicy::Default,
            keyroost_piv::TouchPolicy::Default,
        ));
        assert_eq!(r.status(), iso7816::Status::Success, "GENERATE: {r:?}");
        let (n, e) = rsa_public_of(&r);
        assert_eq!(n.len(), 128);
        assert_ne!(n[127] & 1, 0, "the modulus is odd");
        assert_eq!(e, [0x01u8, 0x00, 0x01]);
        // The stored secret is the PKCS#1 key itself: it decodes and
        // carries the announced modulus and exponent.
        let key = app.slots[crate::piv::Slot::CardAuthentication]
            .key
            .as_ref()
            .expect("the generated key");
        let SlotKey::Rsa(_, stored) = key else {
            panic!("invalid slot key")
        };
        assert_eq!(stored.n().to_be_bytes().to_vec(), n);
        assert_eq!(stored.e(), &rsa::BoxedUint::from_be_slice_vartime(&e));
        rsa_sign_check(&mut app, alg, 0x9E, &n, &e, 0x2B);
    }

    #[test]
    fn imported_rsa_key_round_trips() {
        let mut app = unlocked();
        // Several keys so both `p < q` and `p > q` orderings are exercised.
        for _ in 0..4 {
            let host = host_rsa_1024();
            let body = rsa_members(&[
                (0x01, &host.p),
                (0x02, &host.q),
                (0x03, &host.dp),
                (0x04, &host.dq),
                (0x05, &host.n),
            ]);
            assert_eq!(
                app.process(&import_apdu(
                    keyroost_piv::KeyAlg::Rsa1024.id(),
                    0x9E,
                    &body
                ))
                .status(),
                iso7816::Status::Success,
                "IMPORT"
            );
            // The stored key is the host key: same modulus, and the
            // exponent `from_p_q` derives from the primes — `e^{-1} mod
            // lambda(n)` with `lambda(n) = lcm(p-1, q-1)` — is exactly the
            // host's own `d` reduced to that modulus (the host's `d` is
            // generated modulo phi(n), a multiple of lambda(n)). The GA
            // round trip below proves the two sign the same thing.
            let key = app.slots[crate::piv::Slot::CardAuthentication]
                .key
                .as_ref()
                .expect("the imported key");
            let SlotKey::Rsa(_, stored) = key else {
                panic!("invalid slot key")
            };
            assert_eq!(stored.n().to_be_bytes().to_vec(), host.n);
            rsa_sign_check(
                &mut app,
                keyroost_piv::KeyAlg::Rsa1024,
                0x9E,
                &host.n,
                &[0x01, 0x00, 0x01],
                0x5A,
            );
        }
    }

    #[test]
    fn imported_rsa_refusals_leave_the_slot_empty() {
        let mut app = unlocked();
        let host = host_rsa_1024();
        let mut bad_n = host.n.clone();
        bad_n[64] ^= 1; // `p * q` no longer matches `n`
        let bad_dp = {
            let mut v = vec![0u8];
            v.extend_from_slice(&host.dp);
            v
        };
        let mut even_p = host.p.clone();
        let last = even_p.len() - 1;
        even_p[last] &= 0xFE;
        let bad_half = {
            let mut v = host.dp.clone();
            let last = v.len() - 1;
            v[last] ^= 0x01; // `dP` no longer matches `d mod (p-1)`
            v
        };
        let bodies: [Vec<u8>; 5] = [
            rsa_members(&[
                (0x01, &host.p),
                (0x02, &host.q),
                (0x03, &host.dp),
                (0x04, &host.dq),
                (0x05, &bad_n),
            ]),
            rsa_members(&[
                (0x01, &host.p),
                (0x02, &host.q),
                (0x04, &host.dq),
                (0x05, &host.n),
            ]), // missing dP
            rsa_members(&[
                (0x01, &host.p),
                (0x02, &host.q),
                (0x03, &bad_dp),
                (0x04, &host.dq),
                (0x05, &host.n),
            ]),
            rsa_members(&[
                (0x01, &even_p),
                (0x02, &host.q),
                (0x03, &host.dp),
                (0x04, &host.dq),
                (0x05, &host.n),
            ]),
            rsa_members(&[
                (0x01, &host.p),
                (0x02, &host.q),
                (0x03, &bad_half),
                (0x04, &host.dq),
                (0x05, &host.n),
            ]),
        ];
        for body in &bodies {
            assert_eq!(
                app.process(&import_apdu(keyroost_piv::KeyAlg::Rsa1024.id(), 0x9E, body))
                    .status(),
                iso7816::Status::IncorrectDataParameter,
                "body {body:02X?}"
            );
        }
        assert!(
            app.slots[crate::piv::Slot::CardAuthentication]
                .key
                .is_none()
        );
    }

    /// Read an object back through the host's GET DATA builder; the test
    /// values are all small, so no `61xx` continuation is expected.
    fn read_object(app: &mut PivApplet, tag: &[u8]) -> Vec<u8> {
        let r = app.process(&keyroost_piv::get_data(tag));
        assert_eq!(r.status(), iso7816::Status::Success, "GET DATA {tag:?}");
        keyroost_piv::unwrap_data_object(r.data())
            .expect("a well-formed 53 template")
            .to_vec()
    }

    #[test]
    fn move_carries_key_and_policies_and_leaves_certs() {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        let scalar = fixed_scalar();
        assert_eq!(
            app.process(&import_apdu(
                0x11,
                0x9C,
                &ec_body(&scalar, Some(0x02), Some(0x02))
            ))
            .status(),
            iso7816::Status::Success
        );
        let cert_a = b"source-cert";
        let cert_b = b"dest-cert";
        assert_eq!(
            app.process(&keyroost_piv::put_data(&[0x5F, 0xC1, 0x0A], cert_a))
                .status(),
            iso7816::Status::Success
        );
        assert_eq!(
            app.process(&keyroost_piv::put_data(&[0x5F, 0xC1, 0x0D], cert_b))
                .status(),
            iso7816::Status::Success
        );

        assert_eq!(
            app.process(&keyroost_piv::move_key(
                keyroost_piv::Slot::Signature,
                keyroost_piv::Slot::retired(1).expect("retired 1"),
            ))
            .status(),
            iso7816::Status::Success,
            "move"
        );
        let source = &app.slots[crate::piv::Slot::Signature];
        let dest = &app.slots[crate::piv::Slot::retired(1).expect("retired slot 1")];
        assert!(source.key.is_none(), "the source keeps no key");
        let Some(SlotKey::EccP256(secret)) = &dest.key else {
            panic!("invalid slot key")
        };
        assert_eq!(secret.to_bytes().as_slice(), &scalar);
        assert_eq!(dest.pin_policy, PinPolicy::Once);
        assert_eq!(dest.touch_policy, TouchPolicy::Always);
        assert_eq!(dest.origin, KeyOrigin::Imported);
        // The certificate objects are left untouched (host contract).
        assert_eq!(read_object(&mut app, &[0x5F, 0xC1, 0x0A]), cert_a);
        assert_eq!(read_object(&mut app, &[0x5F, 0xC1, 0x0D]), cert_b);
    }

    #[test]
    fn delete_removes_only_the_key() {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        let scalar = fixed_scalar();
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9A, &ec_body(&scalar, None, None)))
                .status(),
            iso7816::Status::Success
        );
        assert_eq!(
            app.process(&keyroost_piv::put_data(&[0x5F, 0xC1, 0x05], b"auth-cert"))
                .status(),
            iso7816::Status::Success
        );

        assert_eq!(
            app.process(&keyroost_piv::delete_key(
                keyroost_piv::Slot::Authentication
            ))
            .status(),
            iso7816::Status::Success,
            "delete"
        );
        let slot = &app.slots[crate::piv::Slot::Authentication];
        assert!(slot.key.is_none());
        assert_eq!(slot.pin_policy, PinPolicy::Once, "the policy is untouched");
        assert!(slot.cert.is_some(), "the certificate is untouched");
        assert_eq!(
            app.process(&keyroost_piv::get_metadata(0x9A)).status(),
            iso7816::Status::KeyReferenceNotFound,
            "no key, so metadata reports the slot empty"
        );
    }

    #[test]
    fn move_and_delete_refuse_an_empty_source() {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        // 9D is empty at the factory.
        assert_eq!(
            app.process(&keyroost_piv::move_key(
                keyroost_piv::Slot::KeyManagement,
                keyroost_piv::Slot::Authentication,
            ))
            .status(),
            iso7816::Status::NotFound
        );
        assert_eq!(
            app.process(&keyroost_piv::delete_key(keyroost_piv::Slot::KeyManagement))
                .status(),
            iso7816::Status::NotFound
        );
    }

    #[test]
    fn move_key_refusals() {
        let mut app = PivApplet::new();
        assert_eq!(
            app.process(&[0x00, 0xF6, 0x9C, 0x9A]).status(),
            iso7816::Status::SecurityStatusNotSatisfied
        );
        mgmt_handshake(&mut app);
        // F9 is not in the slot table, in either position; neither is 9B.
        assert_eq!(
            app.process(&[0x00, 0xF6, 0xF9, 0x9A]).status(),
            iso7816::Status::IncorrectP1OrP2Parameter
        );
        assert_eq!(
            app.process(&[0x00, 0xF6, 0x9C, 0xF9]).status(),
            iso7816::Status::IncorrectP1OrP2Parameter
        );
        assert_eq!(
            app.process(&[0x00, 0xF6, 0x9B, 0x9A]).status(),
            iso7816::Status::IncorrectP1OrP2Parameter
        );
        assert_eq!(
            app.process(&[0xFF, 0xF6, 0x9C, 0x9A]).status(),
            iso7816::Status::ClassNotSupported
        );
    }

    #[test]
    fn move_into_an_occupied_destination_is_refused() {
        let mut app = PivApplet::new();
        mgmt_handshake(&mut app);
        let scalar = fixed_scalar();
        let other = [0x5E; 32];
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9C, &ec_body(&scalar, None, None)))
                .status(),
            iso7816::Status::Success
        );
        assert_eq!(
            app.process(&import_apdu(0x11, 0x9D, &ec_body(&other, None, None)))
                .status(),
            iso7816::Status::Success
        );

        // R1: an occupied destination (the source itself included) is
        // refused and nothing moves.
        assert_eq!(
            app.process(&keyroost_piv::move_key(
                keyroost_piv::Slot::Signature,
                keyroost_piv::Slot::KeyManagement,
            ))
            .status(),
            iso7816::Status::IncorrectDataParameter
        );
        assert_eq!(
            app.process(&keyroost_piv::move_key(
                keyroost_piv::Slot::Signature,
                keyroost_piv::Slot::Signature,
            ))
            .status(),
            iso7816::Status::IncorrectDataParameter
        );
        let source = &app.slots[crate::piv::Slot::Signature];
        let dest = &app.slots[crate::piv::Slot::KeyManagement];
        let Some(SlotKey::EccP256(source_secret)) = &source.key else {
            panic!("invalid slot key")
        };
        assert_eq!(source_secret.to_bytes().as_slice(), &scalar);
        let Some(SlotKey::EccP256(dest_secret)) = &dest.key else {
            panic!("invalid slot key")
        };
        assert_eq!(dest_secret.to_bytes().as_slice(), &other);
    }

    /// A GENERATE APDU for a specific algorithm and slot: the host's own
    /// builder, so the test rides the exact wire shape.
    fn gen_apdu_for(slot: keyroost_piv::Slot, alg: keyroost_piv::KeyAlg) -> Vec<u8> {
        keyroost_piv::generate_key(
            slot,
            alg.id(),
            keyroost_piv::PinPolicy::Default,
            keyroost_piv::TouchPolicy::Default,
        )
    }

    #[test]
    fn generate_produces_each_nist_curve() {
        let mut app = unlocked();
        // 9C: P-384, a 97-byte point on the curve.
        let r = app.process(&gen_apdu_for(
            keyroost_piv::Slot::Signature,
            keyroost_piv::KeyAlg::EccP384,
        ));
        assert_eq!(r.status(), iso7816::Status::Success);
        let point = point_of(&r);
        assert_eq!(point.len(), 97);
        p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("a P-384 point");
        assert_eq!(
            app.slots[crate::piv::Slot::Signature]
                .key
                .as_ref()
                .expect("a key")
                .alg(),
            KeyAlg::EccP384
        );

        // 9D: P-521, a 133-byte point on the curve.
        let r = app.process(&gen_apdu_for(
            keyroost_piv::Slot::KeyManagement,
            keyroost_piv::KeyAlg::EccP521,
        ));
        assert_eq!(r.status(), iso7816::Status::Success);
        let point = point_of(&r);
        assert_eq!(point.len(), 133);
        p521::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("a P-521 point");
        assert_eq!(
            app.slots[crate::piv::Slot::KeyManagement]
                .key
                .as_ref()
                .expect("a key")
                .alg(),
            KeyAlg::EccP521
        );
    }

    #[test]
    fn import_accepts_p384_and_p521_scalars() {
        let mut app = unlocked();
        // P-384 into 9A: the slot then signs with the imported scalar —
        // verify the signature against the point of that scalar.
        let scalar: Vec<u8> = {
            let mut v = vec![0x2B; 48];
            v[47] = 0x01;
            v
        };
        let body = ec_body(&scalar, None, None);
        assert_eq!(
            app.process(&import_apdu(
                keyroost_piv::KeyAlg::EccP384.id(),
                0x9A,
                &body
            ))
            .status(),
            iso7816::Status::Success
        );
        assert_eq!(
            app.slots[crate::piv::Slot::Authentication]
                .key
                .as_ref()
                .expect("a key")
                .alg(),
            KeyAlg::EccP384
        );
        assert_eq!(
            app.slots[crate::piv::Slot::Authentication].origin,
            KeyOrigin::Imported
        );
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        let expected_point = p384::SecretKey::from_slice(&scalar)
            .expect("a valid scalar")
            .public_key()
            .to_sec1_point(false);
        let expected_point = expected_point.as_bytes();
        assert_eq!(
            app.process(&keyroost_piv::verify_pin(b"123456").unwrap())
                .status(),
            iso7816::Status::Success
        );
        let digest = [0x2C; 48];
        let r = app.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP384.id(),
            0x9A,
            &digest,
        ));
        assert_eq!(r.status(), iso7816::Status::Success, "signing GA: {r:?}");
        let sig_der = keyroost_piv::parse_general_auth(r.data(), 0x82).expect("an 82 answer");
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(expected_point).expect("the point");
        let sig = p384::ecdsa::Signature::from_der(sig_der).expect("a DER signature");
        vk.verify_prehash(&digest, &sig).expect("a valid signature");

        // P-521 into the first retired slot. The scalar must sit below
        // the group order, whose leading byte is `0x01`.
        let scalar: Vec<u8> = {
            let mut v = vec![0x01; 66];
            v[65] = 0x01;
            v
        };
        let body = ec_body(&scalar, None, None);
        assert_eq!(
            app.process(&import_apdu(
                keyroost_piv::KeyAlg::EccP521.id(),
                0x82,
                &body
            ))
            .status(),
            iso7816::Status::Success
        );
        assert_eq!(
            app.slots[crate::piv::Slot::retired(1).expect("retired slot 1")]
                .key
                .as_ref()
                .expect("a key")
                .alg(),
            KeyAlg::EccP521
        );
        assert_eq!(
            app.slots[crate::piv::Slot::retired(1).expect("retired slot 1")].origin,
            KeyOrigin::Imported
        );
    }

    #[test]
    fn import_refuses_wrong_length_and_out_of_range_scalars() {
        let mut app = unlocked();
        // A length mismatch for the requested curve: 48 bytes for P-256,
        // 32 bytes for P-384, 48 bytes for P-521.
        let long: Vec<u8> = vec![0x2B; 48];
        let short = [0x2B; 32];
        let mid: Vec<u8> = vec![0x2B; 48];
        assert_eq!(
            app.process(&import_apdu(
                keyroost_piv::KeyAlg::EccP256.id(),
                0x9C,
                &ec_body(&long, None, None)
            ))
            .status(),
            iso7816::Status::IncorrectDataParameter
        );
        assert_eq!(
            app.process(&import_apdu(
                keyroost_piv::KeyAlg::EccP384.id(),
                0x9C,
                &ec_body(&short, None, None)
            ))
            .status(),
            iso7816::Status::IncorrectDataParameter
        );
        assert_eq!(
            app.process(&import_apdu(
                keyroost_piv::KeyAlg::EccP521.id(),
                0x9C,
                &ec_body(&mid, None, None)
            ))
            .status(),
            iso7816::Status::IncorrectDataParameter
        );
        // Zero scalars and group orders, per curve: the range check refuses
        // them before the field conversion.
        for (alg, size) in [
            (keyroost_piv::KeyAlg::EccP256, 32usize),
            (keyroost_piv::KeyAlg::EccP384, 48usize),
            (keyroost_piv::KeyAlg::EccP521, 66usize),
        ] {
            let zero = vec![0u8; size];
            assert_eq!(
                app.process(&import_apdu(alg.id(), 0x9C, &ec_body(&zero, None, None)))
                    .status(),
                iso7816::Status::IncorrectDataParameter
            );
            let order = match alg {
                keyroost_piv::KeyAlg::EccP256 => p256::NistP256::ORDER.to_be_bytes().to_vec(),
                keyroost_piv::KeyAlg::EccP384 => p384::NistP384::ORDER.to_be_bytes().to_vec(),
                keyroost_piv::KeyAlg::EccP521 => p521::NistP521::ORDER.to_be_bytes().to_vec(),
                _ => unreachable!("a NIST curve"),
            };
            assert_eq!(
                app.process(&import_apdu(alg.id(), 0x9C, &ec_body(&order, None, None)))
                    .status(),
                iso7816::Status::IncorrectDataParameter
            );
        }
        // Nothing landed in 9C.
        assert!(app.slots[crate::piv::Slot::Signature].key.is_none());
    }
}
