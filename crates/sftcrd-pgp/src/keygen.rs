//! `OpenPGP` Card v3.4 key generation (`0x47`) and key import (`0xDB`, `3FFF`).

use elliptic_curve::Generate;
use iso7816::Status;
use rsa::{
    BoxedUint,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use sftcrd_apdu::CommandView;
use sftcrd_tlv::{BerLength, BerTag, ValueDecoder, ValueEncoder, tlv_struct};

use crate::{
    PgpApplet, Response,
    pgp::{GenerateMode, KeySlotId, RsaBits},
    pin::PwRef,
};

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

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct PublicKeyTemplate {
        #[tag(0x86)]
        point: Option<Vec<u8>>,
        #[tag(0x81)]
        modulus: Option<Vec<u8>>,
        #[tag(0x82)]
        exponent: Option<Vec<u8>>,
    }
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct GenerateKeyResponse {
        #[tag(0x7F49)]
        public_key: PublicKeyTemplate,
    }
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct ControlReferenceTemplate<'a> {
        #[tag(0xB6)]
        sig: Option<&'a [u8]>,
        #[tag(0xB8)]
        dec: Option<&'a [u8]>,
        #[tag(0xA4)]
        aut: Option<&'a [u8]>,
    }
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    #[header_list]
    struct KeyImportFields<'a> {
        #[tag(0x91)]
        exp: Option<&'a [u8]>,
        #[tag(0x92)]
        prime_p_or_scalar: &'a [u8],
        #[tag(0x93)]
        prime_q: Option<&'a [u8]>,
        #[tag(0x94)]
        crt_u: Option<&'a [u8]>,
        #[tag(0x95)]
        exp_p: Option<&'a [u8]>,
        #[tag(0x96)]
        exp_q: Option<&'a [u8]>,
        #[tag(0x97)]
        modulus: Option<&'a [u8]>,
        #[tag(0x99)]
        ecc_public: Option<&'a [u8]>,
    }
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct ExtendedHeaderList<'a> {
        #[tag(0xB6)]
        sig: Option<&'a [u8]>,
        #[tag(0xB8)]
        dec: Option<&'a [u8]>,
        #[tag(0xA4)]
        aut: Option<&'a [u8]>,
        #[header_list(0x7F48, 0x5F48)]
        fields: KeyImportFields<'a>,
    }
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct PutDataOddBody<'a> {
        #[tag(0x4D)]
        header_list: ExtendedHeaderList<'a>,
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

    /// Encode the public key as a `7F49` BER-TLV template.
    pub(crate) fn encode_public_key(&self) -> Result<Vec<u8>, Status> {
        let template = match self {
            Self::Rsa(_, key) => PublicKeyTemplate {
                point: None,
                modulus: Some(key.n().to_be_bytes().to_vec()),
                exponent: Some(key.e().to_be_bytes_trimmed_vartime().to_vec()),
            },
            Self::P256(secret) => PublicKeyTemplate {
                point: Some(secret.public_key().to_sec1_bytes().to_vec()),
                modulus: None,
                exponent: None,
            },
            Self::P384(secret) => PublicKeyTemplate {
                point: Some(secret.public_key().to_sec1_bytes().to_vec()),
                modulus: None,
                exponent: None,
            },
            Self::P521(secret) => PublicKeyTemplate {
                point: Some(secret.public_key().to_sec1_bytes().to_vec()),
                modulus: None,
                exponent: None,
            },
            Self::Ed25519(signing) => PublicKeyTemplate {
                point: Some(signing.verifying_key().to_bytes().to_vec()),
                modulus: None,
                exponent: None,
            },
            Self::X25519(secret) => PublicKeyTemplate {
                point: Some(x25519_dalek::PublicKey::from(secret).to_bytes().to_vec()),
                modulus: None,
                exponent: None,
            },
        };

        GenerateKeyResponse {
            public_key: template,
        }
        .encode_top_level()
        .map_err(|_| Status::MemoryFailure)
    }
}

impl PgpApplet {
    /// `GENERATE ASYMMETRIC KEY PAIR` (`0x47`):
    /// - `P1 = 0x80`: generate a new key pair for the CRT slot (PW3-gated).
    /// - `P1 = 0x81`: read the existing public key for the CRT slot (no PIN).
    pub(crate) fn process_generate_key_pair(&mut self, cmd: &CommandView<'_>) -> Response {
        if cmd.p2 != 0x00 {
            return Status::IncorrectP1OrP2Parameter.into();
        }
        let Some(mode) = GenerateMode::from_u8(cmd.p1) else {
            return Status::IncorrectP1OrP2Parameter.into();
        };
        if cmd.data().is_empty() {
            return Status::WrongLength.into();
        }
        let Ok(slot_id) = parse_crt(cmd.data()) else {
            return Status::IncorrectDataParameter.into();
        };

        match mode {
            GenerateMode::Generate => {
                if !self.pins.is_verified(PwRef::Pw3Admin) {
                    return Status::SecurityStatusNotSatisfied.into();
                }
                let alg = match self.data.slot(slot_id).slot_alg() {
                    Ok(alg) => alg,
                    Err(status) => return status.into(),
                };
                let key = match SlotKey::generate(alg) {
                    Ok(key) => key,
                    Err(status) => return status.into(),
                };
                let resp = match key.encode_public_key() {
                    Ok(bytes) => bytes,
                    Err(status) => return status.into(),
                };
                let slot = self.data.slot_mut(slot_id);
                slot.fingerprint = [0u8; 20];
                slot.generation_time = 0;
                slot.key = Some(key);
                if slot_id == KeySlotId::Sig {
                    self.data.ds_counter = 0;
                }
                resp.into()
            }
            GenerateMode::ReadPublicKey => {
                let Some(key) = &self.data.slot(slot_id).key else {
                    return Status::KeyReferenceNotFound.into();
                };
                match key.encode_public_key() {
                    Ok(bytes) => bytes.into(),
                    Err(status) => status.into(),
                }
            }
        }
    }

    /// `PUT DATA odd` (`0xDB`, `P1P2 = 3FFF`): import an asymmetric key via a `4D`
    /// Extended Header List.
    pub(crate) fn process_put_data_odd(&mut self, cmd: &CommandView<'_>) -> Response {
        if cmd.p1 != 0x3F || cmd.p2 != 0xFF {
            return Status::IncorrectP1OrP2Parameter.into();
        }
        if !self.pins.is_verified(PwRef::Pw3Admin) {
            return Status::SecurityStatusNotSatisfied.into();
        }

        match self.import_extended_header_list(cmd.data()) {
            Ok(()) => Status::Success.into(),
            Err(status) => status.into(),
        }
    }

    fn import_extended_header_list(&mut self, data: &[u8]) -> Result<(), Status> {
        let Ok(body) = PutDataOddBody::decode(data) else {
            return Err(Status::IncorrectDataParameter);
        };
        let ehl = body.header_list;
        let slot_id = resolve_crt(ehl.sig, ehl.dec, ehl.aut)?;

        let alg = self.data.slot(slot_id).slot_alg()?;
        let key = match alg {
            SlotAlg::Rsa { n_bits, .. } => import_rsa(n_bits, &ehl.fields)?,
            SlotAlg::P256 | SlotAlg::P384 | SlotAlg::P521 | SlotAlg::Ed25519 | SlotAlg::X25519 => {
                import_ecc(alg, &ehl.fields)?
            }
        };

        self.data.slot_mut(slot_id).key = Some(key);
        if slot_id == KeySlotId::Sig {
            self.data.ds_counter = 0;
        }
        Ok(())
    }
}

fn resolve_crt(
    sig: Option<&[u8]>,
    dec: Option<&[u8]>,
    aut: Option<&[u8]>,
) -> Result<KeySlotId, Status> {
    match (sig, dec, aut) {
        (Some([]), None, None) => Ok(KeySlotId::Sig),
        (None, Some([]), None) => Ok(KeySlotId::Dec),
        (None, None, Some([])) => Ok(KeySlotId::Aut),
        _ => Err(Status::IncorrectDataParameter),
    }
}

fn parse_crt(data: &[u8]) -> Result<KeySlotId, Status> {
    let Ok(crt) = ControlReferenceTemplate::decode(data) else {
        return Err(Status::IncorrectDataParameter);
    };
    resolve_crt(crt.sig, crt.dec, crt.aut)
}

fn import_rsa(bits: RsaBits, fields: &KeyImportFields<'_>) -> Result<SlotKey, Status> {
    if fields.ecc_public.is_some() {
        return Err(Status::IncorrectDataParameter);
    }
    let (Some(e_bytes), Some(q_bytes)) = (fields.exp, fields.prime_q) else {
        return Err(Status::IncorrectDataParameter);
    };
    let p_bytes = fields.prime_p_or_scalar;
    if e_bytes.is_empty() || p_bytes.is_empty() || q_bytes.is_empty() {
        return Err(Status::IncorrectDataParameter);
    }

    let half = bits.modulus_bytes() / 2;
    if p_bytes.len() > half || q_bytes.len() > half {
        return Err(Status::IncorrectDataParameter);
    }
    if let Some(u_bytes) = fields.crt_u
        && (u_bytes.is_empty() || u_bytes.len() > half)
    {
        return Err(Status::IncorrectDataParameter);
    }

    let e_uint = BoxedUint::from_be_slice_vartime(e_bytes);
    let p_uint = BoxedUint::from_be_slice_vartime(p_bytes);
    let q_uint = BoxedUint::from_be_slice_vartime(q_bytes);

    let mut key = rsa::PrivateKey::from_p_q(p_uint, q_uint, e_uint)
        .map_err(|_| Status::IncorrectDataParameter)?;
    if key.n().to_be_bytes().len() != bits.modulus_bytes() {
        return Err(Status::IncorrectDataParameter);
    }
    key.precompute()
        .map_err(|_| Status::IncorrectDataParameter)?;

    if let Some(n_bytes) = fields.modulus
        && (n_bytes.is_empty()
            || key.n().clone().get() != BoxedUint::from_be_slice_vartime(n_bytes))
    {
        return Err(Status::IncorrectDataParameter);
    }
    if let Some(dp_bytes) = fields.exp_p
        && (dp_bytes.is_empty() || key.dp() != Some(&BoxedUint::from_be_slice_vartime(dp_bytes)))
    {
        return Err(Status::IncorrectDataParameter);
    }
    if let Some(dq_bytes) = fields.exp_q
        && (dq_bytes.is_empty() || key.dq() != Some(&BoxedUint::from_be_slice_vartime(dq_bytes)))
    {
        return Err(Status::IncorrectDataParameter);
    }

    Ok(SlotKey::Rsa(bits, key))
}

fn import_ecc(alg: SlotAlg, fields: &KeyImportFields<'_>) -> Result<SlotKey, Status> {
    if fields.exp.is_some()
        || fields.prime_q.is_some()
        || fields.crt_u.is_some()
        || fields.exp_p.is_some()
        || fields.exp_q.is_some()
        || fields.modulus.is_some()
    {
        return Err(Status::IncorrectDataParameter);
    }

    let scalar = fields.prime_p_or_scalar;
    if scalar.is_empty() || fields.ecc_public.is_some_and(<[u8]>::is_empty) {
        return Err(Status::IncorrectDataParameter);
    }

    match alg {
        SlotAlg::P256 => {
            let secret = elliptic_curve::SecretKey::<p256::NistP256>::from_slice(scalar)
                .map_err(|_| Status::IncorrectDataParameter)?;
            if let Some(pub_bytes) = fields.ecc_public
                && pub_bytes != secret.public_key().to_sec1_bytes().as_ref()
            {
                return Err(Status::IncorrectDataParameter);
            }
            Ok(SlotKey::P256(secret))
        }
        SlotAlg::P384 => {
            let secret = elliptic_curve::SecretKey::<p384::NistP384>::from_slice(scalar)
                .map_err(|_| Status::IncorrectDataParameter)?;
            if let Some(pub_bytes) = fields.ecc_public
                && pub_bytes != secret.public_key().to_sec1_bytes().as_ref()
            {
                return Err(Status::IncorrectDataParameter);
            }
            Ok(SlotKey::P384(secret))
        }
        SlotAlg::P521 => {
            let secret = elliptic_curve::SecretKey::<p521::NistP521>::from_slice(scalar)
                .map_err(|_| Status::IncorrectDataParameter)?;
            if let Some(pub_bytes) = fields.ecc_public
                && pub_bytes != secret.public_key().to_sec1_bytes().as_ref()
            {
                return Err(Status::IncorrectDataParameter);
            }
            Ok(SlotKey::P521(secret))
        }
        SlotAlg::Ed25519 => {
            let seed: [u8; 32] = scalar
                .try_into()
                .map_err(|_| Status::IncorrectDataParameter)?;
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
            if let Some(pub_bytes) = fields.ecc_public
                && pub_bytes != signing.verifying_key().as_bytes()
            {
                return Err(Status::IncorrectDataParameter);
            }
            Ok(SlotKey::Ed25519(signing))
        }
        SlotAlg::X25519 => {
            let raw: [u8; 32] = scalar
                .try_into()
                .map_err(|_| Status::IncorrectDataParameter)?;
            let secret = x25519_dalek::StaticSecret::from(raw);
            if let Some(pub_bytes) = fields.ecc_public
                && pub_bytes != x25519_dalek::PublicKey::from(&secret).to_bytes().as_slice()
            {
                return Err(Status::IncorrectDataParameter);
            }
            Ok(SlotKey::X25519(secret))
        }
        SlotAlg::Rsa { .. } => Err(Status::IncorrectDataParameter),
    }
}

#[cfg(test)]
mod tests {
    use keyroost_openpgp::{
        EccPrivateKeyParts, KeyAlg, KeyCrt, PW3_ADMIN, PublicKey, RsaImportFormat,
        RsaPrivateKeyParts, TAG_SECURITY_SUPPORT, generate_key, import_ecc_key,
        import_ecc_key_chained, import_rsa_key, import_rsa_key_chained, parse_generated_public_key,
        parse_signature_counter, put_algorithm_attributes, read_public_key, verify,
    };

    use super::*;

    fn verify_pw3(applet: &mut PgpApplet) {
        assert_eq!(
            applet.process(&verify(PW3_ADMIN, b"12345678")).status(),
            Status::Success
        );
    }

    fn set_slot_alg(applet: &mut PgpApplet, crt: KeyCrt, alg: KeyAlg) {
        let attrs = alg.attributes(crt).unwrap();
        assert_eq!(
            applet
                .process(&put_algorithm_attributes(crt, &attrs))
                .status(),
            Status::Success
        );
    }

    fn ds_counter(applet: &mut PgpApplet) -> u32 {
        let resp = applet.process(&keyroost_openpgp::get_data(TAG_SECURITY_SUPPORT));
        assert_eq!(resp.status(), Status::Success);
        parse_signature_counter(resp.data()).unwrap()
    }

    fn exchange_via_dispatch(applet: &mut PgpApplet, apdus: &[&[u8]]) -> Vec<Vec<u8>> {
        let contact = apdu_dispatch::interchanges::Channel::new();
        let (mut requester, contact_rp) = contact.split().unwrap();
        let contactless = apdu_dispatch::interchanges::Channel::new();
        let (_, contactless_rp) = contactless.split().unwrap();
        let mut dispatch = apdu_dispatch::dispatch::ApduDispatch::new(contact_rp, contactless_rp);

        let mut send = |apdu: &[u8]| -> Vec<u8> {
            let data = apdu_dispatch::interchanges::Data::from_slice(apdu).unwrap();
            requester.request(data).unwrap();
            loop {
                match dispatch.poll(&mut [applet]) {
                    Some(apdu_dispatch::dispatch::Interface::Contact) => {
                        return requester.take_response().unwrap().to_vec();
                    }
                    Some(_) => panic!("unexpected contactless response"),
                    None => {}
                }
            }
        };

        let select_resp = send(&keyroost_openpgp::select());
        assert_eq!(&select_resp[select_resp.len() - 2..], &[0x90, 0x00]);
        apdus.iter().map(|apdu| send(apdu)).collect()
    }

    #[test]
    fn generate_and_read_public_key_all_ecc_algorithms() {
        let mut applet = PgpApplet::new();

        // Empty slots reject READ PUBLIC KEY
        for crt in [KeyCrt::Sign, KeyCrt::Decrypt, KeyCrt::Auth] {
            assert_eq!(
                applet.process(&read_public_key(crt)).status(),
                Status::KeyReferenceNotFound
            );
        }

        // Generating without PW3 fails
        assert_eq!(
            applet.process(&generate_key(KeyCrt::Sign)).status(),
            Status::SecurityStatusNotSatisfied
        );

        let cases = [
            (KeyCrt::Sign, KeyAlg::NistP256, 65usize),
            (KeyCrt::Sign, KeyAlg::NistP384, 97),
            (KeyCrt::Sign, KeyAlg::NistP521, 133),
            (KeyCrt::Sign, KeyAlg::Ed25519, 32),
            (KeyCrt::Decrypt, KeyAlg::NistP256, 65),
            (KeyCrt::Decrypt, KeyAlg::NistP384, 97),
            (KeyCrt::Decrypt, KeyAlg::NistP521, 133),
            (KeyCrt::Decrypt, KeyAlg::X25519, 32),
            (KeyCrt::Auth, KeyAlg::NistP256, 65),
            (KeyCrt::Auth, KeyAlg::Ed25519, 32),
        ];

        verify_pw3(&mut applet);
        for (crt, alg, expected_len) in cases {
            set_slot_alg(&mut applet, crt, alg);

            let gen_resp = applet.process(&generate_key(crt));
            assert_eq!(gen_resp.status(), Status::Success);
            let PublicKey::Ecc { point: gen_point } =
                parse_generated_public_key(gen_resp.data()).unwrap()
            else {
                panic!("expected ECC public key for {alg:?}");
            };
            assert_eq!(gen_point.len(), expected_len);

            // READ PUBLIC KEY works even after ending session (no PIN required)
            applet.pins.session_end();
            let read_resp = applet.process(&read_public_key(crt));
            assert_eq!(read_resp.status(), Status::Success);
            let PublicKey::Ecc { point: read_point } =
                parse_generated_public_key(read_resp.data()).unwrap()
            else {
                panic!("expected ECC public key on read for {alg:?}");
            };
            assert_eq!(read_point, gen_point);

            verify_pw3(&mut applet);
        }
    }

    #[test]
    fn generate_and_read_public_key_rsa_sizes() {
        let mut applet = PgpApplet::new();
        verify_pw3(&mut applet);

        for (alg, expected_mod_bytes) in [
            (KeyAlg::Rsa2048, 256usize),
            (KeyAlg::Rsa3072, 384),
            (KeyAlg::Rsa4096, 512),
        ] {
            set_slot_alg(&mut applet, KeyCrt::Sign, alg);
            let gen_resp = applet.process(&generate_key(KeyCrt::Sign));
            assert_eq!(gen_resp.status(), Status::Success);
            let PublicKey::Rsa { modulus, exponent } =
                parse_generated_public_key(gen_resp.data()).unwrap()
            else {
                panic!("expected RSA public key for {alg:?}");
            };
            assert_eq!(modulus.len(), expected_mod_bytes);
            assert_eq!(exponent, &[0x01, 0x00, 0x01]);

            let read_resp = applet.process(&read_public_key(KeyCrt::Sign));
            assert_eq!(read_resp.status(), Status::Success);
            let PublicKey::Rsa {
                modulus: read_mod,
                exponent: read_exp,
            } = parse_generated_public_key(read_resp.data()).unwrap()
            else {
                panic!("expected RSA public key on read");
            };
            assert_eq!(read_mod, modulus);
            assert_eq!(read_exp, exponent);
        }
    }

    #[test]
    fn generate_or_import_sign_key_resets_ds_counter() {
        let mut applet = PgpApplet::new();
        verify_pw3(&mut applet);
        set_slot_alg(&mut applet, KeyCrt::Sign, KeyAlg::Ed25519);
        set_slot_alg(&mut applet, KeyCrt::Decrypt, KeyAlg::X25519);

        // Non-Sign keygen preserves DS counter
        applet.data.ds_counter = 42;
        assert_eq!(
            applet.process(&generate_key(KeyCrt::Decrypt)).status(),
            Status::Success
        );
        assert_eq!(ds_counter(&mut applet), 42);

        // Sign keygen resets DS counter to 0
        assert_eq!(
            applet.process(&generate_key(KeyCrt::Sign)).status(),
            Status::Success
        );
        assert_eq!(ds_counter(&mut applet), 0);

        // Sign key import resets DS counter to 0
        applet.data.ds_counter = 7;
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let seed = signing.to_bytes();
        let apdu = import_ecc_key(
            KeyCrt::Sign,
            &EccPrivateKeyParts {
                scalar: &seed,
                public: None,
            },
            32,
        )
        .unwrap();
        assert_eq!(applet.process(&apdu).status(), Status::Success);
        assert_eq!(ds_counter(&mut applet), 0);
    }

    #[test]
    fn import_rsa_standard_and_crt_extended_and_chained() {
        let mut applet = PgpApplet::new();
        verify_pw3(&mut applet);

        let key = rsa::PrivateKey::new(&mut rand::rng(), 2048).unwrap();
        let primes = key.primes();
        let p_bytes = primes[0].to_be_bytes();
        let q_bytes = primes[1].to_be_bytes();
        let e_bytes = key.e().to_be_bytes_trimmed_vartime();
        let n_bytes = key.n().to_be_bytes();
        let exp_p_bytes = key.dp().unwrap().to_be_bytes();
        let q_crt_exp = key.dq().unwrap().to_be_bytes();
        let u_bytes = [0x01u8; 128];

        let parts = RsaPrivateKeyParts {
            e: &e_bytes,
            p: &p_bytes,
            q: &q_bytes,
            u: &u_bytes,
            dp: &exp_p_bytes,
            dq: &q_crt_exp,
            n: &n_bytes,
        };

        // 1. Extended-length Standard format into Sign slot
        set_slot_alg(&mut applet, KeyCrt::Sign, KeyAlg::Rsa2048);
        let apdu_std = import_rsa_key(KeyCrt::Sign, &parts, RsaImportFormat::Standard, 32).unwrap();
        assert_eq!(applet.process(&apdu_std).status(), Status::Success);
        let PublicKey::Rsa { modulus, exponent } =
            parse_generated_public_key(applet.process(&read_public_key(KeyCrt::Sign)).data())
                .unwrap()
        else {
            panic!("expected RSA public key");
        };
        assert_eq!(modulus, n_bytes.as_ref());
        assert_eq!(exponent, e_bytes.as_ref());

        // 2. Chained CRT+Modulus format into Auth slot via ApduDispatch (254-byte chunks)
        let mut dispatch_applet = PgpApplet::new();
        let verify_apdu = verify(PW3_ADMIN, b"12345678");
        let auth_attrs = KeyAlg::Rsa2048.attributes(KeyCrt::Auth).unwrap();
        let attr_apdu = put_algorithm_attributes(KeyCrt::Auth, &auth_attrs);
        let chained = import_rsa_key_chained(
            KeyCrt::Auth,
            &parts,
            RsaImportFormat::CrtWithModulus,
            32,
            254,
        )
        .unwrap();
        assert!(chained.len() > 1);
        let mut apdus: Vec<&[u8]> = vec![&verify_apdu, &attr_apdu];
        apdus.extend(chained.iter().map(Vec::as_slice));
        for resp in exchange_via_dispatch(&mut dispatch_applet, &apdus) {
            assert_eq!(resp, [0x90, 0x00]);
        }
        let PublicKey::Rsa { modulus, .. } = parse_generated_public_key(
            dispatch_applet
                .process(&read_public_key(KeyCrt::Auth))
                .data(),
        )
        .unwrap() else {
            panic!("expected RSA public key");
        };
        assert_eq!(modulus, n_bytes.as_ref());

        // 3. Reject mismatched CRT dp
        let mut bad_dp = exp_p_bytes.to_vec();
        bad_dp[0] ^= 0xFF;
        let bad_parts = RsaPrivateKeyParts {
            dp: &bad_dp,
            ..parts
        };
        let bad_apdu = import_rsa_key(KeyCrt::Sign, &bad_parts, RsaImportFormat::Crt, 32).unwrap();
        assert_eq!(
            applet.process(&bad_apdu).status(),
            Status::IncorrectDataParameter
        );
    }

    #[test]
    fn import_ecc_nist_extended_and_chained() {
        let mut applet = PgpApplet::new();
        verify_pw3(&mut applet);

        // P-256 (with public point, chained via ApduDispatch)
        let mut dispatch_applet = PgpApplet::new();
        let verify_apdu = verify(PW3_ADMIN, b"12345678");
        let p256_attrs = KeyAlg::NistP256.attributes(KeyCrt::Sign).unwrap();
        let attr_apdu = put_algorithm_attributes(KeyCrt::Sign, &p256_attrs);
        let p256_secret =
            elliptic_curve::SecretKey::<p256::NistP256>::generate_from_rng(&mut rand::rng());
        let p256_scalar = p256_secret.to_bytes();
        let p256_pub = p256_secret.public_key().to_sec1_bytes();
        let p256_chained = import_ecc_key_chained(
            KeyCrt::Sign,
            &EccPrivateKeyParts {
                scalar: &p256_scalar,
                public: Some(&p256_pub),
            },
            32,
            40,
        )
        .unwrap();
        assert!(p256_chained.len() > 1);
        let mut apdus: Vec<&[u8]> = vec![&verify_apdu, &attr_apdu];
        apdus.extend(p256_chained.iter().map(Vec::as_slice));
        for resp in exchange_via_dispatch(&mut dispatch_applet, &apdus) {
            assert_eq!(resp, [0x90, 0x00]);
        }
        let PublicKey::Ecc { point } = parse_generated_public_key(
            dispatch_applet
                .process(&read_public_key(KeyCrt::Sign))
                .data(),
        )
        .unwrap() else {
            panic!("expected ECC public key");
        };
        assert_eq!(point, p256_pub.as_ref());

        // P-384 (without public point, extended)
        set_slot_alg(&mut applet, KeyCrt::Auth, KeyAlg::NistP384);
        let p384_secret =
            elliptic_curve::SecretKey::<p384::NistP384>::generate_from_rng(&mut rand::rng());
        let p384_scalar = p384_secret.to_bytes();
        let p384_pub = p384_secret.public_key().to_sec1_bytes();
        let apdu_p384 = import_ecc_key(
            KeyCrt::Auth,
            &EccPrivateKeyParts {
                scalar: &p384_scalar,
                public: None,
            },
            48,
        )
        .unwrap();
        assert_eq!(applet.process(&apdu_p384).status(), Status::Success);
        let PublicKey::Ecc { point } =
            parse_generated_public_key(applet.process(&read_public_key(KeyCrt::Auth)).data())
                .unwrap()
        else {
            panic!("expected ECC public key");
        };
        assert_eq!(point, p384_pub.as_ref());

        // P-521 (with public point, extended)
        set_slot_alg(&mut applet, KeyCrt::Sign, KeyAlg::NistP521);
        let p521_secret =
            elliptic_curve::SecretKey::<p521::NistP521>::generate_from_rng(&mut rand::rng());
        let p521_scalar = p521_secret.to_bytes();
        let p521_pub = p521_secret.public_key().to_sec1_bytes();
        let apdu_p521 = import_ecc_key(
            KeyCrt::Sign,
            &EccPrivateKeyParts {
                scalar: &p521_scalar,
                public: Some(&p521_pub),
            },
            66,
        )
        .unwrap();
        assert_eq!(applet.process(&apdu_p521).status(), Status::Success);
    }

    #[test]
    fn import_x25519_and_reject_mismatched_public() {
        let mut applet = PgpApplet::new();
        verify_pw3(&mut applet);

        // X25519 (with public point, extended)
        set_slot_alg(&mut applet, KeyCrt::Decrypt, KeyAlg::X25519);
        let x_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand::rng());
        let x_pub = x25519_dalek::PublicKey::from(&x_secret).to_bytes();
        let x_raw = x_secret.to_bytes();
        let apdu_x = import_ecc_key(
            KeyCrt::Decrypt,
            &EccPrivateKeyParts {
                scalar: &x_raw,
                public: Some(&x_pub),
            },
            32,
        )
        .unwrap();
        assert_eq!(applet.process(&apdu_x).status(), Status::Success);
        let PublicKey::Ecc { point } =
            parse_generated_public_key(applet.process(&read_public_key(KeyCrt::Decrypt)).data())
                .unwrap()
        else {
            panic!("expected X25519 public key");
        };
        assert_eq!(point, x_pub);

        // Reject mismatched public point (tag 99)
        let mut bad_pub = x_pub;
        bad_pub[0] ^= 0xFF;
        let bad_apdu = import_ecc_key(
            KeyCrt::Decrypt,
            &EccPrivateKeyParts {
                scalar: &x_raw,
                public: Some(&bad_pub),
            },
            32,
        )
        .unwrap();
        assert_eq!(
            applet.process(&bad_apdu).status(),
            Status::IncorrectDataParameter
        );
    }

    #[test]
    fn put_data_odd_requires_pw3_and_rejects_raw_chained_cla() {
        let mut applet = PgpApplet::new();
        let signing = ed25519_dalek::SigningKey::generate(&mut rand::rng());
        let seed = signing.to_bytes();
        let apdu = import_ecc_key(
            KeyCrt::Sign,
            &EccPrivateKeyParts {
                scalar: &seed,
                public: None,
            },
            32,
        )
        .unwrap();

        // Fails without PW3
        assert_eq!(
            applet.process(&apdu).status(),
            Status::SecurityStatusNotSatisfied
        );

        // Raw chained CLA is rejected when bypassing apdu-dispatch
        let chained = import_ecc_key_chained(
            KeyCrt::Sign,
            &EccPrivateKeyParts {
                scalar: &seed,
                public: None,
            },
            32,
            20,
        )
        .unwrap();
        assert_eq!(
            applet.process(&chained[0]).status(),
            Status::ClaNotSupported
        );
    }
}
