//! `OpenPGP` Card v3.4 cryptographic operations: `PSO:CDS` (`0x2A 9E9A`),
//! `PSO:DECIPHER` (`0x2A 8086`), and `INTERNAL AUTHENTICATE` (`0x88 0000`).

use iso7816::Status;
use sftcrd_apdu::CommandView;
use sftcrd_tlv::{BerLength, BerTag, ValueDecoder, tlv_struct};

use crate::{PgpApplet, Response, pgp::PsoOp, pin::PwRef, slot::SlotKey};

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct EcdhPublicKey<'a> {
        #[tag(0x86)]
        point: &'a [u8],
    }
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct EcdhCipherDo<'a> {
        #[tag(0x7F49)]
        public_key: EcdhPublicKey<'a>,
    }
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct EcdhRequest<'a> {
        #[tag(0xA6)]
        cipher_do: EcdhCipherDo<'a>,
    }
}

fn decode_ecdh_point(data: &[u8]) -> Result<&[u8], Status> {
    let req = EcdhRequest::decode(data).map_err(|_| Status::IncorrectDataParameter)?;
    Ok(req.cipher_do.public_key.point)
}

impl PgpApplet {
    /// `PERFORM SECURITY OPERATION` (`0x2A`): dispatch `PSO:CDS` (`9E 9A`) and
    /// `PSO:DECIPHER` (`80 86`).
    pub(crate) fn process_pso(&mut self, cmd: &CommandView<'_>) -> Response {
        match PsoOp::from_p1p2(cmd.p1, cmd.p2) {
            Some(PsoOp::ComputeDigitalSignature) => self.process_pso_cds(cmd.data()),
            Some(PsoOp::Decipher) => self.process_pso_decipher(cmd.data()),
            None => Status::IncorrectP1OrP2Parameter.into(),
        }
    }

    /// `PSO:CDS` (`0x2A 9E9A`): sign with the Sign (`B6`) slot key under PW1 (`0x81`).
    fn process_pso_cds(&mut self, data: &[u8]) -> Response {
        if !self.pins.is_verified(PwRef::Pw1Sign) {
            return Status::SecurityStatusNotSatisfied.into();
        }
        let Some(ref key) = self.data.sig.key else {
            return Status::ConditionsOfUseNotSatisfied.into();
        };
        let sig = match key.sign(data) {
            Ok(sig) => sig,
            Err(status) => return status.into(),
        };
        self.data.incr_ds_counter();
        if !self.pins.pw1_valid_multiple() {
            self.pins.clear_verified(PwRef::Pw1Sign);
        }
        Response::from_slice(&sig)
    }

    /// `PSO:DECIPHER` (`0x2A 8086`): decrypt or perform ECDH with the Decrypt (`B8`)
    /// slot key under PW1 (`0x82`).
    fn process_pso_decipher(&self, data: &[u8]) -> Response {
        if !self.pins.is_verified(PwRef::Pw1Other) {
            return Status::SecurityStatusNotSatisfied.into();
        }
        let Some(ref key) = self.data.dec.key else {
            return Status::ConditionsOfUseNotSatisfied.into();
        };
        let result = match key {
            SlotKey::Rsa(_, _) => {
                let Some((&0x00, ciphertext)) = data.split_first() else {
                    return Status::IncorrectDataParameter.into();
                };
                key.decrypt_rsa(ciphertext)
            }
            SlotKey::P256(_) | SlotKey::P384(_) | SlotKey::P521(_) | SlotKey::X25519(_) => {
                let point = match decode_ecdh_point(data) {
                    Ok(point) => point,
                    Err(status) => return status.into(),
                };
                key.ecdh(point)
            }
            SlotKey::Ed25519(_) => Err(Status::ConditionsOfUseNotSatisfied),
        };
        match result {
            Ok(plain) => Response::from_slice(&plain),
            Err(status) => status.into(),
        }
    }

    /// `INTERNAL AUTHENTICATE` (`0x88 0000`): sign with the Auth (`A4`) slot key
    /// under PW1 (`0x82`).
    pub(crate) fn process_internal_authenticate(&self, cmd: &CommandView<'_>) -> Response {
        if cmd.p1 != 0x00 || cmd.p2 != 0x00 {
            return Status::IncorrectP1OrP2Parameter.into();
        }
        if !self.pins.is_verified(PwRef::Pw1Other) {
            return Status::SecurityStatusNotSatisfied.into();
        }
        let Some(ref key) = self.data.aut.key else {
            return Status::ConditionsOfUseNotSatisfied.into();
        };
        match key.sign(cmd.data()) {
            Ok(sig) => Response::from_slice(&sig),
            Err(status) => status.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use iso7816::Status;
    use keyroost_openpgp::{
        KeyAlg, KeyCrt, PW1_OTHER, PW1_SIGN, PW3_ADMIN, PublicKey, TAG_SECURITY_SUPPORT,
        ecdh_cipher_do, generate_key, get_data, internal_authenticate, parse_generated_public_key,
        parse_signature_counter, pso_compute_signature, pso_decipher, pso_decipher_chained,
        put_algorithm_attributes, put_data, verify,
    };
    use rsa::BoxedUint;

    use crate::PgpApplet;

    fn verify_pw(applet: &mut PgpApplet, pw_ref: u8, pin: &[u8]) {
        assert_eq!(
            applet.process(&verify(pw_ref, pin)).status(),
            Status::Success
        );
    }

    fn set_and_generate(applet: &mut PgpApplet, crt: KeyCrt, alg: KeyAlg) -> PublicKey {
        let attrs = alg.attributes(crt).expect("supported slot/alg");
        assert_eq!(
            applet
                .process(&put_algorithm_attributes(crt, &attrs))
                .status(),
            Status::Success
        );
        let resp = applet.process(&generate_key(crt));
        assert_eq!(resp.status(), Status::Success);
        parse_generated_public_key(resp.data()).unwrap()
    }

    fn ds_counter(applet: &mut PgpApplet) -> u32 {
        let resp = applet.process(&get_data(TAG_SECURITY_SUPPORT));
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
    fn pso_cds_enforces_pw1_valid_multiple_and_ds_counter() {
        let mut applet = PgpApplet::new();
        verify_pw(&mut applet, PW3_ADMIN, b"12345678");
        let PublicKey::Ecc { point, .. } =
            set_and_generate(&mut applet, KeyCrt::Sign, KeyAlg::Ed25519)
        else {
            panic!("expected Ed25519 key");
        };
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(point.as_slice().try_into().unwrap()).unwrap();
        let msg = b"openpgp-cds-test";

        verify_pw(&mut applet, PW1_OTHER, b"123456");
        assert_eq!(
            applet.process(&pso_compute_signature(msg)).status(),
            Status::SecurityStatusNotSatisfied
        );
        assert_eq!(ds_counter(&mut applet), 0);

        verify_pw(&mut applet, PW1_SIGN, b"123456");
        let r1 = applet.process(&pso_compute_signature(msg));
        assert_eq!(r1.status(), Status::Success);
        vk.verify_strict(
            msg,
            &ed25519_dalek::Signature::from_slice(r1.data()).unwrap(),
        )
        .unwrap();
        assert_eq!(ds_counter(&mut applet), 1);

        // Consumed when pw1_valid_multiple is false
        assert_eq!(
            applet.process(&pso_compute_signature(msg)).status(),
            Status::SecurityStatusNotSatisfied
        );

        // Enable pw1_valid_multiple
        assert_eq!(
            applet.process(&put_data(0x00C4, &[0x01])).status(),
            Status::Success
        );
        verify_pw(&mut applet, PW1_SIGN, b"123456");
        for expected in 2..=3 {
            let r = applet.process(&pso_compute_signature(msg));
            assert_eq!(r.status(), Status::Success);
            assert_eq!(ds_counter(&mut applet), expected);
        }
    }

    #[test]
    fn pso_decipher_chained_and_internal_authenticate() {
        let mut applet = PgpApplet::new();
        verify_pw(&mut applet, PW3_ADMIN, b"12345678");

        // Auth slot (Ed25519)
        let PublicKey::Ecc { point, .. } =
            set_and_generate(&mut applet, KeyCrt::Auth, KeyAlg::Ed25519)
        else {
            panic!("expected Ed25519 key");
        };
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(point.as_slice().try_into().unwrap()).unwrap();
        verify_pw(&mut applet, PW1_OTHER, b"123456");
        let challenge = b"ssh-auth-challenge";
        let r_auth = applet.process(&internal_authenticate(challenge));
        assert_eq!(r_auth.status(), Status::Success);
        vk.verify_strict(
            challenge,
            &ed25519_dalek::Signature::from_slice(r_auth.data()).unwrap(),
        )
        .unwrap();
        assert_eq!(ds_counter(&mut applet), 0);

        // Decrypt slot (RSA-2048) via chained APDU
        let PublicKey::Rsa { modulus, exponent } =
            set_and_generate(&mut applet, KeyCrt::Decrypt, KeyAlg::Rsa2048)
        else {
            panic!("expected RSA key");
        };
        let pub_key = rsa::PublicKey::new(
            BoxedUint::from_be_slice_vartime(&modulus),
            BoxedUint::from_be_slice_vartime(&exponent),
        )
        .unwrap();
        let plaintext = b"session-key-32-bytes-0123456789!";
        let k = modulus.len();
        let mut em = vec![0x00, 0x02];
        em.resize(k - plaintext.len() - 1, 0xA5);
        em.push(0x00);
        em.extend_from_slice(plaintext);
        let ct = rsa::hazmat::rsa_encrypt(&pub_key, &BoxedUint::from_be_slice_vartime(&em))
            .unwrap()
            .to_be_bytes();
        let mut cipher_do = vec![0x00; 1 + k];
        let offset = 1 + k - ct.len();
        cipher_do[offset..].copy_from_slice(&ct);

        let verify_apdu = verify(PW1_OTHER, b"123456");
        let chained = pso_decipher_chained(&cipher_do, 254);
        assert!(chained.len() > 1);
        let mut apdus: Vec<&[u8]> = vec![&verify_apdu];
        apdus.extend(chained.iter().map(Vec::as_slice));
        let resps = exchange_via_dispatch(&mut applet, &apdus);
        assert_eq!(resps[0], [0x90, 0x00]);
        let last = resps.last().unwrap();
        assert_eq!(&last[last.len() - 2..], &[0x90, 0x00]);
        assert_eq!(&last[..last.len() - 2], plaintext);

        // ECDH via PSO:DECIPHER
        verify_pw(&mut applet, PW3_ADMIN, b"12345678");
        let PublicKey::Ecc { point, .. } =
            set_and_generate(&mut applet, KeyCrt::Decrypt, KeyAlg::X25519)
        else {
            panic!("expected X25519 key");
        };
        let card_pub = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(point).unwrap());
        let eph = x25519_dalek::EphemeralSecret::random_from_rng(&mut rand::rng());
        let eph_pub = x25519_dalek::PublicKey::from(&eph);
        let expected = eph.diffie_hellman(&card_pub);
        verify_pw(&mut applet, PW1_OTHER, b"123456");
        let r_ecdh = applet.process(&pso_decipher(&ecdh_cipher_do(eph_pub.as_bytes())));
        assert_eq!(r_ecdh.status(), Status::Success);
        assert_eq!(r_ecdh.data(), expected.as_bytes());
    }

    #[test]
    fn pso_and_internal_auth_error_conditions() {
        let mut applet = PgpApplet::new();
        verify_pw(&mut applet, PW1_SIGN, b"123456");
        verify_pw(&mut applet, PW1_OTHER, b"123456");

        assert_eq!(
            applet.process(&pso_compute_signature(b"data")).status(),
            Status::ConditionsOfUseNotSatisfied
        );
        assert_eq!(
            applet.process(&pso_decipher(&[0x00, 0x01])).status(),
            Status::ConditionsOfUseNotSatisfied
        );
        assert_eq!(
            applet.process(&internal_authenticate(b"data")).status(),
            Status::ConditionsOfUseNotSatisfied
        );
        assert_eq!(
            applet.process(&[0x00, 0x2A, 0x00, 0x00]).status(),
            Status::IncorrectP1OrP2Parameter
        );
        assert_eq!(
            applet.process(&[0x00, 0x88, 0x01, 0x00]).status(),
            Status::IncorrectP1OrP2Parameter
        );
    }
}
