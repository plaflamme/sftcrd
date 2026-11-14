//! GENERAL AUTHENTICATE (0x87) — the SP 800-73-4 dynamic-auth half: the 9B
//! management-key witness / challenge exchange and the one-shot per-slot
//! ECDSA signing and ECDH key agreement of the NIST-curve slots.

use iso7816::Status;

use crate::piv::MgmtAlg;
use crate::tlv::{BerLength, ValueDecoder, tlv_struct};
use crate::{PivApplet, Response};

/// SP 800-73-4 §4.1.3 dynamic-authentication tags: the `7C` wrapper and its
/// witness / challenge / response / exponent members.
const GA_TAG_DYN_AUTH: u8 = 0x7C;
const GA_TAG_WITNESS: u8 = 0x80;
const GA_TAG_RESPONSE: u8 = 0x82;

/// Largest GA challenge value this applet will encrypt — the reference's
/// 64-byte scratch buffer caps the template it will accept at all.
const GA_MAX_CHALLENGE: usize = 64;

impl PivApplet {
    /// GENERAL AUTHENTICATE (0x87): the SP 800-73-4 dynamic-authentication
    /// exchange — the 9B management-key mutual auth this applet implements.
    ///
    /// The body is the dynamic-auth template `7C [80 witness] [81
    /// challenge] [82 response] [85 exponent]`, where an *empty* member
    /// names what the host wants (at most one) and a *non-empty* member
    /// carries data. Mirrors the card's `processGeneralAuth` /
    /// `processGenAuthSym` for P2=`9B`:
    ///
    /// - `6B00` when P1 is not the stored management algorithm, when P2 is
    ///   not a slot reference the applet knows, or — with an asymmetric P1
    ///   (`06`/`07`/`11`/`14`) — whenever: the slot holds no key.
    /// - The body is either an empty witness tag (`80`) — a witness
    ///   request — or a non-empty witness (`80`): the current challenge
    ///   encrypted with the management key (a re-issued witness invalidates
    ///   the pending one), optionally with the host's challenge under `81`.
    ///   Any other member or shape is refused `6B00`: the reference's
    ///   `81`/`82` shapes prove nothing to the applet.
    /// - A witness request issues a fresh challenge and answers
    ///   `7C 80 <n> <encrypted challenge>`. A correct witness sets the
    ///   slot's unlocked status and answers `9000` with no data, or
    ///   `7C 82 <n> <encrypted host challenge>` when one was offered;
    ///   a wrong witness — or one after the challenge was already
    ///   consumed — is `6A86`. Issue and check both re-lock the slot,
    ///   so a witness request after a successful handshake demands a
    ///   full mutual auth again.
    ///
    /// Every slot reference (9A/9C/9D/9E and the retired slots
    /// `82`–`95`) goes through the slot path: the slot's PIN policy is
    /// enforced (`6986` while it is not satisfied), the slot must hold a
    /// key and P1 must be the slot's algorithm byte (`6B00` otherwise),
    /// and the body is the one-shot dynamic-auth template — an empty `82`
    /// plus exactly one data member: a 32-byte digest under `81` (ECDSA
    /// signing — the applet signs the host's pre-hashed digest) or a
    /// 65-byte uncompressed peer point under `85` (ECDH — the applet
    /// answers the shared secret's x-coordinate). `9B` is the management
    /// key; every other P2 — `9F`, `58`–`5A`, the vendor-extension
    /// references, … — answers `6B00` outright.
    pub(crate) fn process_general_authenticate(
        &mut self,
        command: &crate::apdu::CommandView<'_>,
    ) -> Response {
        // P2 is the key reference: a slot reference goes to the slot path,
        // `9B` is the management key, everything else is refused.
        match crate::piv::Slot::from_u8(command.p2) {
            Some(slot) => self.ga_slot(slot, command.p1, command.data()),
            None => match command.p2 {
                0x9B => self.ga_management(command.p1, command.data()),
                _ => iso7816::Status::IncorrectP1OrP2Parameter.into(),
            },
        }
    }

    /// The slot half of GENERAL AUTHENTICATE (9A/9C/9D/9E and the retired
    /// slots): the slot's PIN policy is enforced, the slot must hold a
    /// key, P1 must be the slot's algorithm byte, and the body is the
    /// one-shot dynamic-auth template — an empty `82` plus exactly one
    /// data member. The applet answers the signature or shared secret
    /// under `82`.
    fn ga_slot(&self, slot: crate::piv::Slot, p1: u8, body: &[u8]) -> Response {
        if let Err(sw) = self.slot_pin_gate(slot) {
            return sw.into();
        }
        let Some(key) = self.slots[slot].key.as_ref() else {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        };
        if p1 != key.alg() as u8 {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        }
        let Ok(request) = GaRequest::decode(body) else {
            return iso7816::Status::IncorrectDataParameter.into();
        };
        let t = request.ga_template;

        // The one-shot slot shape: an empty `82` plus a single data
        // member. Anything else is a wrong member.
        let Some([]) = t.response else {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        };
        match (t.witness, t.challenge, t.exponent) {
            (None, Some(digest), None) => match key.sign_prehash(digest) {
                Ok(out) => ga_response(GA_TAG_RESPONSE, &out),
                Err(status) => status.into(),
            },
            (None, None, Some(peer)) => match key.ecdh(peer) {
                Ok(shared) => ga_response(GA_TAG_RESPONSE, &shared),
                Err(status) => status.into(),
            },
            _ => iso7816::Status::IncorrectP1OrP2Parameter.into(),
        }
    }

    /// The 9B (management-key) half of GENERAL AUTHENTICATE: P1 selects the
    /// symmetric or an asymmetric algorithm, the body carries the
    /// dynamic-auth template.
    fn ga_management(&mut self, p1: u8, body: &[u8]) -> Response {
        #[allow(clippy::manual_let_else)]
        let request = match GaRequest::decode(body) {
            Ok(t) => t,
            Err(_) => return iso7816::Status::IncorrectDataParameter.into(),
        };

        match MgmtAlg::from_u8(p1) {
            Some(alg) => self.ga_sym(alg, &request.ga_template),
            // Asymmetric (or unknown) algorithm: no key slot, so no
            // exchange — the reference fails on the missing key.
            None => iso7816::Status::IncorrectP1OrP2Parameter.into(),
        }
    }

    /// The symmetric 9B dynamic-auth exchange (the card's
    /// `processGenAuthSym`), once the template is parsed.
    fn ga_sym(&mut self, alg: MgmtAlg, t: &GaTemplate) -> Response {
        if self.mgmt.alg() != alg {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        }

        let bs = alg.block_size();
        // The witness flow is the only supported symmetric exchange: a
        // witness request (an empty `80`) or a witness value, optionally
        // with the host's challenge under `81`.
        if t.response.is_some() {
            return iso7816::Status::IncorrectP1OrP2Parameter.into();
        }
        match (t.witness, t.challenge) {
            // Request witness
            (Some([]), None) => {
                let enc = self.mgmt.issue();
                ga_response(GA_TAG_WITNESS, &enc)
            }
            // Verify witness and optionally request challenge response
            (Some(w), host_chal) => {
                if w.len() != bs {
                    return iso7816::Status::IncorrectDataParameter.into();
                }
                if host_chal.is_some_and(|hc| {
                    hc.is_empty() || hc.len() > GA_MAX_CHALLENGE || hc.len() % bs != 0
                }) {
                    return iso7816::Status::IncorrectDataParameter.into();
                }
                match self.mgmt.check(w, host_chal) {
                    Ok(resp) => match resp {
                        Some(enc) => ga_response(GA_TAG_RESPONSE, &enc),
                        None => Status::Success.into(),
                    },
                    Err(_) => iso7816::Status::IncorrectDataParameter.into(),
                }
            }
            _ => iso7816::Status::IncorrectP1OrP2Parameter.into(),
        }
    }
}

tlv_struct! {
    #[derive(Debug)]
    #[length(BerLength)]
    struct GaTemplate<'a> {
        #[tag=0x80]
        witness: Option<&'a [u8]>,
        #[tag=0x81]
        challenge: Option<&'a [u8]>,
        #[tag=0x82]
        response: Option<&'a [u8]>,
        #[tag=0x85]
        exponent: Option<&'a [u8]>,
    }
}

tlv_struct! {
    #[derive(Debug)]
    #[length(crate::tlv::BerLength)]
    struct GaRequest<'a> {
        #[tag=0x7C]
        ga_template: GaTemplate<'a>
    }
}

/// Build the card's GA answer: the `7C` wrapper around one tagged value.
#[allow(clippy::cast_possible_truncation)]
fn ga_response(tag: u8, value: &[u8]) -> Response {
    fn length(data: &mut Vec<u8>, len: usize) {
        if len <= 127 {
            data.push(len as u8);
        } else if len < 256 {
            data.push(0x81);
            data.push(len as u8);
        } else {
            data.push(0x82);
            data.push((len >> 8) as u8);
            data.push(len as u8);
        }
    }
    let mut inner = vec![tag];
    length(&mut inner, value.len());
    inner.extend_from_slice(value);
    let mut data = vec![GA_TAG_DYN_AUTH];
    length(&mut data, inner.len());
    data.extend_from_slice(&inner);
    data.into()
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
#[allow(clippy::items_after_statements)]
pub(crate) mod tests {
    use super::*;
    use aes::cipher::{BlockCipherDecrypt, KeyInit};
    use elliptic_curve::Generate;
    use elliptic_curve::sec1::ToSec1Point;
    use keyroost_piv::KEY_REF_MANAGEMENT;

    /// The GA dynamic-auth body: `7C` wrapping the given tagged members.
    pub(crate) fn ga_body(members: &[&[u8]]) -> Vec<u8> {
        let mut inner = Vec::new();
        for m in members {
            inner.extend_from_slice(m);
        }
        let mut body = vec![0x7C, inner.len() as u8];
        body.extend_from_slice(&inner);
        body
    }

    /// A GA APDU: `00 87 p1 9B Lc body`.
    pub(crate) fn ga_apdu(p1: u8, body: &[u8]) -> Vec<u8> {
        let mut apdu = vec![0x00, 0x87, p1, KEY_REF_MANAGEMENT, body.len() as u8];
        apdu.extend_from_slice(body);
        apdu
    }

    /// A full 9B management-key handshake against a fresh applet using the
    /// factory 3DES key: a witness round, then a response round proving the
    /// witness — afterwards the session is unlocked.
    /// The host's management-key handshake (keyroost-transport's
    /// `authenticate_management`), factory 3DES: the witness round, then
    /// the decrypted witness plus a fresh host challenge — the exact APDUs
    /// `general_auth_request_witness` and `general_auth_mutual` build.
    /// Returns the card's step-2 `7C` data and the host challenge the
    /// caller can check the card encrypted.
    pub(crate) fn mgmt_handshake(applet: &mut PivApplet) -> (Vec<u8>, [u8; 8]) {
        // Step 1 (general_auth_request_witness): 7C 02 80 00.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.status(), iso7816::Status::Success, "witness round: {r:?}");
        assert_eq!(r.data()[0], 0x7C);
        // The 7C wraps tag + length + 8-byte value: 2 + 8.
        assert_eq!(r.data()[1], 10);
        assert_eq!(r.data()[2], 0x80);
        assert_eq!(r.data()[3], 8);
        // The host decrypts the witness with the management key — the
        // clear challenge is the key proof.
        let witness = des_decrypt(&r.data()[4..12]);
        // Step 2 (general_auth_mutual): the clear witness plus a fresh
        // host challenge; the card answers 7C .. 82 .. <enc(challenge)>.
        let challenge: [u8; 8] = [0x42; 8];
        let mut members = vec![0x80, 0x08];
        members.extend_from_slice(&witness);
        members.extend_from_slice(&[0x81, 0x08]);
        members.extend_from_slice(&challenge);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&members])));
        assert_eq!(r.status(), iso7816::Status::Success, "mutual round: {r:?}");
        assert_eq!(r.data()[0], 0x7C);
        assert_eq!(r.data()[2], 0x82);
        assert_eq!(r.data()[3], 8);
        (Vec::from(r.data()), challenge)
    }

    /// Decrypt an 8-byte block with the stored 3DES management key.
    fn des_decrypt(data: &[u8]) -> [u8; 8] {
        let c = des::TdesEde3::new_from_slice(&[
            1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
        ])
        .unwrap();
        let mut block = cipher::Array::try_from(data).expect("can clone slice");
        c.decrypt_block(&mut block);
        block.into()
    }

    /// Burn every PUK retry with wrong PUKs, asserting each `63Cx` along
    /// the way; afterwards the PUK is blocked.
    pub(crate) fn block_puk(applet: &mut PivApplet) {
        for tries in (1..=3).rev() {
            let resp = applet.process(&keyroost_piv::unblock_pin(b"00000000", b"123456").unwrap());
            assert_eq!(resp.status(), iso7816::Status::RemainingRetries(tries - 1));
        }
    }

    #[test]
    fn ga_witness_round_answers_an_encrypted_challenge() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.status(), iso7816::Status::Success);
        assert_eq!(r1.data().len(), 12);
        let r2 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r2.status(), iso7816::Status::Success);
        // A fresh challenge every time — the witnesses differ.
        assert_ne!(&r1.data()[4..12], &r2.data()[4..12]);
    }

    #[test]
    fn ga_full_handshake_unlocks_and_responds() {
        let mut applet = PivApplet::new();
        let (data, challenge) = mgmt_handshake(&mut applet);
        // Mutual auth: the 0x82 response decrypts to the host challenge.
        assert_eq!(des_decrypt(&data[4..12]), challenge);
    }

    /// A management write, the way the set-management-key command sends
    /// it: the 9B key reference, the 24-byte 3DES length, a zero key.
    fn set_mgmt_key_apdu() -> Vec<u8> {
        let mut apdu = vec![0x00, 0xFF, 0xFF, 0xFF, 27];
        apdu.extend_from_slice(&[0x03, KEY_REF_MANAGEMENT, 0x18]);
        apdu.extend_from_slice(&[0u8; 24]);
        apdu
    }

    #[test]
    fn ga_witness_request_re_locks_the_slot() {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        // The session is unlocked: a management write goes through.
        let apdu = set_mgmt_key_apdu();
        let r = applet.process(&apdu);
        assert_eq!(
            r.status(),
            iso7816::Status::Success,
            "unlocked session: {r:?}"
        );
        // A witness request re-locks the slot (issue() clears the flag)...
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.status(), iso7816::Status::Success);
        // ...so the same write now fails until a full mutual auth again.
        let r = applet.process(&apdu);
        assert_eq!(
            r.status(),
            iso7816::Status::SecurityStatusNotSatisfied,
            "re-locked: {r:?}"
        );
    }

    #[test]
    fn ga_challenged_body_without_a_witness_is_incorrect_p1p2() {
        let mut applet = PivApplet::new();
        // Only a non-empty challenge, no witness: the shape is refused
        // outright — there is nothing to check it against, and a clear
        // challenge proves nothing.
        let r = applet.process(&ga_apdu(
            0x03,
            &ga_body(&[&[0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7]]),
        ));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
        // After a handshake the answer is the same — the shape, not the
        // state, is what is refused.
        mgmt_handshake(&mut applet);
        let r = applet.process(&ga_apdu(
            0x03,
            &ga_body(&[&[0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7]]),
        ));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
    }

    #[test]
    fn ga_wrong_witness_is_wrong_data_and_consumes_the_challenge() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.status(), iso7816::Status::Success);
        // A corrupted witness — the applet's challenge is consumed.
        let mut bad = vec![0x80, 0x08];
        bad.extend_from_slice(&r1.data()[4..12]);
        bad[2] ^= 1;
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&bad])));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
        // The real witness no longer verifies — the challenge is gone.
        let mut good = vec![0x80, 0x08];
        good.extend_from_slice(&r1.data()[4..12]);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&good])));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
    }

    #[test]
    fn ga_reissued_witness_invalidates_the_old_one() {
        let mut applet = PivApplet::new();
        let r1 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        let r2 = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r1.status(), iso7816::Status::Success);
        assert_eq!(r2.status(), iso7816::Status::Success);
        // Presenting the first witness fails — the second issued it away.
        let mut body = vec![0x80, 0x08];
        body.extend_from_slice(&r1.data()[4..12]);
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&body])));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
    }

    #[test]
    fn ga_response_member_is_incorrect_p1p2() {
        let mut applet = PivApplet::new();
        // A 0x82 member is refused outright — a replay of the card's own
        // ciphertext proves nothing, so its length is never even looked at.
        let body = ga_body(&[&[0x82, 4, 0, 1, 2, 3]]);
        let r = applet.process(&ga_apdu(0x03, &body));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
    }

    #[test]
    fn ga_wrong_algorithm_is_incorrect_p1p2() {
        let mut applet = PivApplet::new();
        // The applet is 3DES; P1 = AES-256 is not its algorithm.
        let r = applet.process(&ga_apdu(0x0C, &ga_body(&[&[0x80, 0x00]])));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
        // And an asymmetric P1 with a signing-shaped body too.
        let mut members = vec![0x81, 0x08, 0, 1, 2, 3, 4, 5, 6, 7];
        members.extend_from_slice(&[0x82, 0x00]);
        let r = applet.process(&ga_apdu(0x14, &ga_body(&[&members])));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
    }

    #[test]
    fn ga_slot_refs_are_policy_gated_and_non_slot_p2s_refused() {
        let mut applet = PivApplet::new();
        // Non-slot P2s: `6B00` outright.
        for p2 in [0x58u8, 0x00u8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
        }
        // 9E is a slot (factory NEVER) — ungated, refused for the missing
        // key.
        let r = applet.process(&ga_apdu_for_p2(0x9E));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
        // 9A/9C/9D and the retired slots: PIN-gated — locked first.
        for p2 in [0x9Au8, 0x9Cu8, 0x9Du8, 0x82u8, 0x8Cu8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(
                r.status(),
                iso7816::Status::SecurityStatusNotSatisfied,
                "0x{p2:02X}"
            );
        }
        // After the PIN is verified the applet has no key material for
        // them. The ONCE slots pass on the session flag; the ALWAYS latch
        // is consumed by the first slot APDU, so the 9C GA that does not
        // follow the VERIFY is gated again.
        let r = applet.process(&keyroost_piv::verify_pin(b"123456").unwrap());
        assert_eq!(r.status(), iso7816::Status::Success);
        let r = applet.process(&ga_apdu_for_p2(0x9A));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
        let r = applet.process(&ga_apdu_for_p2(0x9C));
        assert_eq!(r.status(), iso7816::Status::SecurityStatusNotSatisfied);
        for p2 in [0x9Du8, 0x82u8, 0x8Cu8] {
            let r = applet.process(&ga_apdu_for_p2(p2));
            assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
        }
    }

    /// A GA APDU for a slot reference other than 9B: `00 87 00 p2 00`.
    fn ga_apdu_for_p2(p2: u8) -> Vec<u8> {
        vec![0x00, 0x87, 0x00, p2, 0x00]
    }

    #[test]
    fn ga_broken_templates_are_wrong_length_or_wrong_data() {
        let mut applet = PivApplet::new();
        // Lc overrunning the APDU.
        let r = applet.process(&[0x00, 0x87, 0x03, KEY_REF_MANAGEMENT, 0x08, 0x7C, 0x00]);
        assert_eq!(r.status(), iso7816::Status::WrongLength);
        // No 7C wrapper at all.
        let r = applet.process(&ga_apdu(0x03, &[0x80, 0x00]));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
        // Two empty tags.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x80, 0x00], &[0x81, 0x00]])));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
        // An unknown empty tag.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x85, 0x00]])));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
        // A member that overruns the body.
        let r = applet.process(&ga_apdu(0x03, &ga_body(&[&[0x81, 0x08, 0, 1, 2]])));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
        // The 7C wrapper's length underdeclared: the scan still runs to the
        // end of the body — here to a second empty tag, a protocol error.
        let body = vec![0x7C, 0x02, 0x80, 0x00, 0x81, 0x00];
        let r = applet.process(&ga_apdu(0x03, &body));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
    }

    #[test]
    fn ga_rejects_cla_bits() {
        let mut applet = PivApplet::new();
        let mut apdu = ga_apdu(0x03, &ga_body(&[&[0x80, 0x00]]));
        apdu[0] = 0x80;
        let r = applet.process(&apdu);
        assert_eq!(r.status(), iso7816::Status::ClaNotSupported);
    }

    /// Management unlock plus a key of `alg` in `slot`; returns the
    /// uncompressed public point the card announced.
    fn slot_with_key(
        applet: &mut PivApplet,
        slot: keyroost_piv::Slot,
        alg: keyroost_piv::KeyAlg,
    ) -> Vec<u8> {
        mgmt_handshake(applet);
        let r = applet.process(&keyroost_piv::generate_key(
            slot,
            alg.id(),
            keyroost_piv::PinPolicy::Default,
            keyroost_piv::TouchPolicy::Default,
        ));
        assert_eq!(r.status(), iso7816::Status::Success, "GENERATE: {r:?}");
        match keyroost_piv::parse_public_key(r.data()).expect("a well-formed public-key template") {
            keyroost_piv::PublicKey::Ecc { point } => point,
            keyroost_piv::PublicKey::Rsa { .. } => panic!("expected an EC point"),
        }
    }

    /// Management unlock plus a P-256 key in `slot`.
    fn slot_with_p256(applet: &mut PivApplet, slot: keyroost_piv::Slot) -> Vec<u8> {
        slot_with_key(applet, slot, keyroost_piv::KeyAlg::EccP256)
    }

    /// Run the host's signing GA against the slot and verify the card's
    /// DER signature under the point the card announced.
    pub(crate) fn card_signature(
        applet: &mut PivApplet,
        key_ref: u8,
        point: &[u8],
        digest: &[u8; 32],
    ) {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP256.id(),
            key_ref,
            digest,
        ));
        assert_eq!(r.status(), iso7816::Status::Success, "signing GA: {r:?}");
        let sig_der = keyroost_piv::parse_general_auth(r.data(), 0x82).expect("an 82 answer");
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).expect("the announced point");
        let sig = p256::ecdsa::Signature::from_der(sig_der).expect("a DER signature");
        vk.verify_prehash(digest, &sig).expect("a valid signature");
    }

    #[test]
    fn ga_slot_signs_the_hosts_prehashed_digest() {
        let mut applet = PivApplet::new();
        let point = slot_with_p256(&mut applet, keyroost_piv::Slot::Authentication); // 9A: ONCE
        assert_eq!(
            applet
                .process(&keyroost_piv::verify_pin(b"123456").unwrap())
                .status(),
            iso7816::Status::Success
        );
        card_signature(&mut applet, 0x9A, &point, &[0x2B; 32]);
    }

    #[test]
    fn ga_slot_ecdh_answers_the_shared_x_coordinate() {
        let mut applet = PivApplet::new();
        let point = slot_with_p256(&mut applet, keyroost_piv::Slot::CardAuthentication); // 9E: NEVER
        let peer = p256::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
        let r = applet.process(&keyroost_piv::general_auth_key_agree(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9E,
            peer.public_key().to_sec1_point(false).as_bytes(),
        ));
        assert_eq!(
            r.status(),
            iso7816::Status::Success,
            "key agree(ment GA: {r:?}"
        );
        let z = keyroost_piv::parse_general_auth(r.data(), 0x82).expect("an 82 answer");
        assert_eq!(z.len(), 32);
        let card_pub = p256::PublicKey::from_sec1_bytes(&point).expect("the announced point");
        let expected = peer.diffie_hellman(&card_pub);
        assert_eq!(z, expected.raw_secret_bytes().as_slice());
    }

    #[test]
    fn ga_slot_signs_a_p384_digest() {
        let mut applet = PivApplet::new();
        let point = slot_with_key(
            &mut applet,
            keyroost_piv::Slot::Authentication, // 9A: ONCE
            keyroost_piv::KeyAlg::EccP384,
        );
        assert_eq!(point.len(), 97);
        assert_eq!(
            applet
                .process(&keyroost_piv::verify_pin(b"123456").unwrap())
                .status(),
            iso7816::Status::Success
        );
        let digest = [0x2C; 48];
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP384.id(),
            0x9A,
            &digest,
        ));
        assert_eq!(r.status(), iso7816::Status::Success, "signing GA: {r:?}");
        let sig_der = keyroost_piv::parse_general_auth(r.data(), 0x82).expect("an 82 answer");
        use p384::ecdsa::signature::hazmat::PrehashVerifier;
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("the announced point");
        let sig = p384::ecdsa::Signature::from_der(sig_der).expect("a DER signature");
        vk.verify_prehash(&digest, &sig).expect("a valid signature");
    }

    #[test]
    fn ga_slot_signs_a_p521_digest() {
        let mut applet = PivApplet::new();
        let point = slot_with_key(
            &mut applet,
            keyroost_piv::Slot::Authentication, // 9A: ONCE
            keyroost_piv::KeyAlg::EccP521,
        );
        assert_eq!(point.len(), 133);
        assert_eq!(
            applet
                .process(&keyroost_piv::verify_pin(b"123456").unwrap())
                .status(),
            iso7816::Status::Success
        );
        // The host hashes the TBS with SHA-512: a 64-byte digest, two bytes
        // short of the 66-byte field -- the applet accepts it as-is.
        let digest = [0x2D; 64];
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP521.id(),
            0x9A,
            &digest,
        ));
        assert_eq!(r.status(), iso7816::Status::Success, "signing GA: {r:?}");
        let sig_der = keyroost_piv::parse_general_auth(r.data(), 0x82).expect("an 82 answer");
        use p521::ecdsa::signature::hazmat::PrehashVerifier;
        let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(&point).expect("the announced point");
        let sig = p521::ecdsa::Signature::from_der(sig_der).expect("a DER signature");
        vk.verify_prehash(&digest, &sig).expect("a valid signature");
    }

    #[test]
    fn ga_slot_ecdh_answers_the_p384_shared_x_coordinate() {
        let mut applet = PivApplet::new();
        let point = slot_with_key(
            &mut applet,
            keyroost_piv::Slot::CardAuthentication, // 9E: NEVER
            keyroost_piv::KeyAlg::EccP384,
        );
        let peer = p384::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
        let r = applet.process(&keyroost_piv::general_auth_key_agree(
            keyroost_piv::KeyAlg::EccP384.id(),
            0x9E,
            peer.public_key().to_sec1_point(false).as_bytes(),
        ));
        assert_eq!(
            r.status(),
            iso7816::Status::Success,
            "key agreement GA: {r:?}"
        );
        let z = keyroost_piv::parse_general_auth(r.data(), 0x82).expect("an 82 answer");
        assert_eq!(z.len(), 48);
        let card_pub = p384::PublicKey::from_sec1_bytes(&point).expect("the announced point");
        let expected = peer.diffie_hellman(&card_pub);
        assert_eq!(z, expected.raw_secret_bytes().as_slice());
    }

    #[test]
    fn ga_slot_ecdh_answers_the_p521_shared_x_coordinate() {
        let mut applet = PivApplet::new();
        let point = slot_with_key(
            &mut applet,
            keyroost_piv::Slot::CardAuthentication, // 9E: NEVER
            keyroost_piv::KeyAlg::EccP521,
        );
        // A P-521 uncompressed point is `04 || X || Y` = 1 + 66 + 66 = 133
        // bytes, not the 1 + 64 + 64 a SHA-512-sized coordinate would give.
        assert_eq!(point.len(), 133);
        let peer = p521::ecdh::EphemeralSecret::generate_from_rng(&mut rand::rng());
        let r = applet.process(&keyroost_piv::general_auth_key_agree(
            keyroost_piv::KeyAlg::EccP521.id(),
            0x9E,
            peer.public_key().to_sec1_point(false).as_bytes(),
        ));
        assert_eq!(
            r.status(),
            iso7816::Status::Success,
            "key agreement GA: {r:?}"
        );
        let z = keyroost_piv::parse_general_auth(r.data(), 0x82).expect("an 82 answer");
        assert_eq!(z.len(), 66);
        let card_pub = p521::PublicKey::from_sec1_bytes(&point).expect("the announced point");
        let expected = peer.diffie_hellman(&card_pub);
        assert_eq!(z, expected.raw_secret_bytes().as_slice());
    }

    #[test]
    fn ga_slot_refuses_a_p1_that_is_not_the_slots_algorithm() {
        let mut applet = PivApplet::new();
        let _point = slot_with_p256(&mut applet, keyroost_piv::Slot::Authentication);
        assert_eq!(
            applet
                .process(&keyroost_piv::verify_pin(b"123456").unwrap())
                .status(),
            iso7816::Status::Success
        );
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP384.id(),
            0x9A,
            &[0x2B; 32],
        ));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
    }

    #[test]
    fn ga_slot_rsa_signs_the_hosts_preencoded_block() {
        rsa_sign_roundtrip(keyroost_piv::KeyAlg::Rsa1024);
    }

    /// The RSA-2048 slot: its modulus-size block is 256 bytes, so the GA
    /// dynamic-auth template crosses the 255-byte boundary and both its
    /// `7C` wrapper and the `81` data member carry a two-byte `82` length —
    /// the long form the slot path has to parse. (RSA-1024's 128-byte block
    /// stays in the short form, so only this size exercises it.)
    #[test]
    fn ga_slot_rsa2048_signs_a_modulus_size_block() {
        rsa_sign_roundtrip(keyroost_piv::KeyAlg::Rsa2048);
    }

    /// Generate an RSA key of `alg` in the `NEVER`-policy 9E slot (no VERIFY
    /// needed), sign the host's pre-encoded modulus-size block through a
    /// single extended-length GENERAL AUTHENTICATE, and check the raw
    /// `s^e == m (mod n)` round trip plus the length guards.
    fn rsa_sign_roundtrip(alg: keyroost_piv::KeyAlg) {
        let mut applet = PivApplet::new();
        mgmt_handshake(&mut applet);
        // 9E is `NEVER` at the factory: the sign round trip needs no VERIFY.
        let r = applet.process(&keyroost_piv::generate_key(
            keyroost_piv::Slot::CardAuthentication,
            alg.id(),
            keyroost_piv::PinPolicy::Default,
            keyroost_piv::TouchPolicy::Default,
        ));
        assert_eq!(r.status(), iso7816::Status::Success, "GENERATE: {r:?}");
        let (n, e) = match keyroost_piv::parse_public_key(r.data()).expect("a template") {
            keyroost_piv::PublicKey::Rsa { modulus, exponent } => (modulus, exponent),
            keyroost_piv::PublicKey::Ecc { .. } => panic!("expected an RSA modulus"),
        };
        // The host's pre-encoded DigestInfo block — exactly the modulus size.
        let mut block = vec![0u8; n.len()];
        block[n.len() - 1] = 0x2B;
        let r = applet.process(&keyroost_piv::general_auth_sign(alg.id(), 0x9E, &block));
        assert_eq!(r.status(), iso7816::Status::Success, "signing GA: {r:?}");
        let s = keyroost_piv::parse_general_auth(r.data(), 0x82).expect("an 82 answer");
        assert_eq!(
            s.len(),
            n.len(),
            "the answer is zero-extended to the modulus size"
        );
        use rsa::BoxedUint;
        assert_eq!(
            BoxedUint::from_be_slice_vartime(s).pow_mod(
                &BoxedUint::from_be_slice_vartime(&e),
                BoxedUint::from_be_slice_vartime(&n)
                    .as_odd_vartime()
                    .expect("is odd")
            ),
            BoxedUint::from(0x2Bu8),
            "s^e == m (mod n)"
        );
        // A short block is the wrong length, whatever it says.
        let r = applet.process(&keyroost_piv::general_auth_sign(
            alg.id(),
            0x9E,
            &block[..block.len() - 1],
        ));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
        // A block >= n is not a valid residue.
        let r = applet.process(&keyroost_piv::general_auth_sign(alg.id(), 0x9E, &n));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
    }

    #[test]
    fn ga_to_the_attest_slot_is_not_dispatched() {
        let mut applet = PivApplet::new();
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP256.id(),
            0xF9,
            &[0x2B; 32],
        ));
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
    }

    #[test]
    fn ga_slot_sign_wants_exactly_a_32_byte_digest() {
        let mut applet = PivApplet::new();
        let _point = slot_with_p256(&mut applet, keyroost_piv::Slot::Authentication);
        assert_eq!(
            applet
                .process(&keyroost_piv::verify_pin(b"123456").unwrap())
                .status(),
            iso7816::Status::Success
        );
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9A,
            &[0x2B; 20],
        ));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
    }

    #[test]
    fn ga_slot_ecdh_wants_a_65_byte_point_on_the_curve() {
        let mut applet = PivApplet::new();
        let _point = slot_with_p256(&mut applet, keyroost_piv::Slot::CardAuthentication);
        // 64 bytes: not a point encoding.
        let r = applet.process(&keyroost_piv::general_auth_key_agree(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9E,
            &[0x04; 64],
        ));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
        // 65 bytes but off the curve.
        let mut off_curve = [0x11; 65];
        off_curve[0] = 0x04;
        let r = applet.process(&keyroost_piv::general_auth_key_agree(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9E,
            &off_curve,
        ));
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
    }

    #[test]
    fn ga_slot_refuses_wrong_member_shapes() {
        let mut applet = PivApplet::new();
        let _point = slot_with_p256(&mut applet, keyroost_piv::Slot::Authentication);
        assert_eq!(
            applet
                .process(&keyroost_piv::verify_pin(b"123456").unwrap())
                .status(),
            iso7816::Status::Success
        );
        let digest = [0x2B; 32];
        // A non-empty 82 member: not the one-shot slot shape.
        let mut body = vec![
            0x7C,
            3 + 4 + 34,
            0x82,
            0x04,
            0xDE,
            0xAD,
            0xBE,
            0xEF,
            0x81,
            0x20,
        ];
        body.extend_from_slice(&digest);
        let mut apdu = vec![0x00, 0x87, 0x11, 0x9A, body.len() as u8];
        apdu.extend_from_slice(&body);
        apdu.push(0x00);
        let r = applet.process(&apdu);
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
        // Both an 81 and an 85 member: not the one-shot slot shape.
        let mut body = vec![0x7C, 3 + 34 + 2 + 65, 0x81, 0x20];
        body.extend_from_slice(&digest);
        body.extend_from_slice(&[0x85, 0x41, 0x04]);
        body.extend_from_slice(&[0x02; 64]);
        let mut apdu = vec![0x00, 0x87, 0x11, 0x9A, body.len() as u8];
        apdu.extend_from_slice(&body);
        apdu.push(0x00);
        let r = applet.process(&apdu);
        assert_eq!(r.status(), iso7816::Status::IncorrectDataParameter);
        // A lone empty 82 (no data member at all): not the one-shot slot
        // shape.
        let r = applet.process(&[0x00, 0x87, 0x11, 0x9A, 0x04, 0x7C, 0x02, 0x82, 0x00, 0x00]);
        assert_eq!(r.status(), iso7816::Status::IncorrectP1OrP2Parameter);
    }
}
