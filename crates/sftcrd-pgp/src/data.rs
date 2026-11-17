//! `OpenPGP` Card v3.4 Data Objects, `GET DATA` (`0xCA`), and `PUT DATA` (`0xDA`).

use iso7816::Status;
use sftcrd_apdu::CommandView;
use sftcrd_tlv::{BerLength, BerTag, ValueEncoder as _, encode_sequence, tlv_struct};

use crate::{
    PgpApplet, Response,
    constants::{
        AlgoId, DEFAULT_ALGO_ATTR, DEFAULT_UIF, EXTENDED_CAPABILITIES, Gender, HISTORICAL_BYTES,
        OID_ED25519, OID_NIST_P256, OID_NIST_P384, OID_NIST_P521, OID_X25519, UifMode,
    },
    pin::{PinState, PwRef},
};

const MAX_NAME_LEN: usize = 39;
const MAX_LANGUAGE_LEN: usize = 8;
const MAX_URL_LEN: usize = 2048;
const MAX_LOGIN_DATA_LEN: usize = 2048;

/// Which of the three `OpenPGP` key slots a tag refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeySlotId {
    Sig,
    Dec,
    Aut,
}

/// Per-slot metadata stored on the card (algorithm attributes, fingerprints,
/// generation timestamp, and User Interaction Flag).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeySlotMeta {
    pub(crate) algo_attr: Vec<u8>,
    pub(crate) fingerprint: [u8; 20],
    pub(crate) ca_fingerprint: [u8; 20],
    pub(crate) generation_time: u32,
    pub(crate) uif: [u8; 2],
}

impl Default for KeySlotMeta {
    fn default() -> Self {
        Self {
            algo_attr: DEFAULT_ALGO_ATTR.to_vec(),
            fingerprint: [0u8; 20],
            ca_fingerprint: [0u8; 20],
            generation_time: 0,
            uif: DEFAULT_UIF,
        }
    }
}

impl KeySlotMeta {
    fn wipe_key_metadata(&mut self) {
        self.fingerprint = [0u8; 20];
        self.generation_time = 0;
    }
}

/// Persistent `OpenPGP` Card data objects (cardholder metadata, slot metadata,
/// and digital signature counter).
#[derive(Debug, Clone, Default)]
pub(crate) struct CardData {
    pub(crate) name: Vec<u8>,
    pub(crate) language: Vec<u8>,
    pub(crate) gender: Gender,
    pub(crate) url: Vec<u8>,
    pub(crate) login_data: Vec<u8>,
    pub(crate) ds_counter: u32,
    pub(crate) sig: KeySlotMeta,
    pub(crate) dec: KeySlotMeta,
    pub(crate) aut: KeySlotMeta,
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct CardholderRelatedData<'a> {
        #[tag(0x5B)]
        name: &'a [u8],
        #[tag(0x5F2D)]
        language: &'a [u8],
        #[tag(0x5F35)]
        gender: u8,
    }
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct SecuritySupportTemplate {
        #[tag(0x93)]
        ds_counter: [u8; 3],
    }
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct DiscretionaryData<'a> {
        #[tag(0xC0)]
        extended_capabilities: [u8; 10],
        #[tag(0xC1)]
        algo_attr_sig: &'a [u8],
        #[tag(0xC2)]
        algo_attr_dec: &'a [u8],
        #[tag(0xC3)]
        algo_attr_aut: &'a [u8],
        #[tag(0xC4)]
        pw_status: [u8; 7],
        #[tag(0xC5)]
        fingerprints: [[u8; 20]; 3],
        #[tag(0xC6)]
        ca_fingerprints: [[u8; 20]; 3],
        #[tag(0xCD)]
        generation_times: [u32; 3],
        #[tag(0xD6)]
        uif_sig: [u8; 2],
        #[tag(0xD7)]
        uif_dec: [u8; 2],
        #[tag(0xD8)]
        uif_aut: [u8; 2],
    }
}

tlv_struct! {
    #[tag_type(BerTag)]
    #[length(BerLength)]
    struct ApplicationRelatedData<'a> {
        #[tag(0x4F)]
        aid: &'a [u8],
        #[tag(0x5F52)]
        historical_bytes: &'a [u8],
        #[tag(0x73)]
        discretionary: DiscretionaryData<'a>,
    }
}

impl CardData {
    fn slot(&self, id: KeySlotId) -> &KeySlotMeta {
        match id {
            KeySlotId::Sig => &self.sig,
            KeySlotId::Dec => &self.dec,
            KeySlotId::Aut => &self.aut,
        }
    }

    fn slot_mut(&mut self, id: KeySlotId) -> &mut KeySlotMeta {
        match id {
            KeySlotId::Sig => &mut self.sig,
            KeySlotId::Dec => &mut self.dec,
            KeySlotId::Aut => &mut self.aut,
        }
    }

    /// Build Cardholder Related Data (`0065` value: `5B`, `5F2D`, `5F35`).
    fn cardholder_related_data(&self) -> CardholderRelatedData<'_> {
        CardholderRelatedData {
            name: &self.name,
            language: &self.language,
            gender: self.gender as u8,
        }
    }

    /// Build Application Related Data (`006E` value: `4F`, `5F52`, `73`).
    fn application_related_data<'a>(
        &'a self,
        aid: &'a [u8; 16],
        pins: &PinState,
    ) -> ApplicationRelatedData<'a> {
        ApplicationRelatedData {
            aid,
            historical_bytes: &HISTORICAL_BYTES,
            discretionary: DiscretionaryData {
                extended_capabilities: EXTENDED_CAPABILITIES,
                algo_attr_sig: &self.sig.algo_attr,
                algo_attr_dec: &self.dec.algo_attr,
                algo_attr_aut: &self.aut.algo_attr,
                pw_status: pins.pw_status_bytes(),
                fingerprints: [
                    self.sig.fingerprint,
                    self.dec.fingerprint,
                    self.aut.fingerprint,
                ],
                ca_fingerprints: [
                    self.sig.ca_fingerprint,
                    self.dec.ca_fingerprint,
                    self.aut.ca_fingerprint,
                ],
                generation_times: [
                    self.sig.generation_time,
                    self.dec.generation_time,
                    self.aut.generation_time,
                ],
                uif_sig: self.sig.uif,
                uif_dec: self.dec.uif,
                uif_aut: self.aut.uif,
            },
        }
    }

    /// Build Security Support Template (`007A` value: `93`).
    fn security_support(&self) -> SecuritySupportTemplate {
        let [_, b1, b2, b3] = self.ds_counter.to_be_bytes();
        SecuritySupportTemplate {
            ds_counter: [b1, b2, b3],
        }
    }

    /// Encode Algorithm Information (`00FA` value): supported algorithms per slot.
    pub(crate) fn encode_algorithm_information() -> Vec<u8> {
        let mut entries: Vec<(BerTag, Vec<u8>)> = Vec::new();
        for (tag, slot) in [
            (BerTag(0xC1), KeySlotId::Sig),
            (BerTag(0xC2), KeySlotId::Dec),
            (BerTag(0xC3), KeySlotId::Aut),
        ] {
            for bits in [2048u16, 3072, 4096] {
                let [hi, lo] = bits.to_be_bytes();
                entries.push((tag, vec![AlgoId::Rsa as u8, hi, lo, 0x00, 0x20, 0x00]));
            }
            match slot {
                KeySlotId::Sig | KeySlotId::Aut => {
                    for oid in [OID_NIST_P256, OID_NIST_P384, OID_NIST_P521] {
                        entries.push((tag, ecc_attr(AlgoId::Ecdsa, oid)));
                    }
                    entries.push((tag, ecc_attr(AlgoId::EdDsa, OID_ED25519)));
                }
                KeySlotId::Dec => {
                    for oid in [OID_NIST_P256, OID_NIST_P384, OID_NIST_P521, OID_X25519] {
                        entries.push((tag, ecc_attr(AlgoId::Ecdh, oid)));
                    }
                }
            }
        }

        encode_sequence::<BerTag, BerLength, _>(&entries)
            .expect("in-memory TLV encoding cannot overflow")
    }
}

fn ecc_attr(algo_id: AlgoId, oid: &[u8]) -> Vec<u8> {
    let mut attr = Vec::with_capacity(1 + oid.len());
    attr.push(algo_id as u8);
    attr.extend_from_slice(oid);
    attr
}

fn validate_algo_attr(slot: KeySlotId, attr: &[u8]) -> Result<(), Status> {
    let Some(&raw_algo_id) = attr.first() else {
        return Err(Status::WrongLength);
    };
    let algo_id = AlgoId::from_u8(raw_algo_id).ok_or(Status::IncorrectDataParameter)?;
    if algo_id == AlgoId::Rsa {
        if !(5..=6).contains(&attr.len()) {
            return Err(Status::IncorrectDataParameter);
        }
        let n_bits = u16::from_be_bytes([attr[1], attr[2]]);
        let e_bits = u16::from_be_bytes([attr[3], attr[4]]);
        if !matches!(n_bits, 2048 | 3072 | 4096) || e_bits == 0 {
            return Err(Status::IncorrectDataParameter);
        }
        if let Some(&fmt) = attr.get(5)
            && fmt > 0x03
        {
            return Err(Status::IncorrectDataParameter);
        }
        return Ok(());
    }

    let raw_oid = &attr[1..];
    let oid = if is_supported_ecc(slot, algo_id, raw_oid) {
        raw_oid
    } else if let Some((&last, rest)) = raw_oid.split_last()
        && matches!(last, 0x00 | 0xFF)
        && is_supported_ecc(slot, algo_id, rest)
    {
        rest
    } else {
        return Err(Status::IncorrectDataParameter);
    };
    let _ = oid;
    Ok(())
}

fn is_supported_ecc(slot: KeySlotId, algo_id: AlgoId, oid: &[u8]) -> bool {
    match slot {
        KeySlotId::Sig | KeySlotId::Aut => {
            (algo_id == AlgoId::Ecdsa
                && matches!(oid, OID_NIST_P256 | OID_NIST_P384 | OID_NIST_P521))
                || (algo_id == AlgoId::EdDsa && oid == OID_ED25519)
        }
        KeySlotId::Dec => {
            algo_id == AlgoId::Ecdh
                && matches!(
                    oid,
                    OID_NIST_P256 | OID_NIST_P384 | OID_NIST_P521 | OID_X25519
                )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GetDataSelector {
    Aid,
    LoginData,
    Url,
    HistoricalBytes,
    CardholderRelatedData,
    ApplicationRelatedData,
    SecuritySupport,
    PwStatus,
    AlgorithmInformation,
    Uif(KeySlotId),
}

impl GetDataSelector {
    const fn from_p1_p2(p1: u8, p2: u8) -> Option<Self> {
        match u16::from_be_bytes([p1, p2]) {
            0x004F => Some(Self::Aid),
            0x005E => Some(Self::LoginData),
            0x5F50 => Some(Self::Url),
            0x5F52 => Some(Self::HistoricalBytes),
            0x0065 => Some(Self::CardholderRelatedData),
            0x006E => Some(Self::ApplicationRelatedData),
            0x007A => Some(Self::SecuritySupport),
            0x00C4 => Some(Self::PwStatus),
            0x00FA => Some(Self::AlgorithmInformation),
            0x00D6 => Some(Self::Uif(KeySlotId::Sig)),
            0x00D7 => Some(Self::Uif(KeySlotId::Dec)),
            0x00D8 => Some(Self::Uif(KeySlotId::Aut)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PutDataSelector {
    Name,
    Language,
    Gender,
    Url,
    LoginData,
    AlgoAttr(KeySlotId),
    PwStatus,
    Fingerprint(KeySlotId),
    GenerationTime(KeySlotId),
    ResettingCode,
    Uif(KeySlotId),
}

impl PutDataSelector {
    const fn from_p1_p2(p1: u8, p2: u8) -> Option<Self> {
        match u16::from_be_bytes([p1, p2]) {
            0x005B => Some(Self::Name),
            0x5F2D => Some(Self::Language),
            0x5F35 => Some(Self::Gender),
            0x5F50 => Some(Self::Url),
            0x005E => Some(Self::LoginData),
            0x00C1 => Some(Self::AlgoAttr(KeySlotId::Sig)),
            0x00C2 => Some(Self::AlgoAttr(KeySlotId::Dec)),
            0x00C3 => Some(Self::AlgoAttr(KeySlotId::Aut)),
            0x00C4 => Some(Self::PwStatus),
            0x00C7 => Some(Self::Fingerprint(KeySlotId::Sig)),
            0x00C8 => Some(Self::Fingerprint(KeySlotId::Dec)),
            0x00C9 => Some(Self::Fingerprint(KeySlotId::Aut)),
            0x00CE => Some(Self::GenerationTime(KeySlotId::Sig)),
            0x00CF => Some(Self::GenerationTime(KeySlotId::Dec)),
            0x00D0 => Some(Self::GenerationTime(KeySlotId::Aut)),
            0x00D3 => Some(Self::ResettingCode),
            0x00D6 => Some(Self::Uif(KeySlotId::Sig)),
            0x00D7 => Some(Self::Uif(KeySlotId::Dec)),
            0x00D8 => Some(Self::Uif(KeySlotId::Aut)),
            _ => None,
        }
    }
}

impl PgpApplet {
    /// `GET DATA` (`0xCA`): read a Data Object identified by `P1 || P2`.
    pub(crate) fn process_get_data(&self, cmd: &CommandView<'_>) -> Response {
        if !cmd.data().is_empty() {
            return Status::WrongLength.into();
        }
        let Some(selector) = GetDataSelector::from_p1_p2(cmd.p1, cmd.p2) else {
            return Status::KeyReferenceNotFound.into();
        };
        match selector {
            GetDataSelector::Aid => self.aid.as_slice().into(),
            GetDataSelector::LoginData => self.data.login_data.as_slice().into(),
            GetDataSelector::Url => self.data.url.as_slice().into(),
            GetDataSelector::HistoricalBytes => HISTORICAL_BYTES.as_slice().into(),
            GetDataSelector::CardholderRelatedData => self
                .data
                .cardholder_related_data()
                .encode_top_level()
                .map_or_else(|_| Status::MemoryFailure.into(), Response::from),
            GetDataSelector::ApplicationRelatedData => self
                .data
                .application_related_data(&self.aid, &self.pins)
                .encode_top_level()
                .map_or_else(|_| Status::MemoryFailure.into(), Response::from),
            GetDataSelector::SecuritySupport => self
                .data
                .security_support()
                .encode_top_level()
                .map_or_else(|_| Status::MemoryFailure.into(), Response::from),
            GetDataSelector::PwStatus => self.pins.pw_status_bytes().into(),
            GetDataSelector::AlgorithmInformation => {
                CardData::encode_algorithm_information().into()
            }
            GetDataSelector::Uif(slot) => self.data.slot(slot).uif.into(),
        }
    }

    /// `PUT DATA` (`0xDA`): write a PW3-gated Data Object identified by `P1 || P2`.
    pub(crate) fn process_put_data(&mut self, cmd: &CommandView<'_>) -> Response {
        let Some(selector) = PutDataSelector::from_p1_p2(cmd.p1, cmd.p2) else {
            return Status::KeyReferenceNotFound.into();
        };
        if !self.pins.is_verified(PwRef::Pw3Admin) {
            return Status::SecurityStatusNotSatisfied.into();
        }

        let data = cmd.data();
        match selector {
            PutDataSelector::Name => {
                if data.len() > MAX_NAME_LEN {
                    return Status::WrongLength.into();
                }
                self.data.name = data.to_vec();
            }
            PutDataSelector::Language => {
                if data.len() > MAX_LANGUAGE_LEN {
                    return Status::WrongLength.into();
                }
                self.data.language = data.to_vec();
            }
            PutDataSelector::Gender => {
                if data.len() != 1 {
                    return Status::WrongLength.into();
                }
                let Some(gender) = Gender::from_u8(data[0]) else {
                    return Status::IncorrectDataParameter.into();
                };
                self.data.gender = gender;
            }
            PutDataSelector::Url => {
                if data.len() > MAX_URL_LEN {
                    return Status::WrongLength.into();
                }
                self.data.url = data.to_vec();
            }
            PutDataSelector::LoginData => {
                if data.len() > MAX_LOGIN_DATA_LEN {
                    return Status::WrongLength.into();
                }
                self.data.login_data = data.to_vec();
            }
            PutDataSelector::AlgoAttr(slot) => return self.put_algo_attr(slot, data),
            PutDataSelector::PwStatus => {
                if data.len() != 1 {
                    return Status::WrongLength.into();
                }
                match data[0] {
                    0x00 => self.pins.set_pw1_valid_multiple(false),
                    0x01 => self.pins.set_pw1_valid_multiple(true),
                    _ => return Status::IncorrectDataParameter.into(),
                }
            }
            PutDataSelector::Fingerprint(slot) => return self.put_fingerprint(slot, data),
            PutDataSelector::GenerationTime(slot) => return self.put_timestamp(slot, data),
            PutDataSelector::ResettingCode => {
                if data.is_empty() {
                    self.pins.clear_rc();
                } else if let Err(status) = self.pins.set_rc(data) {
                    return status.into();
                }
            }
            PutDataSelector::Uif(slot) => return self.put_uif(slot, data),
        }
        Status::Success.into()
    }

    fn put_algo_attr(&mut self, slot: KeySlotId, data: &[u8]) -> Response {
        if let Err(status) = validate_algo_attr(slot, data) {
            return status.into();
        }
        let meta = self.data.slot_mut(slot);
        if meta.algo_attr != data {
            meta.wipe_key_metadata();
            meta.algo_attr = data.to_vec();
        }
        Status::Success.into()
    }

    fn put_fingerprint(&mut self, slot: KeySlotId, data: &[u8]) -> Response {
        let Ok(fpr): Result<[u8; 20], _> = data.try_into() else {
            return Status::WrongLength.into();
        };
        self.data.slot_mut(slot).fingerprint = fpr;
        Status::Success.into()
    }

    fn put_timestamp(&mut self, slot: KeySlotId, data: &[u8]) -> Response {
        let Ok(bytes): Result<[u8; 4], _> = data.try_into() else {
            return Status::WrongLength.into();
        };
        self.data.slot_mut(slot).generation_time = u32::from_be_bytes(bytes);
        Status::Success.into()
    }

    fn put_uif(&mut self, slot: KeySlotId, data: &[u8]) -> Response {
        let Ok(uif): Result<[u8; 2], _> = data.try_into() else {
            return Status::WrongLength.into();
        };
        if UifMode::from_u8(uif[0]).is_none() {
            return Status::IncorrectDataParameter.into();
        }
        let meta = self.data.slot_mut(slot);
        if UifMode::from_u8(meta.uif[0]) == Some(UifMode::Permanent) {
            return Status::ConditionsOfUseNotSatisfied.into();
        }
        meta.uif = uif;
        Status::Success.into()
    }
}

#[cfg(test)]
mod tests {
    use keyroost_openpgp::{
        KeyAlg, KeyCrt, PW1_SIGN, PW3_ADMIN, TAG_AID, TAG_CA_FINGERPRINTS,
        TAG_CARDHOLDER_RELATED_DATA, TAG_EXTENDED_CAPABILITIES, TAG_GENERATION_TIMES,
        TAG_HISTORICAL_BYTES, TAG_LANGUAGE, TAG_LOGIN_DATA, TAG_NAME, TAG_PW_STATUS,
        TAG_SECURITY_SUPPORT, TAG_SEX, TAG_UIF_AUT, TAG_UIF_DEC, TAG_UIF_SIG, TAG_URL, find_nested,
        find_tag, parse_algorithm_information, parse_application_related_data, parse_pw_status,
        parse_signature_counter, parse_tlvs, uif_asks_touch,
    };

    use super::*;

    fn verify_pw3(applet: &mut PgpApplet) {
        let resp = applet.process(&keyroost_openpgp::verify(PW3_ADMIN, b"12345678"));
        assert_eq!(resp.status(), Status::Success);
    }

    #[test]
    fn get_data_parses_with_keyroost_openpgp() {
        let mut applet = PgpApplet::new();

        // 004F AID
        let aid_resp = applet.process(&keyroost_openpgp::get_data(TAG_AID));
        assert_eq!(aid_resp.status(), Status::Success);
        assert_eq!(aid_resp.data(), applet.full_aid());

        // 5F52 Historical bytes
        let hist_resp = applet.process(&keyroost_openpgp::get_data(TAG_HISTORICAL_BYTES));
        assert_eq!(hist_resp.status(), Status::Success);
        assert_eq!(hist_resp.data(), &HISTORICAL_BYTES);

        // 0065 Cardholder Related Data
        let ch_resp = applet.process(&keyroost_openpgp::get_data(TAG_CARDHOLDER_RELATED_DATA));
        assert_eq!(ch_resp.status(), Status::Success);
        let ch_tlvs = parse_tlvs(ch_resp.data()).unwrap();
        assert_eq!(find_tag(&ch_tlvs, TAG_NAME), Some(&[][..]));
        assert_eq!(find_tag(&ch_tlvs, TAG_LANGUAGE), Some(&[][..]));
        assert_eq!(find_tag(&ch_tlvs, TAG_SEX), Some(&b"9"[..]));

        // 006E Application Related Data
        let app_resp = applet.process(&keyroost_openpgp::get_application_related_data());
        assert_eq!(app_resp.status(), Status::Success);
        let app = parse_application_related_data(app_resp.data()).unwrap();
        assert_eq!(app.aid, applet.full_aid());
        assert_eq!(app.algo_attr_sig, DEFAULT_ALGO_ATTR);
        assert_eq!(app.algo_attr_dec, DEFAULT_ALGO_ATTR);
        assert_eq!(app.algo_attr_aut, DEFAULT_ALGO_ATTR);
        assert!(!app.pw_status.pw1_valid_multiple);
        assert_eq!(app.pw_status.tries_pw1, 3);
        assert_eq!(app.pw_status.tries_rc, 0);
        assert_eq!(app.pw_status.tries_pw3, 3);
        assert_eq!(app.fingerprint_sig, [0u8; 20]);

        let app_tlvs = parse_tlvs(app_resp.data()).unwrap();
        assert_eq!(
            find_nested(&app_tlvs, TAG_HISTORICAL_BYTES),
            Some(&HISTORICAL_BYTES[..])
        );
        assert_eq!(
            find_nested(&app_tlvs, TAG_EXTENDED_CAPABILITIES),
            Some(&EXTENDED_CAPABILITIES[..])
        );
        assert_eq!(
            find_nested(&app_tlvs, TAG_CA_FINGERPRINTS),
            Some(&[0u8; 60][..])
        );
        assert_eq!(
            find_nested(&app_tlvs, TAG_GENERATION_TIMES),
            Some(&[0u8; 12][..])
        );

        // 007A Security Support Template
        let sst_resp = applet.process(&keyroost_openpgp::get_data(TAG_SECURITY_SUPPORT));
        assert_eq!(sst_resp.status(), Status::Success);
        assert_eq!(parse_signature_counter(sst_resp.data()).unwrap(), 0);

        // 00C4 PW Status
        let pws_resp = applet.process(&keyroost_openpgp::get_pw_status());
        assert_eq!(pws_resp.status(), Status::Success);
        let pws = parse_pw_status(pws_resp.data()).unwrap();
        assert_eq!(pws, app.pw_status);

        // 00FA Algorithm Information
        let alg_resp = applet.process(&keyroost_openpgp::get_algorithm_information());
        assert_eq!(alg_resp.status(), Status::Success);
        let info = parse_algorithm_information(alg_resp.data()).unwrap();
        assert_eq!(
            info.key_algs(KeyCrt::Sign),
            vec![
                KeyAlg::Rsa2048,
                KeyAlg::Rsa3072,
                KeyAlg::Rsa4096,
                KeyAlg::NistP256,
                KeyAlg::NistP384,
                KeyAlg::NistP521,
                KeyAlg::Ed25519,
            ]
        );
        assert_eq!(
            info.key_algs(KeyCrt::Decrypt),
            vec![
                KeyAlg::Rsa2048,
                KeyAlg::Rsa3072,
                KeyAlg::Rsa4096,
                KeyAlg::NistP256,
                KeyAlg::NistP384,
                KeyAlg::NistP521,
                KeyAlg::X25519,
            ]
        );
        assert_eq!(info.key_algs(KeyCrt::Auth), info.key_algs(KeyCrt::Sign));

        // 00D6/00D7/00D8 UIF
        for tag in [TAG_UIF_SIG, TAG_UIF_DEC, TAG_UIF_AUT] {
            let uif_resp = applet.process(&keyroost_openpgp::get_data(tag));
            assert_eq!(uif_resp.status(), Status::Success);
            assert_eq!(uif_asks_touch(uif_resp.data()), Some(false));
        }

        // Unknown tag and invalid Lc
        assert_eq!(
            applet.process(&keyroost_openpgp::get_data(0x9999)).status(),
            Status::KeyReferenceNotFound
        );
        assert_eq!(
            applet
                .process(&[0x00, 0xCA, 0x00, 0x4F, 0x01, 0x00])
                .status(),
            Status::WrongLength
        );
    }

    #[test]
    fn put_data_requires_pw3_and_updates_metadata() {
        let mut applet = PgpApplet::new();

        // PW1 is not enough for PUT DATA
        assert_eq!(
            applet
                .process(&keyroost_openpgp::verify(PW1_SIGN, b"123456"))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_cardholder_name(b"Doe<<Jane"))
                .status(),
            Status::SecurityStatusNotSatisfied
        );

        // Unknown tag returns KeyReferenceNotFound even before PW3
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(0x9999, b"x"))
                .status(),
            Status::KeyReferenceNotFound
        );

        verify_pw3(&mut applet);

        // Cardholder metadata: Name, Language, Gender, URL, Login data
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_cardholder_name(b"Doe<<Jane"))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(TAG_LANGUAGE, b"enfr"))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(TAG_SEX, b"2"))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_url(
                    b"https://example.invalid/key.asc"
                ))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(TAG_LOGIN_DATA, b"jdoe"))
                .status(),
            Status::Success
        );

        let ch_resp = applet.process(&keyroost_openpgp::get_data(TAG_CARDHOLDER_RELATED_DATA));
        let ch_tlvs = parse_tlvs(ch_resp.data()).unwrap();
        assert_eq!(find_tag(&ch_tlvs, TAG_NAME), Some(&b"Doe<<Jane"[..]));
        assert_eq!(find_tag(&ch_tlvs, TAG_LANGUAGE), Some(&b"enfr"[..]));
        assert_eq!(find_tag(&ch_tlvs, TAG_SEX), Some(&b"2"[..]));
        assert_eq!(
            applet.process(&keyroost_openpgp::get_data(TAG_URL)).data(),
            b"https://example.invalid/key.asc"
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::get_data(TAG_LOGIN_DATA))
                .data(),
            b"jdoe"
        );

        // Validation errors
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_cardholder_name(&[b'A'; 40]))
                .status(),
            Status::WrongLength
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(TAG_LANGUAGE, b"123456789"))
                .status(),
            Status::WrongLength
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(TAG_SEX, b"5"))
                .status(),
            Status::IncorrectDataParameter
        );
    }

    #[test]
    fn put_data_algo_attr_wipes_fingerprint_and_timestamp_on_change() {
        let mut applet = PgpApplet::new();
        verify_pw3(&mut applet);

        let fpr = [0xAB; 20];
        let ts = 1_700_000_000u32;
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_fingerprint(KeyCrt::Sign, &fpr))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_generation_time(KeyCrt::Sign, ts))
                .status(),
            Status::Success
        );

        // Writing the SAME algorithm attributes preserves fingerprint and timestamp
        let rsa2048 = KeyAlg::Rsa2048.attributes(KeyCrt::Sign).unwrap();
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_algorithm_attributes(
                    KeyCrt::Sign,
                    &rsa2048
                ))
                .status(),
            Status::Success
        );
        let app = parse_application_related_data(
            applet
                .process(&keyroost_openpgp::get_application_related_data())
                .data(),
        )
        .unwrap();
        assert_eq!(app.fingerprint_sig, fpr);

        // Changing to Ed25519 wipes fingerprint and timestamp
        let ed25519 = KeyAlg::Ed25519.attributes(KeyCrt::Sign).unwrap();
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_algorithm_attributes(
                    KeyCrt::Sign,
                    &ed25519
                ))
                .status(),
            Status::Success
        );
        let app_resp = applet.process(&keyroost_openpgp::get_application_related_data());
        let app = parse_application_related_data(app_resp.data()).unwrap();
        assert_eq!(app.algo_attr_sig, ed25519);
        assert_eq!(app.fingerprint_sig, [0u8; 20]);
        let app_tlvs = parse_tlvs(app_resp.data()).unwrap();
        assert_eq!(
            find_nested(&app_tlvs, TAG_GENERATION_TIMES),
            Some(&[0u8; 12][..])
        );

        // Decryption slot accepts X25519, rejects Ed25519
        let x25519 = KeyAlg::X25519.attributes(KeyCrt::Decrypt).unwrap();
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_algorithm_attributes(
                    KeyCrt::Decrypt,
                    &x25519
                ))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_algorithm_attributes(
                    KeyCrt::Decrypt,
                    &ed25519
                ))
                .status(),
            Status::IncorrectDataParameter
        );
    }

    #[test]
    fn put_data_pw_status_rc_and_uif() {
        let mut applet = PgpApplet::new();
        verify_pw3(&mut applet);

        // PW Status (00C4)
        assert!(!applet.pw1_valid_multiple());
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(TAG_PW_STATUS, &[0x01]))
                .status(),
            Status::Success
        );
        assert!(applet.pw1_valid_multiple());
        let pws =
            parse_pw_status(applet.process(&keyroost_openpgp::get_pw_status()).data()).unwrap();
        assert!(pws.pw1_valid_multiple);
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(TAG_PW_STATUS, &[0x02]))
                .status(),
            Status::IncorrectDataParameter
        );

        // Resetting Code (00D3): set then clear
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(0x00D3, b"resetcode"))
                .status(),
            Status::Success
        );
        let pws =
            parse_pw_status(applet.process(&keyroost_openpgp::get_pw_status()).data()).unwrap();
        assert_eq!(pws.tries_rc, 3);

        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(0x00D3, &[]))
                .status(),
            Status::Success
        );
        let pws =
            parse_pw_status(applet.process(&keyroost_openpgp::get_pw_status()).data()).unwrap();
        assert_eq!(pws.tries_rc, 0);

        // UIF (00D6): off -> on -> permanent (locked)
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(TAG_UIF_SIG, &[0x01, 0x20]))
                .status(),
            Status::Success
        );
        assert_eq!(
            uif_asks_touch(
                applet
                    .process(&keyroost_openpgp::get_data(TAG_UIF_SIG))
                    .data()
            ),
            Some(true)
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(TAG_UIF_SIG, &[0x02, 0x20]))
                .status(),
            Status::Success
        );
        assert_eq!(
            applet
                .process(&keyroost_openpgp::put_data(TAG_UIF_SIG, &[0x00, 0x20]))
                .status(),
            Status::ConditionsOfUseNotSatisfied
        );
    }
}
