//! Configuration parsing and loading for `sftcrd-pgp`.
//!
//! Provides structures and deserializers to initialize a [`PgpApplet`] from
//! configuration providers (such as TOML files loaded with [`figment`]),
//! including support for PEM-encoded private keys and on-startup key generation.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use figment::Figment;
use figment::providers::{Format, Toml};
use serde::Deserialize;
use sftcrd_key::{KeyAlg, PublicKey, RsaBits, SlotKey};
use sha1::{Digest as _, Sha1};
use toml_example::TomlExample;

use crate::PgpApplet;
use crate::data::{
    MAX_LANGUAGE_LEN, MAX_LOGIN_DATA_LEN, MAX_NAME_LEN, MAX_URL_LEN, OID_ED25519, OID_NIST_P256,
    OID_NIST_P384, OID_NIST_P521, OID_X25519,
};
use crate::pgp::{AlgoId, Gender, KeySlotId, UifMode};
use crate::pin::PwRef;

/// Errors that can occur when reading or applying configuration to an `OpenPGP` applet.
#[derive(Debug)]
pub enum ConfigError {
    /// A figment configuration error.
    Figment(Box<figment::Error>),
    /// An unknown or invalid slot name/identifier.
    InvalidSlot(String),
    /// An invalid PIN, admin PIN, or Resetting Code value.
    InvalidPin(String),
    /// Invalid cardholder metadata (name, language, gender, url, or login).
    InvalidCardholderData(String),
    /// An invalid touch policy (UIF) string.
    InvalidPolicy(String),
    /// An invalid v4 fingerprint hex string.
    InvalidFingerprint(String),
    /// A PEM decoding error.
    PemError(String),
    /// An unsupported, invalid, or slot-incompatible cryptographic key.
    KeyError(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Figment(e) => write!(f, "configuration error: {e}"),
            Self::InvalidSlot(s) => write!(f, "invalid slot identifier: {s}"),
            Self::InvalidPin(s) => write!(f, "invalid PIN/RC: {s}"),
            Self::InvalidCardholderData(s) => write!(f, "invalid cardholder data: {s}"),
            Self::InvalidPolicy(s) => write!(f, "invalid policy: {s}"),
            Self::InvalidFingerprint(s) => write!(f, "invalid fingerprint: {s}"),
            Self::PemError(s) => write!(f, "PEM decode error: {s}"),
            Self::KeyError(s) => write!(f, "key error: {s}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Figment(e) => Some(e),
            _ => None,
        }
    }
}

impl From<figment::Error> for ConfigError {
    fn from(err: figment::Error) -> Self {
        Self::Figment(Box::new(err))
    }
}

/// Configuration for the `OpenPGP` Card v3.4 applet (`[pgp]`).
#[derive(TomlExample, Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct PgpConfig {
    /// User PIN (PW1, 6–127 bytes). Defaults to `"123456"`.
    #[toml_example(default = "123456", require)]
    pub user_pin: Option<String>,
    /// Admin PIN (PW3, 8–127 bytes). Defaults to `"12345678"`.
    #[toml_example(default = "12345678", require)]
    pub admin_pin: Option<String>,
    /// Optional Resetting Code (RC, 8–127 bytes). Unset by default.
    #[toml_example(default = "12345678", require)]
    pub reset_code: Option<String>,
    /// Whether PW1 (`0x81`) remains valid for multiple `PSO:CDS` commands.
    #[toml_example(default = false, require)]
    pub pw1_valid_multiple: Option<bool>,
    /// Cardholder name (`5B`, max 39 bytes, `Surname<<GivenName`).
    #[toml_example(default = "Doe<<Jane", require)]
    pub name: Option<String>,
    /// Cardholder language preferences (`5F2D`, max 8 bytes, ISO 639-1).
    #[toml_example(default = "en", require)]
    pub language: Option<String>,
    /// Cardholder gender (`5F35`, ISO/IEC 5218: `"0"`/`"unknown"`, `"1"`/`"male"`, `"2"`/`"female"`, `"9"`/`"not_applicable"`).
    #[toml_example(default = "9", require)]
    pub gender: Option<String>,
    /// Public key URL (`5F50`, max 2048 bytes).
    #[toml_example(default = "https://example.com/key.asc", require)]
    pub url: Option<String>,
    /// Cardholder login data (`5E`, max 2048 bytes).
    #[toml_example(default = "jdoe", require)]
    pub login: Option<String>,
    /// Key slot configurations mapped by slot name (`"sign"`, `"decrypt"`, `"auth"`).
    #[serde(default)]
    #[toml_example(default = "sign", nesting)]
    pub slots: BTreeMap<String, SlotConfig>,
}

/// Configuration for an `OpenPGP` key slot (`[pgp.slots.<sign|decrypt|auth>]`).
#[derive(TomlExample, Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct SlotConfig {
    /// Algorithm name to generate on startup (`"rsa2048"`, `"rsa3072"`, `"rsa4096"`,
    /// `"p256"`, `"p384"`, `"p521"`, `"ed25519"`, `"x25519"`) or a PEM-encoded
    /// private key (`PRIVATE KEY`, `RSA PRIVATE KEY`, or `EC PRIVATE KEY`).
    #[toml_example(default = "ed25519", require)]
    pub key: Option<String>,
    /// Key creation timestamp as Unix seconds (`u32`). Defaults to current time when `key` is set.
    #[toml_example(default = 1_700_000_000, require)]
    pub created: Option<u32>,
    /// Optional RFC 4880 v4 fingerprint override (40 hex characters / 20 bytes).
    /// Auto-computed from the public key and `created` timestamp when omitted.
    #[toml_example(default = "0123456789abcdef0123456789abcdef01234567", require)]
    pub fingerprint: Option<String>,
    /// User Interaction Flag (UIF) touch policy: `"off"`, `"on"`, or `"permanent"`.
    #[toml_example(default = "off", require)]
    pub touch_policy: Option<String>,
}

fn parse_slot_id(s: &str) -> Result<KeySlotId, ConfigError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "sign" | "sig" | "signature" | "b6" => Ok(KeySlotId::Sig),
        "decrypt" | "dec" | "decryption" | "b8" => Ok(KeySlotId::Dec),
        "auth" | "aut" | "authentication" | "a4" => Ok(KeySlotId::Aut),
        _ => Err(ConfigError::InvalidSlot(s.to_string())),
    }
}

fn parse_gender(s: &str) -> Result<Gender, ConfigError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "0" | "not_known" | "notknown" | "unknown" => Ok(Gender::NotKnown),
        "1" | "male" | "m" => Ok(Gender::Male),
        "2" | "female" | "f" => Ok(Gender::Female),
        "9" | "not_applicable" | "notapplicable" | "na" => Ok(Gender::NotApplicable),
        other => Err(ConfigError::InvalidCardholderData(format!(
            "invalid gender value '{other}', expected 0/1/2/9 or unknown/male/female/not_applicable"
        ))),
    }
}

fn parse_uif(s: &str) -> Result<[u8; 2], ConfigError> {
    let mode = match s.trim().to_ascii_lowercase().as_str() {
        "off" | "never" => UifMode::Off,
        "on" | "always" => UifMode::On,
        "permanent" | "fixed" => UifMode::Permanent,
        other => {
            return Err(ConfigError::InvalidPolicy(format!(
                "invalid touch policy '{other}', expected off, on, or permanent"
            )));
        }
    };
    Ok([mode as u8, 0x20])
}

fn parse_fingerprint_hex(s: &str) -> Result<[u8; 20], ConfigError> {
    let clean = s.trim().replace([' ', ':', '-'], "");
    let bytes = hex::decode(&clean)
        .map_err(|e| ConfigError::InvalidFingerprint(format!("invalid hex: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        ConfigError::InvalidFingerprint(format!(
            "expected 20-byte (40 hex char) v4 fingerprint, got {} bytes",
            v.len()
        ))
    })
}

fn parse_or_generate_slot_key(spec: &str) -> Result<SlotKey, ConfigError> {
    let alg = match spec.trim().to_ascii_lowercase().as_str() {
        "rsa2048" => Some(KeyAlg::Rsa(RsaBits::Rsa2048)),
        "rsa3072" => Some(KeyAlg::Rsa(RsaBits::Rsa3072)),
        "rsa4096" => Some(KeyAlg::Rsa(RsaBits::Rsa4096)),
        "p256" | "eccp256" | "nistp256" => Some(KeyAlg::P256),
        "p384" | "eccp384" | "nistp384" => Some(KeyAlg::P384),
        "p521" | "eccp521" | "nistp521" => Some(KeyAlg::P521),
        "ed25519" => Some(KeyAlg::Ed25519),
        "x25519" => Some(KeyAlg::X25519),
        _ => None,
    };

    if let Some(alg) = alg {
        return SlotKey::generate(alg)
            .map_err(|_| ConfigError::KeyError(format!("failed to generate {alg:?} key")));
    }

    let key = SlotKey::from_pem(spec).map_err(|err| match err {
        sftcrd_key::KeyError::Pem(msg) => ConfigError::PemError(msg),
        other => ConfigError::KeyError(other.to_string()),
    })?;

    if matches!(key.alg(), KeyAlg::Rsa(RsaBits::Rsa1024)) {
        return Err(ConfigError::KeyError(
            "RSA-1024 is not supported by OpenPGP Card v3.4 (use rsa2048, rsa3072, or rsa4096)"
                .to_string(),
        ));
    }

    Ok(key)
}

/// Build the `OpenPGP` Card algorithm attributes (`C1`/`C2`/`C3`) for `key` in `slot`,
/// rejecting slot-incompatible algorithms (e.g. `Ed25519` in `decrypt` or `X25519` in `sign`).
fn algo_attr_for_slot(slot: KeySlotId, key: &SlotKey) -> Result<Vec<u8>, ConfigError> {
    match key.alg() {
        KeyAlg::Rsa(bits) => {
            let n_bits = (bits as u16).to_be_bytes();
            let PublicKey::Rsa { e, .. } = key.public_key() else {
                unreachable!("RSA key always produces PublicKey::Rsa");
            };
            let e_bits = mpi_bit_len(&e).max(1);
            let e_bytes = e_bits.to_be_bytes();
            Ok(vec![
                AlgoId::Rsa as u8,
                n_bits[0],
                n_bits[1],
                e_bytes[0],
                e_bytes[1],
                0x00,
            ])
        }
        KeyAlg::P256 => Ok(ecc_algo_attr(slot, OID_NIST_P256)),
        KeyAlg::P384 => Ok(ecc_algo_attr(slot, OID_NIST_P384)),
        KeyAlg::P521 => Ok(ecc_algo_attr(slot, OID_NIST_P521)),
        KeyAlg::Ed25519 => match slot {
            KeySlotId::Sig | KeySlotId::Aut => {
                let mut attr = vec![AlgoId::EdDsa as u8];
                attr.extend_from_slice(OID_ED25519);
                Ok(attr)
            }
            KeySlotId::Dec => Err(ConfigError::KeyError(
                "Ed25519 is only supported in sign and auth slots, not decrypt".to_string(),
            )),
        },
        KeyAlg::X25519 => match slot {
            KeySlotId::Dec => {
                let mut attr = vec![AlgoId::Ecdh as u8];
                attr.extend_from_slice(OID_X25519);
                Ok(attr)
            }
            KeySlotId::Sig | KeySlotId::Aut => Err(ConfigError::KeyError(
                "X25519 is only supported in the decrypt slot".to_string(),
            )),
        },
    }
}

fn ecc_algo_attr(slot: KeySlotId, oid: &[u8]) -> Vec<u8> {
    let algo_id = match slot {
        KeySlotId::Sig | KeySlotId::Aut => AlgoId::Ecdsa,
        KeySlotId::Dec => AlgoId::Ecdh,
    };
    let mut attr = Vec::with_capacity(1 + oid.len());
    attr.push(algo_id as u8);
    attr.extend_from_slice(oid);
    attr
}

/// Compute the RFC 4880 §12.2 v4 fingerprint (`SHA-1(0x99 || len_be16 || packet_body)`).
fn compute_v4_fingerprint(slot: KeySlotId, key: &SlotKey, created: u32) -> [u8; 20] {
    let mut body = Vec::new();
    // Version 4 + 4-byte creation timestamp
    body.push(0x04);
    body.extend_from_slice(&created.to_be_bytes());

    match (key.alg(), key.public_key()) {
        (KeyAlg::Rsa(_), PublicKey::Rsa { n, e }) => {
            body.push(AlgoId::Rsa as u8);
            push_mpi(&mut body, &n);
            push_mpi(&mut body, &e);
        }
        (KeyAlg::P256, PublicKey::Point(pt)) => {
            push_nist_ecc_body(&mut body, slot, OID_NIST_P256, &pt, 0x08, 0x07);
        }
        (KeyAlg::P384, PublicKey::Point(pt)) => {
            push_nist_ecc_body(&mut body, slot, OID_NIST_P384, &pt, 0x09, 0x09);
        }
        (KeyAlg::P521, PublicKey::Point(pt)) => {
            push_nist_ecc_body(&mut body, slot, OID_NIST_P521, &pt, 0x0A, 0x09);
        }
        (KeyAlg::Ed25519, PublicKey::Point(pt)) => {
            body.push(AlgoId::EdDsa as u8);
            push_oid(&mut body, OID_ED25519);
            let mut prefixed = Vec::with_capacity(1 + pt.len());
            prefixed.push(0x40);
            prefixed.extend_from_slice(&pt);
            push_mpi(&mut body, &prefixed);
        }
        (KeyAlg::X25519, PublicKey::Point(pt)) => {
            body.push(AlgoId::Ecdh as u8);
            push_oid(&mut body, OID_X25519);
            let mut prefixed = Vec::with_capacity(1 + pt.len());
            prefixed.push(0x40);
            prefixed.extend_from_slice(&pt);
            push_mpi(&mut body, &prefixed);
            // RFC 6637 KDF: len=3, reserved=1, SHA-256 (0x08), AES-128 (0x07)
            body.extend_from_slice(&[0x03, 0x01, 0x08, 0x07]);
        }
        _ => unreachable!("key.alg() and key.public_key() always match"),
    }

    let len = u16::try_from(body.len()).expect("v4 public-key packet fits in u16");
    let mut hasher = Sha1::new();
    hasher.update([0x99]);
    hasher.update(len.to_be_bytes());
    hasher.update(&body);
    hasher.finalize().into()
}

fn push_nist_ecc_body(
    body: &mut Vec<u8>,
    slot: KeySlotId,
    oid: &[u8],
    point: &[u8],
    kdf_hash: u8,
    kdf_cipher: u8,
) {
    match slot {
        KeySlotId::Sig | KeySlotId::Aut => {
            body.push(AlgoId::Ecdsa as u8);
            push_oid(body, oid);
            push_mpi(body, point);
        }
        KeySlotId::Dec => {
            body.push(AlgoId::Ecdh as u8);
            push_oid(body, oid);
            push_mpi(body, point);
            body.extend_from_slice(&[0x03, 0x01, kdf_hash, kdf_cipher]);
        }
    }
}

fn push_oid(buf: &mut Vec<u8>, oid: &[u8]) {
    let len = u8::try_from(oid.len()).expect("OID length fits in u8");
    buf.push(len);
    buf.extend_from_slice(oid);
}

fn mpi_bit_len(bytes: &[u8]) -> u16 {
    let trimmed = trim_leading_zeros(bytes);
    let Some((&first, rest)) = trimmed.split_first() else {
        return 0;
    };
    let bits = (8 - first.leading_zeros() as usize) + rest.len() * 8;
    u16::try_from(bits).expect("MPI bit length fits in u16")
}

fn push_mpi(buf: &mut Vec<u8>, bytes: &[u8]) {
    let trimmed = trim_leading_zeros(bytes);
    let bits = mpi_bit_len(trimmed);
    buf.extend_from_slice(&bits.to_be_bytes());
    buf.extend_from_slice(trimmed);
}

fn trim_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    &bytes[first_nonzero..]
}

fn current_unix_timestamp() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
}

impl PgpApplet {
    /// Create a [`PgpApplet`] initialized from a [`Figment`] configuration provider.
    ///
    /// The provider can contain either a top-level `[pgp]` table or a direct [`PgpConfig`].
    /// An optional root `serial` field sets the 32-bit card serial in the AID.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if configuration parsing, PIN/cardholder validation,
    /// or key decoding/generation fails.
    pub fn from_figment(figment: &Figment) -> Result<Self, ConfigError> {
        let pgp_config: PgpConfig = if figment.find_value("pgp").is_ok() {
            figment.extract_inner("pgp")?
        } else {
            figment.extract()?
        };

        let serial = figment
            .extract_inner::<u32>("serial")
            .unwrap_or(crate::DEFAULT_SERIAL);

        Self::from_config(&pgp_config, serial)
    }

    /// Convenience method to create a [`PgpApplet`] by reading a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read, decoded, or contains invalid configuration.
    pub fn from_toml_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let figment = Figment::new().merge(Toml::file(path));
        Self::from_figment(&figment)
    }

    /// Convenience method to create a [`PgpApplet`] by reading a TOML string.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the string cannot be parsed as TOML or contains invalid configuration.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, ConfigError> {
        let figment = Figment::new().merge(Toml::string(toml_str));
        Self::from_figment(&figment)
    }

    /// Construct a [`PgpApplet`] from a [`PgpConfig`] and 32-bit card serial.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any PIN, cardholder metadata, slot policy, key,
    /// or fingerprint fails validation.
    pub fn from_config(config: &PgpConfig, serial: u32) -> Result<Self, ConfigError> {
        let mut applet = Self::with_serial(serial);

        apply_pin_config(&mut applet, config)?;
        apply_cardholder_config(&mut applet, config)?;
        for (slot_name, slot_cfg) in &config.slots {
            apply_slot_config(&mut applet, slot_name, slot_cfg)?;
        }

        Ok(applet)
    }
}

fn apply_pin_config(applet: &mut PgpApplet, config: &PgpConfig) -> Result<(), ConfigError> {
    if let Some(pin) = &config.user_pin {
        let bytes = pin.as_bytes();
        let slot = applet.pins.slot_mut(PwRef::Pw1Sign);
        if !slot.is_valid_new_pin(bytes) {
            return Err(ConfigError::InvalidPin(format!(
                "user_pin (PW1) length must be 6..=127 bytes, got {}",
                bytes.len()
            )));
        }
        slot.set_value(bytes);
    }

    if let Some(pin) = &config.admin_pin {
        let bytes = pin.as_bytes();
        let slot = applet.pins.slot_mut(PwRef::Pw3Admin);
        if !slot.is_valid_new_pin(bytes) {
            return Err(ConfigError::InvalidPin(format!(
                "admin_pin (PW3) length must be 8..=127 bytes, got {}",
                bytes.len()
            )));
        }
        slot.set_value(bytes);
    }

    if let Some(rc) = &config.reset_code {
        applet.pins.set_rc(rc.as_bytes()).map_err(|_| {
            ConfigError::InvalidPin(format!(
                "reset_code (RC) length must be 8..=127 bytes, got {}",
                rc.len()
            ))
        })?;
    }

    if let Some(valid_multiple) = config.pw1_valid_multiple {
        applet.pins.set_pw1_valid_multiple(valid_multiple);
    }

    Ok(())
}

fn apply_cardholder_config(applet: &mut PgpApplet, config: &PgpConfig) -> Result<(), ConfigError> {
    if let Some(name) = &config.name {
        if name.len() > MAX_NAME_LEN {
            return Err(ConfigError::InvalidCardholderData(format!(
                "name exceeds {MAX_NAME_LEN} bytes (got {})",
                name.len()
            )));
        }
        applet.data.name = name.as_bytes().to_vec();
    }

    if let Some(language) = &config.language {
        if language.len() > MAX_LANGUAGE_LEN {
            return Err(ConfigError::InvalidCardholderData(format!(
                "language exceeds {MAX_LANGUAGE_LEN} bytes (got {})",
                language.len()
            )));
        }
        applet.data.language = language.as_bytes().to_vec();
    }

    if let Some(gender) = &config.gender {
        applet.data.gender = parse_gender(gender)?;
    }

    if let Some(url) = &config.url {
        if url.len() > MAX_URL_LEN {
            return Err(ConfigError::InvalidCardholderData(format!(
                "url exceeds {MAX_URL_LEN} bytes (got {})",
                url.len()
            )));
        }
        applet.data.url = url.as_bytes().to_vec();
    }

    if let Some(login) = &config.login {
        if login.len() > MAX_LOGIN_DATA_LEN {
            return Err(ConfigError::InvalidCardholderData(format!(
                "login exceeds {MAX_LOGIN_DATA_LEN} bytes (got {})",
                login.len()
            )));
        }
        applet.data.login_data = login.as_bytes().to_vec();
    }

    Ok(())
}

fn apply_slot_config(
    applet: &mut PgpApplet,
    slot_name: &str,
    slot_cfg: &SlotConfig,
) -> Result<(), ConfigError> {
    let slot_id = parse_slot_id(slot_name)?;

    if let Some(key_spec) = &slot_cfg.key {
        let key = parse_or_generate_slot_key(key_spec)?;
        let algo_attr = algo_attr_for_slot(slot_id, &key)?;
        let created = slot_cfg.created.unwrap_or_else(current_unix_timestamp);
        let fingerprint = match &slot_cfg.fingerprint {
            Some(hex_str) => parse_fingerprint_hex(hex_str)?,
            None => compute_v4_fingerprint(slot_id, &key, created),
        };

        let meta = applet.data.slot_mut(slot_id);
        meta.algo_attr = algo_attr;
        meta.generation_time = created;
        meta.fingerprint = fingerprint;
        meta.key = Some(key);
    } else {
        if let Some(created) = slot_cfg.created {
            applet.data.slot_mut(slot_id).generation_time = created;
        }
        if let Some(hex_str) = &slot_cfg.fingerprint {
            applet.data.slot_mut(slot_id).fingerprint = parse_fingerprint_hex(hex_str)?;
        }
    }

    if let Some(touch_policy) = &slot_cfg.touch_policy {
        applet.data.slot_mut(slot_id).uif = parse_uif(touch_policy)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use iso7816::Status;
    use keyroost_openpgp::{
        PW1_OTHER, PW1_SIGN, PW3_ADMIN, TAG_CARDHOLDER_RELATED_DATA, TAG_GENERATION_TIMES,
        TAG_LANGUAGE, TAG_LOGIN_DATA, TAG_NAME, TAG_PW_STATUS, TAG_SEX, TAG_UIF_AUT, TAG_UIF_DEC,
        TAG_UIF_SIG, TAG_URL, find_nested, find_tag, parse_application_related_data,
        parse_pw_status, parse_tlvs, pso_compute_signature,
    };

    use super::*;

    fn generation_times(app_data: &[u8]) -> (u32, u32, u32) {
        let tlvs = parse_tlvs(app_data).unwrap();
        let bytes = find_nested(&tlvs, TAG_GENERATION_TIMES).unwrap();
        assert_eq!(bytes.len(), 12);
        (
            u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
            u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
        )
    }

    const TEST_ED25519_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
-----END PRIVATE KEY-----";

    const TEST_X25519_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4
-----END PRIVATE KEY-----";

    const TEST_P384_SEC1: &str = "\
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCDlYqyUE4s+xlVwfUOU57J/wCW8YREw3RA5CDiKX8BjfgW/LCNKWXE
GWAZ1FBFPcWgBwYFK4EEACKhZANiAASCNFq0Bdkbhp9OXsiZeL40STVXFSZ70gzr
O/hSw0YY7rkQBo8T7r+IqdjWzbhy3N93ya7owpDZpOiF/teztDAPNu/FZv9H/ELg
hIufgaERoMAmoWCzWMxH789ZHedDSBk=
-----END EC PRIVATE KEY-----";

    const TEST_RSA2048_PKCS1: &str = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA74pEU5KTXCW8d+NWhTks41PwKG4kKMfe1SuErt2OV/JF9+Gq
MDb2UZns4DvSRVNbzH7yhxI8ngqAYx8B0cP8B6UGpwPPcWwpkVoo7jaF32wMmhup
PhxXSXs5YyBf4alCnuoqIHzRmw8VTnAOadWKgkcbx6FKynRIuXdD6B7Y1rKfhYDJ
nOUva5FIWXyRuLsNn1h6yunHkhCltpKHJwLCLfPl5bzv5QISk1XMKGG8aTIJSsUu
Q5ahSWi/wALbqZ7GPzof7iP/yW7saNEveTl6bGZNKWZcK3N5/5DZHhsm7Z9iaPjV
pmPaq30OaNbNzuh1nCoFS5QnR+Dhzc7gBgjS5QIDAQABAoH/Wv7rddP4psivD9wM
wg82PiVk1fcBRXyn6dLeVI9Vw5MFgWT4gdhfOiB/G6+d8Tf5Z3XSK/2BiYfzvbPJ
vSX2V/EY1dlctHmiUNUvN07/DCC/qMtZP38EqaVl54Ik6lSiOjw6RJ0mAwF31pQ6
5Xl5ZIQeyXc8Mix6c/oakdMmDGiShJk9BjX5eYBlYLt2cQJBP9vZSj2QhN/w2KEi
WHv1uqfPUm/uex9FZ83gSVd1IOXbF2IOrvYqNCO8Pnkn1SLwV0uECVrguopH7ang
/VyrLzKEvoCMvIEnxSZf/DNsagtbYfnyhJdAghMhmjbyTYrFIJLZ+71DbKB/Xtnv
RixZAoGBAPwTO4AL1DsZOEkz/fL07QaYTZTgufcUYNN90JWlgFB82rgyaGzIT6KT
sf951THtfu024wA+pqHumju4bkZCWDNVTQ/ZGMsUvPCqUzWDSN75DpuvMSQi+9Aa
WSSK8iW9mBoPjRVFHwFj50AIDLnc29sxyLYRGt/j8lXzec/H+BaJAoGBAPNFEfBm
bG7l0xXW1+IXdVNYWPQAU7wQmjWrvWNsI4gp4nQtFfvCZW9EirVo4CKVFoYPTl/c
FeiLXNNOw5KfwuXktC90zuLhqWcYzCOs6kR1q2VKxToJpAqSJt7+43ybYgtWkbXd
jIdqQy1WAeMzOyLaqxKIjF9PKVKa5QqlwsJ9AoGBAPl+h6vLCXqdEarSvQ2WAmw+
nrs2WpoFH3j01FjpgEEp8snRiq3w7XE6wjjc+3j5WmGrq654VDF+mkV13B/KVsYo
Laf79qA6nG+QBd+3W47l7+GD2x2rSpXFHmoe5GEacMuKjNd6nJ+hpCcqUH497ZXc
ho4+C92CHj+YRv6zLAgRAoGBALDVWWftnA60407xwDXqJW/zPZ4IitWfH+m5sE6Q
Mfftsl4O0/cQ5RkPsuCRnrOkuh2zDJ6j5g0HGO/FRmbT2SGxsMT6XNURgkmd/e5E
6HnhKzjTNDCvB15jxPu+PnC6pndlcz/HDzr0JGbVKUQVXnxEhaxQM/GoInqYe7vU
qJElAoGANlVvAFKxER5CUiOVaOpmhVcswZceb/PWMAQLw1h+brD2TAaiGZ0jRfrh
wAC767xWSAzpXw0+PefV3lM0w6c3BuiZp81Q9pGhYagwqj/jFBtPaICdGKfVOVGw
U+YErUxH46LD3Jz+qlYG5o7XmP78qnA5pFhePHaBykZ7mfw1w/Y=
-----END RSA PRIVATE KEY-----";

    #[test]
    fn toml_example_renders_and_parses() {
        let example = PgpConfig::toml_example();
        assert!(example.contains("user_pin"));
        assert!(example.contains("admin_pin"));
        assert!(example.contains("reset_code"));
        assert!(example.contains("pw1_valid_multiple"));
        assert!(example.contains("[slots.sign]"));
    }

    #[test]
    fn load_toml_pins_cardholder_and_serial() {
        let toml = r#"
            serial = 0x11223344

            [pgp]
            user_pin = "654321"
            admin_pin = "87654321"
            reset_code = "reset123"
            pw1_valid_multiple = true
            name = "Doe<<Jane"
            language = "enfr"
            gender = "female"
            url = "https://example.com/jane.asc"
            login = "jdoe"
        "#;

        let mut applet = PgpApplet::from_toml_str(toml).unwrap();
        assert_eq!(&applet.full_aid()[10..14], &[0x11, 0x22, 0x33, 0x44]);

        // Verify configured PW1 and PW3 (defaults should fail)
        assert_ne!(
            applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"123456")).status(),
            Status::Success
        );
        assert_eq!(
            applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"654321")).status(),
            Status::Success
        );
        assert_eq!(
            applet.process(&keyroost_openpgp::verify(PW3_ADMIN, b"87654321")).status(),
            Status::Success
        );

        // Verify pw1_valid_multiple
        assert!(applet.pw1_valid_multiple());
        let pw_status = parse_pw_status(applet.process(&keyroost_openpgp::get_data(TAG_PW_STATUS)).data()).unwrap();
        assert!(pw_status.pw1_valid_multiple);

        // Verify RC unblocks PW1
        for _ in 0..3 {
            let _ = applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"wrong!"));
        }
        assert_eq!(
            applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"654321")).status(),
            Status::OperationBlocked
        );
        let mut rrc_apdu = vec![0x00, 0x2C, 0x00, PW1_SIGN, 14];
        rrc_apdu.extend_from_slice(b"reset123");
        rrc_apdu.extend_from_slice(b"112233");
        assert_eq!(applet.process(&rrc_apdu).status(), Status::Success);
        assert_eq!(
            applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"112233")).status(),
            Status::Success
        );

        // Verify cardholder metadata
        let ch_resp = applet.process(&keyroost_openpgp::get_data(TAG_CARDHOLDER_RELATED_DATA));
        let ch = parse_tlvs(ch_resp.data()).unwrap();
        assert_eq!(find_tag(&ch, TAG_NAME), Some(b"Doe<<Jane".as_slice()));
        assert_eq!(find_tag(&ch, TAG_LANGUAGE), Some(b"enfr".as_slice()));
        assert_eq!(find_tag(&ch, TAG_SEX), Some(b"2".as_slice()));
        assert_eq!(
            applet.process(&keyroost_openpgp::get_data(TAG_URL)).data(),
            b"https://example.com/jane.asc"
        );
        assert_eq!(
            applet.process(&keyroost_openpgp::get_data(TAG_LOGIN_DATA)).data(),
            b"jdoe"
        );
    }

    #[test]
    fn load_direct_pgp_config_without_section_wrapper() {
        let toml = r#"
            user_pin = "abcdef"
            gender = "1"
        "#;
        let mut applet = PgpApplet::from_toml_str(toml).unwrap();
        assert_eq!(
            applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"abcdef")).status(),
            Status::Success
        );
        let ch_resp = applet.process(&keyroost_openpgp::get_data(TAG_CARDHOLDER_RELATED_DATA));
        let ch = parse_tlvs(ch_resp.data()).unwrap();
        assert_eq!(find_tag(&ch, TAG_SEX), Some(b"1".as_slice()));
    }

    #[test]
    fn load_pem_keys_computes_v4_fingerprint_and_signs() {
        let toml = format!(
            r#"
            [pgp.slots.sign]
            key = """
{TEST_ED25519_PKCS8}
"""
            created = 1700000000
            touch_policy = "on"

            [pgp.slots.decrypt]
            key = """
{TEST_X25519_PKCS8}
"""
            created = 1700000001
            fingerprint = "00112233445566778899aabbccddeeff00112233"

            [pgp.slots.auth]
            key = """
{TEST_P384_SEC1}
"""
            touch_policy = "permanent"
            "#
        );

        let mut applet = PgpApplet::from_toml_str(&toml).unwrap();
        let app_resp = applet.process(&keyroost_openpgp::get_application_related_data());
        let app = parse_application_related_data(app_resp.data()).unwrap();
        let (gen_sig, gen_dec, gen_aut) = generation_times(app_resp.data());

        // Sign slot: auto-computed v4 fingerprint, created=1700000000, UIF=on
        assert_eq!(gen_sig, 1_700_000_000);
        assert_ne!(app.fingerprint_sig, [0u8; 20]);
        assert_eq!(
            applet.process(&keyroost_openpgp::get_data(TAG_UIF_SIG)).data(),
            &[0x01, 0x20]
        );

        // Verify Ed25519 signature via PSO:CDS
        assert_eq!(
            applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"123456")).status(),
            Status::Success
        );
        let sig_resp = applet.process(&pso_compute_signature(b"hello-openpgp"));
        assert_eq!(sig_resp.status(), Status::Success);
        assert_eq!(sig_resp.data().len(), 64);

        // Decrypt slot: explicit fingerprint override, created=1700000001
        assert_eq!(gen_dec, 1_700_000_001);
        assert_eq!(
            app.fingerprint_dec,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff, 0x00, 0x11, 0x22, 0x33
            ]
        );

        // Auth slot: omitted created -> auto-populated, omitted fingerprint -> auto-computed, UIF=permanent
        assert!(gen_aut > 0);
        assert_ne!(app.fingerprint_aut, [0u8; 20]);
        assert_eq!(
            applet.process(&keyroost_openpgp::get_data(TAG_UIF_AUT)).data(),
            &[0x02, 0x20]
        );

        // Verify P-384 INTERNAL AUTHENTICATE works
        assert_eq!(
            applet.process(&keyroost_openpgp::verify(PW1_OTHER, b"123456")).status(),
            Status::Success
        );
        let auth_resp = applet.process(&keyroost_openpgp::internal_authenticate(&[0x42u8; 48]));
        assert_eq!(auth_resp.status(), Status::Success);
        assert_eq!(auth_resp.data().len(), 96);
    }

    #[test]
    fn load_rsa_pkcs1_pem_and_random_keygen_slots() {
        // Test RSA-2048 PKCS#1 PEM in auth and random keygen in sign/decrypt
        let toml = format!(
            r#"
            [pgp.slots.sign]
            key = "p256"
            touch_policy = "off"

            [pgp.slots.decrypt]
            key = "x25519"

            [pgp.slots.auth]
            key = """
{TEST_RSA2048_PKCS1}
"""
            created = 1700000000
            "#
        );

        let mut applet = PgpApplet::from_toml_str(&toml).unwrap();
        let app_resp = applet.process(&keyroost_openpgp::get_application_related_data());
        let app = parse_application_related_data(app_resp.data()).unwrap();
        let (gen_sig, gen_dec, gen_aut) = generation_times(app_resp.data());

        assert!(gen_sig > 0);
        assert_ne!(app.fingerprint_sig, [0u8; 20]);
        assert!(gen_dec > 0);
        assert_ne!(app.fingerprint_dec, [0u8; 20]);
        assert_eq!(gen_aut, 1_700_000_000);
        assert_ne!(app.fingerprint_aut, [0u8; 20]);
        assert_eq!(
            applet.process(&keyroost_openpgp::get_data(TAG_UIF_DEC)).data(),
            &[0x00, 0x20]
        );
    }

    #[test]
    fn random_keygen_rsa2048_and_all_ec_names() {
        let toml = r#"
            [pgp.slots.sign]
            key = "rsa2048"

            [pgp.slots.decrypt]
            key = "p521"

            [pgp.slots.auth]
            key = "ed25519"
        "#;
        let mut applet = PgpApplet::from_toml_str(toml).unwrap();
        assert_eq!(
            applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"123456")).status(),
            Status::Success
        );
        let sig_resp = applet.process(&pso_compute_signature(&[0x30; 32]));
        assert_eq!(sig_resp.status(), Status::Success);
        assert_eq!(sig_resp.data().len(), 256);
    }

    #[test]
    fn from_toml_file_works() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("sftcrd_pgp_test_{}.toml", std::process::id()));
        std::fs::write(&path, "[pgp]\nuser_pin = \"999999\"\n").unwrap();
        let mut applet = PgpApplet::from_toml_file(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            applet.process(&keyroost_openpgp::verify(PW1_SIGN, b"999999")).status(),
            Status::Success
        );
    }

    #[test]
    fn config_error_cases() {
        // Unknown field rejected by deny_unknown_fields
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp]\nunknown_key = true\n"),
            Err(ConfigError::Figment(_))
        ));

        // Invalid PINs / RC
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp]\nuser_pin = \"12345\"\n"),
            Err(ConfigError::InvalidPin(_))
        ));
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp]\nadmin_pin = \"1234567\"\n"),
            Err(ConfigError::InvalidPin(_))
        ));
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp]\nreset_code = \"short\"\n"),
            Err(ConfigError::InvalidPin(_))
        ));

        // Invalid cardholder data
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp]\ngender = \"invalid\"\n"),
            Err(ConfigError::InvalidCardholderData(_))
        ));
        let long_name = "A".repeat(40);
        assert!(matches!(
            PgpApplet::from_toml_str(&format!("[pgp]\nname = \"{long_name}\"\n")),
            Err(ConfigError::InvalidCardholderData(_))
        ));
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp]\nlanguage = \"123456789\"\n"),
            Err(ConfigError::InvalidCardholderData(_))
        ));

        // Invalid slot name
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp.slots.bogus]\ntouch_policy = \"off\"\n"),
            Err(ConfigError::InvalidSlot(_))
        ));

        // Invalid touch policy
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp.slots.sign]\ntouch_policy = \"cached\"\n"),
            Err(ConfigError::InvalidPolicy(_))
        ));

        // Invalid fingerprint
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp.slots.sign]\nfingerprint = \"abcd\"\n"),
            Err(ConfigError::InvalidFingerprint(_))
        ));
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp.slots.sign]\nfingerprint = \"zzzz\"\n"),
            Err(ConfigError::InvalidFingerprint(_))
        ));

        // Bad PEM
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp.slots.sign]\nkey = \"not-a-key\"\n"),
            Err(ConfigError::PemError(_))
        ));

        // Slot-incompatible algorithms
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp.slots.decrypt]\nkey = \"ed25519\"\n"),
            Err(ConfigError::KeyError(_))
        ));
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp.slots.sign]\nkey = \"x25519\"\n"),
            Err(ConfigError::KeyError(_))
        ));
        assert!(matches!(
            PgpApplet::from_toml_str("[pgp.slots.auth]\nkey = \"x25519\"\n"),
            Err(ConfigError::KeyError(_))
        ));
    }
}
