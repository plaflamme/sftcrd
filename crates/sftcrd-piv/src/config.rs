//! Configuration parsing and loading for `sftcrd-piv`.
//!
//! Provides structures and deserializers to initialize a [`PivApplet`] from
//! configuration providers (such as TOML files loaded with [`figment`]),
//! including support for PEM-encoded keys and certificates.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use figment::Figment;
use figment::providers::{Format, Toml};
use pkcs8::der::{Decode, Encode};
use serde::Deserialize;
use sftcrd_tlv::{BerLength, EncodeError, ValueDecoder, ValueEncoder, tlv_struct};
use toml_example::TomlExample;

use crate::PivApplet;
use crate::piv::{MgmtAlg, PinPolicy, RsaBits, Slot, TouchPolicy};
use crate::slot::{KeyOrigin, SlotKey};

/// Errors that can occur when reading or applying configuration to a PIV applet.
#[derive(Debug)]
pub enum ConfigError {
    /// A figment configuration error.
    Figment(Box<figment::Error>),
    /// An unknown or invalid slot name/identifier.
    InvalidSlot(String),
    /// An invalid PIN or PUK value.
    InvalidPin(String),
    /// An invalid management key specification.
    InvalidMgmtKey(String),
    /// An invalid policy string.
    InvalidPolicy(String),
    /// An invalid key origin string.
    InvalidKeyOrigin(String),
    /// A PEM decoding error.
    PemError(String),
    /// An unsupported or invalid cryptographic key.
    KeyError(String),
    /// An invalid certificate.
    CertError(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Figment(e) => write!(f, "configuration error: {e}"),
            ConfigError::InvalidSlot(s) => write!(f, "invalid slot identifier: {s}"),
            ConfigError::InvalidPin(s) => write!(f, "invalid PIN/PUK: {s}"),
            ConfigError::InvalidMgmtKey(s) => write!(f, "invalid management key: {s}"),
            ConfigError::InvalidPolicy(s) => write!(f, "invalid policy: {s}"),
            ConfigError::InvalidKeyOrigin(s) => write!(f, "invalid key origin: {s}"),
            ConfigError::PemError(s) => write!(f, "PEM decode error: {s}"),
            ConfigError::KeyError(s) => write!(f, "key error: {s}"),
            ConfigError::CertError(s) => write!(f, "certificate error: {s}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Figment(e) => Some(e),
            _ => None,
        }
    }
}

impl From<figment::Error> for ConfigError {
    fn from(err: figment::Error) -> Self {
        ConfigError::Figment(Box::new(err))
    }
}

/// Top-level card configuration holding applet namespaces.
#[derive(TomlExample, Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct CardConfig {
    /// Card serial number.
    #[toml_example(default = 87654321, require)]
    pub serial: Option<u32>,
    /// PIV applet configuration.
    #[toml_example(nesting, require)]
    pub piv: Option<PivConfig>,
}

/// Configuration for the PIV applet.
#[derive(TomlExample, Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct PivConfig {
    /// Application PIN configuration.
    #[toml_example(nesting, require)]
    pub pin: Option<PinConfig>,
    /// PUK configuration.
    #[toml_example(nesting, require)]
    pub puk: Option<PinConfig>,
    /// Management key configuration.
    #[toml_example(nesting, require)]
    pub management_key: Option<MgmtKeyConfig>,
    #[toml_example(nesting, require)]
    pub attestation: Option<AttestationConfig>,
    /// Slot configurations mapped by slot identifier (e.g. `"9a"`, `"9c"`, `"82"`).
    #[serde(default)]
    #[toml_example(default = "9a", nesting)]
    pub slots: BTreeMap<String, SlotConfig>,
}

/// Configuration for a PIN or PUK.
#[derive(TomlExample, Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PinConfig {
    /// PIN or PUK value as a string (6-8 ASCII digits).
    #[toml_example(default = 123456, require)]
    pub value: String,
    /// Maximum number of tries.
    #[toml_example(default = 3, require)]
    pub max_tries: Option<u8>,
}

/// Configuration for the 9B management key.
#[derive(TomlExample, Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MgmtKeyConfig {
    /// Hex-encoded management key bytes.
    #[toml_example(default = "010203040506070801020304050607080102030405060708", require)]
    pub key: String,
    /// Management key algorithm: `"3des"`, `"aes128"`, `"aes192"`, or `"aes256"`.
    /// If omitted, the algorithm is inferred from the key length (24 bytes -> 3DES, 16 -> AES-128, etc.).
    #[toml_example(default = "3des", require)]
    pub algorithm: Option<String>,
}

/// Configuration for the attestation key and certificate.
/// By default a secret key and self-signed certificate will be generated on startup if none is provided here.
#[derive(TomlExample, Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AttestationConfig {
    /// PEM-encoded NISTP256 elliptic curve private key, i.e: `BEGIN EC PRIVATE KEY`.
    #[toml_example(
        default = """
-----BEGIN EC PRIVATE KEY-----
...
-----END EC PRIVATE KEY-----
""",
        require
    )]
    pub key: String,
    /// PEM-encoded X.509 certificate (`BEGIN CERTIFICATE`).
    #[toml_example(
        default = """
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
""",
        require
    )]
    pub cert: String,
}

/// Configuration for an asymmetric key slot.
#[derive(TomlExample, Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct SlotConfig {
    /// PEM-encoded private key to import (PKCS#8, PKCS#1, or SEC1; sets origin to `"imported"`),
    /// or an algorithm name to generate a random key (`"p256"`, `"p384"`, `"p521"`, `"rsa1024"`, `"rsa2048"`, `"rsa3072"`, `"rsa4096"`; sets origin to `"generated"`).
    #[toml_example(default = "p256", require)]
    pub key: Option<String>,
    /// PEM-encoded X.509 certificate (`BEGIN CERTIFICATE`).
    #[toml_example(
        default = """
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
""",
        require
    )]
    pub cert: Option<String>,
    /// Override the key's origin, either `"imported"` or `"generated"`.
    #[toml_example(default = "imported", require)]
    pub origin: Option<String>,
    /// PIN policy: `"never"`, `"once"`, or `"always"`.
    #[toml_example(default = "never", require)]
    pub pin_policy: Option<String>,
    /// Touch policy: `"never"`, `"always"`, or `"cached"`.
    #[toml_example(default = "never", require)]
    pub touch_policy: Option<String>,
}

impl FromStr for PinPolicy {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "never" => Ok(PinPolicy::Never),
            "once" => Ok(PinPolicy::Once),
            "always" => Ok(PinPolicy::Always),
            other => Err(ConfigError::InvalidPolicy(format!(
                "invalid pin policy: {other}"
            ))),
        }
    }
}

impl FromStr for Slot {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s_clean = s.trim().to_ascii_lowercase().replace(['-', '_'], "");
        match s_clean.as_str() {
            "9a" | "auth" | "authentication" => Ok(Slot::Authentication),
            "9c" | "sig" | "signature" | "digitalsignature" => Ok(Slot::Signature),
            "9d" | "keymgmt" | "keymanagement" | "management" => Ok(Slot::KeyManagement),
            "9e" | "cardauth" | "cardauthentication" => Ok(Slot::CardAuthentication),
            other => {
                // Check if hex byte in 82..=95
                if let Ok(byte) = u8::from_str_radix(other, 16)
                    && let Some(slot) = Slot::from_u8(byte)
                {
                    return Ok(slot);
                }
                // Check if retired slot index, e.g. "retired1".."retired20" or "r1".."r20"
                let num_str = other
                    .strip_prefix("retired")
                    .or_else(|| other.strip_prefix('r'));
                if let Some(num_str) = num_str
                    && let Ok(n) = num_str.parse::<u8>()
                    && let Some(slot) = Slot::retired(n)
                {
                    return Ok(slot);
                }
                Err(ConfigError::InvalidSlot(s.to_string()))
            }
        }
    }
}

/// Parse a PIN or PUK string into the 8-byte buffer.
pub(crate) fn parse_pin_value(s: &str) -> Result<[u8; 8], ConfigError> {
    let bytes = s.as_bytes();
    if bytes.len() < 6 || bytes.len() > 8 {
        return Err(ConfigError::InvalidPin(format!(
            "PIN/PUK length must be between 6 and 8 characters, got {}",
            bytes.len()
        )));
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(ConfigError::InvalidPin(
            "PIN/PUK must contain only ASCII digits".to_string(),
        ));
    }
    let mut buf = [0xFFu8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(buf)
}

/// Parse a PIN policy string.
fn parse_pin_policy(s: &str) -> Result<PinPolicy, ConfigError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "never" => Ok(PinPolicy::Never),
        "once" => Ok(PinPolicy::Once),
        "always" => Ok(PinPolicy::Always),
        other => Err(ConfigError::InvalidPolicy(format!(
            "invalid pin policy: {other}"
        ))),
    }
}

/// Parse a Touch policy string.
fn parse_touch_policy(s: &str) -> Result<TouchPolicy, ConfigError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "never" => Ok(TouchPolicy::Never),
        "always" => Ok(TouchPolicy::Always),
        "cached" => Ok(TouchPolicy::Cached),
        other => Err(ConfigError::InvalidPolicy(format!(
            "invalid touch policy: {other}"
        ))),
    }
}

/// Parse a Touch policy string.
fn parse_key_origin(s: &str) -> Result<KeyOrigin, ConfigError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "generated" => Ok(KeyOrigin::Generated),
        "imported" => Ok(KeyOrigin::Imported),
        other => Err(ConfigError::InvalidKeyOrigin(format!(
            "invalid touch policy: {other}"
        ))),
    }
}

/// Parse a slot key specification: either an algorithm name to generate a random key
/// (e.g. `"p256"`, `"rsa2048"`) or a PEM-encoded private key.
pub(crate) fn parse_or_generate_slot_key(spec: &str) -> Result<(SlotKey, KeyOrigin), ConfigError> {
    let alg = match spec.trim().to_ascii_lowercase().as_str() {
        "p256" | "eccp256" | "nistp256" => Some(crate::piv::KeyAlg::EccP256),
        "p384" | "eccp384" | "nistp384" => Some(crate::piv::KeyAlg::EccP384),
        "p521" | "eccp521" | "nistp521" => Some(crate::piv::KeyAlg::EccP521),
        "rsa1024" => Some(crate::piv::KeyAlg::Rsa(RsaBits::Rsa1024)),
        "rsa2048" => Some(crate::piv::KeyAlg::Rsa(RsaBits::Rsa2048)),
        "rsa3072" => Some(crate::piv::KeyAlg::Rsa(RsaBits::Rsa3072)),
        "rsa4096" => Some(crate::piv::KeyAlg::Rsa(RsaBits::Rsa4096)),
        _ => None,
    };

    if let Some(alg) = alg {
        let key = SlotKey::generate(alg)
            .map_err(|_| ConfigError::KeyError(format!("failed to generate {alg:?} key")))?;
        return Ok((key, KeyOrigin::Generated));
    }

    parse_pem_key(spec).map(|key| (key, KeyOrigin::Imported))
}

/// Parse a PEM-encoded private key into a `SlotKey`.
pub(crate) fn parse_pem_key(pem_str: &str) -> Result<SlotKey, ConfigError> {
    use pem_rfc7468::decode_vec;

    let (label, der) =
        decode_vec(pem_str.as_bytes()).map_err(|e| ConfigError::PemError(e.to_string()))?;

    match label {
        "PRIVATE KEY" => parse_pkcs8_der(&der),
        "RSA PRIVATE KEY" => parse_pkcs1_der(&der),
        "EC PRIVATE KEY" => parse_sec1_der(&der),
        other => Err(ConfigError::KeyError(format!(
            "unsupported PEM type '{other}', expected 'PRIVATE KEY', 'RSA PRIVATE KEY', or 'EC PRIVATE KEY'"
        ))),
    }
}

pub(crate) fn parse_attestation_key(
    pem_str: &str,
) -> Result<elliptic_curve::SecretKey<p256::NistP256>, ConfigError> {
    use pem_rfc7468::decode_vec;

    let (label, der) =
        decode_vec(pem_str.as_bytes()).map_err(|e| ConfigError::PemError(e.to_string()))?;

    match label {
        "EC PRIVATE KEY" => elliptic_curve::SecretKey::<p256::NistP256>::from_sec1_der(&der)
            .map_err(|_| {
                ConfigError::KeyError(
                    "failed to parse SEC1 EC private key as P-256, P-384, or P-521".to_string(),
                )
            }),
        other => Err(ConfigError::KeyError(format!(
            "unsupported PEM type '{other}', expected 'EC PRIVATE KEY'"
        ))),
    }
}

/// Parse a PKCS#8 DER private key.
fn parse_pkcs8_der(der: &[u8]) -> Result<SlotKey, ConfigError> {
    use pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;

    // First try RSA via pkcs8
    if let Ok(rsa_key) = rsa::PrivateKey::from_pkcs8_der(der) {
        let bits = match rsa_key.n().bits_precision() {
            1024 => RsaBits::Rsa1024,
            2048 => RsaBits::Rsa2048,
            3072 => RsaBits::Rsa3072,
            4096 => RsaBits::Rsa4096,
            bits => {
                return Err(ConfigError::KeyError(format!(
                    "unsupported RSA key size {bits} bits (supported: 1024, 2048, 3072, 4096)"
                )));
            }
        };
        return Ok(SlotKey::Rsa(bits, rsa_key));
    }

    // Try EC curves P-256, P-384, P-521
    if let Ok(sk) = elliptic_curve::SecretKey::<p256::NistP256>::from_pkcs8_der(der) {
        return Ok(SlotKey::EccP256(sk));
    }
    if let Ok(sk) = elliptic_curve::SecretKey::<p384::NistP384>::from_pkcs8_der(der) {
        return Ok(SlotKey::EccP384(sk));
    }
    if let Ok(sk) = elliptic_curve::SecretKey::<p521::NistP521>::from_pkcs8_der(der) {
        return Ok(SlotKey::EccP521(sk));
    }

    Err(ConfigError::KeyError(
        "failed to parse PKCS#8 private key as RSA, P-256, P-384, or P-521".to_string(),
    ))
}

/// Parse a PKCS#1 DER RSA private key.
fn parse_pkcs1_der(der: &[u8]) -> Result<SlotKey, ConfigError> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;

    let rsa_key = rsa::PrivateKey::from_pkcs1_der(der)
        .map_err(|e| ConfigError::KeyError(format!("invalid PKCS#1 RSA private key: {e}")))?;

    let bits = match rsa_key.n().bits_precision() {
        1024 => RsaBits::Rsa1024,
        2048 => RsaBits::Rsa2048,
        3072 => RsaBits::Rsa3072,
        4096 => RsaBits::Rsa4096,
        bits => {
            return Err(ConfigError::KeyError(format!(
                "unsupported RSA key size {bits} bits (supported: 1024, 2048, 3072, 4096)"
            )));
        }
    };
    Ok(SlotKey::Rsa(bits, rsa_key))
}

/// Parse a SEC1 DER EC private key.
fn parse_sec1_der(der: &[u8]) -> Result<SlotKey, ConfigError> {
    if let Ok(sk) = elliptic_curve::SecretKey::<p256::NistP256>::from_sec1_der(der) {
        return Ok(SlotKey::EccP256(sk));
    }
    if let Ok(sk) = elliptic_curve::SecretKey::<p384::NistP384>::from_sec1_der(der) {
        return Ok(SlotKey::EccP384(sk));
    }
    if let Ok(sk) = elliptic_curve::SecretKey::<p521::NistP521>::from_sec1_der(der) {
        return Ok(SlotKey::EccP521(sk));
    }

    Err(ConfigError::KeyError(
        "failed to parse SEC1 EC private key as P-256, P-384, or P-521".to_string(),
    ))
}

/// Parse a PEM-encoded X.509 certificate.
pub(crate) fn parse_pem_cert(pem_str: &str) -> Result<x509_cert::Certificate, ConfigError> {
    use pem_rfc7468::decode_vec;

    let (label, der) =
        decode_vec(pem_str.as_bytes()).map_err(|e| ConfigError::PemError(e.to_string()))?;

    if label != "CERTIFICATE" && label != "X509 CERTIFICATE" {
        return Err(ConfigError::CertError(format!(
            "expected PEM label 'CERTIFICATE', got '{label}'"
        )));
    }

    x509_cert::Certificate::from_der(&der)
        .map_err(|e| ConfigError::CertError(format!("cannot decode certificate: {e:?}")))
}

/// Parse a PEM-encoded X.509 certificate and encode it into a PIV certificate data object.
pub(crate) fn parse_pem_cert_object(pem_str: &str) -> Result<Vec<u8>, ConfigError> {
    let cert = parse_pem_cert(pem_str)?;

    let cert_data = CertificateData {
        cert: &cert
            .to_der()
            .map_err(|e| ConfigError::CertError(format!("cannot encode certificate: {e:?}")))?,
        cert_info: CertInfo::Uncompressed,
        lrc: &[],
    };

    cert_data
        .encode_top_level()
        .map_err(|e| ConfigError::CertError(format!("cannot encode certificate: {e:?}")))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CertInfo {
    Uncompressed = 0x00,
    Gzip = 0x01,
}

impl ValueDecoder<'_> for CertInfo {
    fn decode(bytes: &'_ [u8]) -> Result<Self, sftcrd_tlv::DecodeError> {
        let [byte] = bytes else {
            return Err(sftcrd_tlv::DecodeError::InvalidValue);
        };

        match *byte {
            0x00 => Ok(Self::Uncompressed),
            0x01 => Ok(Self::Gzip),
            _ => Err(sftcrd_tlv::DecodeError::InvalidValue),
        }
    }
}

impl ValueEncoder for CertInfo {
    fn length(&self) -> usize {
        1
    }

    fn encode(&self, buf: &mut [u8]) -> Result<(), EncodeError> {
        buf[0] = *self as u8;
        Ok(())
    }
}

tlv_struct! {

    /// A PIV certificate data object is formatted as:
    /// - Tag `0x70`: Certificate bytes (DER or gzipped DER)
    /// - Tag `0x71`: `CertInfo` byte (0x00 for uncompressed)
    /// - Tag `0xFE`: LRC byte (empty)
    #[length(BerLength)]
    struct CertificateData<'a> {
        #[tag(0x70)]
        cert: &'a [u8],
        #[tag(0x71)]
        cert_info: CertInfo,
        #[tag(0xFE)]
        lrc: &'a [u8]
    }
}

/// Parse a hex string into management key bytes and algorithm.
pub(crate) fn parse_mgmt_key(
    hex_str: &str,
    alg_str: Option<&str>,
) -> Result<(MgmtAlg, Vec<u8>), ConfigError> {
    let clean_hex = hex_str.trim().replace([' ', '-', ':'], "");
    let key_bytes = hex::decode(&clean_hex)
        .map_err(|e| ConfigError::InvalidMgmtKey(format!("invalid hex: {e}")))?;

    let alg = if let Some(alg) = alg_str {
        match alg.trim().to_ascii_lowercase().as_str() {
            "3des" | "tdes" | "tripledes" => MgmtAlg::TripleDes,
            "aes128" | "aes-128" => MgmtAlg::Aes128,
            "aes192" | "aes-192" => MgmtAlg::Aes192,
            "aes256" | "aes-256" => MgmtAlg::Aes256,
            other => {
                return Err(ConfigError::InvalidMgmtKey(format!(
                    "unsupported algorithm '{other}', expected 3des, aes128, aes192, or aes256"
                )));
            }
        }
    } else {
        match key_bytes.len() {
            16 => MgmtAlg::Aes128,
            24 => MgmtAlg::TripleDes,
            32 => MgmtAlg::Aes256,
            len => {
                return Err(ConfigError::InvalidMgmtKey(format!(
                    "cannot infer algorithm from key length {len} bytes"
                )));
            }
        }
    };

    if key_bytes.len() != alg.key_len() {
        return Err(ConfigError::InvalidMgmtKey(format!(
            "key length mismatch for {:?}: expected {} bytes, got {}",
            alg,
            alg.key_len(),
            key_bytes.len()
        )));
    }

    Ok((alg, key_bytes))
}

impl PivApplet {
    /// Create a [`PivApplet`] initialized from a [`Figment`] configuration provider.
    ///
    /// The provider can contain either a top-level `[piv]` table (as in `CardConfig`)
    /// or a direct `PivConfig`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if configuration parsing, key decoding, or certificate encoding fails.
    pub fn from_figment(figment: &Figment) -> Result<Self, ConfigError> {
        // Try extracting [piv] first (scoped under piv)
        let piv_config: PivConfig = if figment.find_value("piv").is_ok() {
            figment.extract_inner("piv")?
        } else {
            // Otherwise extract at root as PivConfig
            figment.extract()?
        };

        let root_serial: Option<u32> = figment.extract_inner("serial").ok();
        let serial = root_serial.unwrap_or(crate::DEFAULT_SERIAL);

        Self::from_config(&piv_config, serial)
    }

    /// Convenience method to create a [`PivApplet`] by reading a TOML file.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the file cannot be read, decoded, or contains invalid configuration.
    pub fn from_toml_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let figment = Figment::new().merge(Toml::file(path));
        Self::from_figment(&figment)
    }

    /// Convenience method to create a [`PivApplet`] by reading a TOML string.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the string cannot be parsed as TOML or contains invalid configuration.
    pub fn from_toml_str(toml_str: &str) -> Result<Self, ConfigError> {
        let figment = Figment::new().merge(Toml::string(toml_str));
        Self::from_figment(&figment)
    }

    /// Construct a [`PivApplet`] from a [`PivConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if PIN/PUK, management key, slot keys, or certificates fail validation.
    pub fn from_config(config: &PivConfig, serial: u32) -> Result<Self, ConfigError> {
        let mut applet = PivApplet::with_serial(serial);

        // Configure PIN
        if let Some(pin_cfg) = &config.pin {
            let pin_val = parse_pin_value(&pin_cfg.value)?;
            let max_tries = pin_cfg.max_tries.unwrap_or(crate::pin::DEFAULT_PIN_TRIES);
            applet.pin = crate::pin::Pin::new(pin_val, max_tries);
        }

        // Configure PUK
        if let Some(puk_cfg) = &config.puk {
            let puk_val = parse_pin_value(&puk_cfg.value)?;
            let max_tries = puk_cfg.max_tries.unwrap_or(crate::pin::DEFAULT_PUK_TRIES);
            applet.puk = crate::pin::Pin::new(puk_val, max_tries);
        }

        // Configure Management Key
        if let Some(mgmt_cfg) = &config.management_key {
            let (alg, key_bytes) = parse_mgmt_key(&mgmt_cfg.key, mgmt_cfg.algorithm.as_deref())?;
            applet.mgmt.set_key(alg, &key_bytes).map_err(|_| {
                ConfigError::InvalidMgmtKey(
                    "failed to initialize management key cipher".to_string(),
                )
            })?;
        }

        // Configure attestation
        if let Some(attest_cfg) = &config.attestation {
            let key = parse_attestation_key(&attest_cfg.key)?;
            let cert = parse_pem_cert(&attest_cfg.cert)?;
            applet.attestation.secret_key = key;
            applet.attestation.cert = Some(cert);
        }

        // Configure Slots
        for (slot_id, slot_cfg) in &config.slots {
            let slot = Slot::from_str(slot_id)?;
            let slot_ref = &mut applet.slots[slot];

            if let Some(pin_policy) = &slot_cfg.pin_policy {
                slot_ref.pin_policy = parse_pin_policy(pin_policy)?;
            }
            if let Some(touch_policy) = &slot_cfg.touch_policy {
                slot_ref.touch_policy = parse_touch_policy(touch_policy)?;
            }
            if let Some(key_spec) = &slot_cfg.key {
                let (slot_key, default_origin) = parse_or_generate_slot_key(key_spec)?;
                slot_ref.key = Some(slot_key);
                slot_ref.origin = default_origin;
            }
            if let Some(origin) = &slot_cfg.origin {
                slot_ref.origin = parse_key_origin(origin)?;
            }
            if let Some(cert_pem) = &slot_cfg.cert {
                let cert_bytes = parse_pem_cert_object(cert_pem)?;
                slot_ref.cert = Some(cert_bytes);
            }
        }

        Ok(applet)
    }
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;

    const TEST_P256_PKCS8: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgYMU8CVjfJeB+70ru
/NHmQO6CQSZFQmisQ79g//CB/4WhRANCAATHXXM5uR7Wo+zCW1bycqXoqy/9wRVQ
v75NJ4SWaIbfBJB1wobcA3M3qcIhRgtE3dxX3MX9yxFBcF7JQ6X/bLfI
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

    const TEST_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIBfDCCASOgAwIBAgIUMXKZt0dmUfE2X2xvwgS2jme2SlcwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJVGVzdCBQMjU2MB4XDTI2MTExNjIzMjA1NFoXDTI3MTExNjIz
MjA1NFowFDESMBAGA1UEAwwJVGVzdCBQMjU2MFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEx11zObke1qPswltW8nKl6Ksv/cEVUL++TSeElmiG3wSQdcKG3ANzN6nC
IUYLRN3cV9zF/csRQXBeyUOl/2y3yKNTMFEwHQYDVR0OBBYEFAKTdKwoRczwK2CM
eWdSjePzTwTgMB8GA1UdIwQYMBaAFAKTdKwoRczwK2CMeWdSjePzTwTgMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgbr2Vrt04qfVTfniWYaVIZHUT
4sbPin4eBgn48tqnhKECIFmGGFkIJuy8rTq3zdj06vaFQtgf1aNqpWLeWxCxU4hy
-----END CERTIFICATE-----";

    #[test]
    fn parse_slot_names() {
        assert_eq!(Slot::from_str("9a").unwrap(), Slot::Authentication);
        assert_eq!(Slot::from_str("9A").unwrap(), Slot::Authentication);
        assert_eq!(
            Slot::from_str("authentication").unwrap(),
            Slot::Authentication
        );
        assert_eq!(Slot::from_str("9c").unwrap(), Slot::Signature);
        assert_eq!(Slot::from_str("9C").unwrap(), Slot::Signature);
        assert_eq!(Slot::from_str("signature").unwrap(), Slot::Signature);
        assert_eq!(Slot::from_str("9d").unwrap(), Slot::KeyManagement);
        assert_eq!(Slot::from_str("9e").unwrap(), Slot::CardAuthentication);
        assert_eq!(Slot::from_str("82").unwrap(), Slot::retired(1).unwrap());
        assert_eq!(Slot::from_str("95").unwrap(), Slot::retired(20).unwrap());
        assert_eq!(
            Slot::from_str("retired1").unwrap(),
            Slot::retired(1).unwrap()
        );
        assert_eq!(
            Slot::from_str("retired_20").unwrap(),
            Slot::retired(20).unwrap()
        );
        assert_eq!(Slot::from_str("r5").unwrap(), Slot::retired(5).unwrap());
    }

    #[test]
    fn parse_p256_pkcs8_key() {
        let key = parse_pem_key(TEST_P256_PKCS8).expect("valid p256 key");
        assert_eq!(key.alg(), crate::piv::KeyAlg::EccP256);
    }

    #[test]
    fn parse_p384_sec1_key() {
        let key = parse_pem_key(TEST_P384_SEC1).expect("valid p384 key");
        assert_eq!(key.alg(), crate::piv::KeyAlg::EccP384);
    }

    #[test]
    fn parse_rsa2048_pkcs1_key() {
        let key = parse_pem_key(TEST_RSA2048_PKCS1).expect("valid rsa key");
        assert_eq!(key.alg(), crate::piv::KeyAlg::Rsa(RsaBits::Rsa2048));
    }

    #[test]
    fn parse_cert_object() {
        let obj = parse_pem_cert_object(TEST_CERT).expect("valid cert");
        assert!(CertificateData::decode(&obj).is_ok());
    }

    #[test]
    fn load_piv_applet_from_toml() {
        let toml = format!(
            r#"
serial = 98765432

[piv]
pin = {{ value = "654321", max_tries = 4 }}
puk = {{ value = "87654321", max_tries = 5 }}

[piv.management_key]
key = "01020304050607080102030405060708"
algorithm = "aes128"

[piv.slots.9a]
pin_policy = "once"
touch_policy = "never"
key = """
{TEST_P256_PKCS8}
"""
cert = """
{TEST_CERT}
"""

[piv.slots.9c]
pin_policy = "always"
touch_policy = "never"
key = """
{TEST_RSA2048_PKCS1}
"""
"#
        );

        let applet = PivApplet::from_toml_str(&toml).expect("applet loads from toml");
        assert_eq!(applet.serial, 98_765_432);
        assert_eq!(applet.pin.tries(), 4);
        assert_eq!(applet.pin.max_tries(), 4);
        assert_eq!(applet.puk.tries(), 5);
        assert_eq!(applet.puk.max_tries(), 5);

        // Check slot 9A
        let slot_9a = &applet.slots[Slot::Authentication];
        assert_eq!(slot_9a.origin, KeyOrigin::Imported);
        assert_eq!(slot_9a.pin_policy, PinPolicy::Once);
        assert_eq!(slot_9a.touch_policy, TouchPolicy::Never);
        assert_eq!(
            slot_9a.key.as_ref().unwrap().alg(),
            crate::piv::KeyAlg::EccP256
        );
        assert!(slot_9a.cert.is_some());

        // Check slot 9C
        let slot_9c = &applet.slots[Slot::Signature];
        assert_eq!(slot_9c.origin, KeyOrigin::Imported);
        assert_eq!(slot_9c.pin_policy, PinPolicy::Always);
        assert_eq!(slot_9c.touch_policy, TouchPolicy::Never);
        assert_eq!(
            slot_9c.key.as_ref().unwrap().alg(),
            crate::piv::KeyAlg::Rsa(RsaBits::Rsa2048)
        );
    }

    #[test]
    fn apdu_operations_on_configured_applet() {
        let toml = format!(
            r#"
[piv]
pin = {{ value = "654321" }}

[piv.slots.9a]
pin_policy = "once"
key = """
{TEST_P256_PKCS8}
"""
cert = """
{TEST_CERT}
"""
"#
        );

        let mut applet = PivApplet::from_toml_str(&toml).expect("applet loads");

        // Verify PIN
        let r = applet.process(&keyroost_piv::verify_pin(b"654321").unwrap());
        assert_eq!(r.status(), iso7816::Status::Success);

        // Read back certificate with GET DATA
        let r = applet.process(&keyroost_piv::get_data(&[0x5F, 0xC1, 0x05]));
        assert_eq!(r.status(), iso7816::Status::Success);
        let inner = keyroost_piv::unwrap_data_object(r.data()).expect("unwrap data object");
        let (cert_der, is_gzip) = keyroost_piv::cert_object_parts(inner).expect("cert parts");
        assert!(!is_gzip);
        assert_eq!(cert_der[0], 0x30); // DER Sequence

        // Sign with slot 9A
        let digest = [0x42u8; 32];
        let r = applet.process(&keyroost_piv::general_auth_sign(
            keyroost_piv::KeyAlg::EccP256.id(),
            0x9A,
            &digest,
        ));
        assert_eq!(r.status(), iso7816::Status::Success);
    }

    #[test]
    fn generate_slot_keys_from_toml() {
        let toml = r#"
[piv.slots.9a]
key = "p256"

[piv.slots.9c]
key = "P384"

[piv.slots.9d]
key = "rsa1024"
"#;

        let applet = PivApplet::from_toml_str(toml).expect("applet loads from toml");

        let slot_9a = &applet.slots[Slot::Authentication];
        assert_eq!(slot_9a.origin, KeyOrigin::Generated);
        assert_eq!(
            slot_9a.key.as_ref().unwrap().alg(),
            crate::piv::KeyAlg::EccP256
        );

        let slot_9c = &applet.slots[Slot::Signature];
        assert_eq!(slot_9c.origin, KeyOrigin::Generated);
        assert_eq!(
            slot_9c.key.as_ref().unwrap().alg(),
            crate::piv::KeyAlg::EccP384
        );

        let slot_9d = &applet.slots[Slot::KeyManagement];
        assert_eq!(slot_9d.origin, KeyOrigin::Generated);
        assert_eq!(
            slot_9d.key.as_ref().unwrap().alg(),
            crate::piv::KeyAlg::Rsa(RsaBits::Rsa1024)
        );
    }
}
