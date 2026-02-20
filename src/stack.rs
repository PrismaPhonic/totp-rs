//! Stack-allocated parallel types for zero-allocation TOTP operations.
//!
//! This module provides [`Totp`], [`Rfc6238`], and [`Secret`] types that use
//! fixed-capacity [`ArrayVec`] and [`ArrayString`] instead of [`Vec`] and [`String`],
//! eliminating all heap allocations for construction, token generation, and URL output.
//!
//! # Capacity limits
//!
//! | Field | Type | Max capacity |
//! |-------|------|-------------|
//! | Secret (raw) | `ArrayVec<u8, 24>` | 24 bytes |
//! | Secret (encoded) | `ArrayString<40>` | 40 chars |
//! | Issuer | `ArrayString<64>` | 64 bytes |
//! | Account name | `ArrayString<128>` | 128 bytes |

use arrayvec::{ArrayString, ArrayVec};
use constant_time_eq::constant_time_eq;
use core::fmt;
use std::time::SystemTimeError;

use crate::encoding;
use crate::{Algorithm, Rfc6238Error, SecretParseError, TotpUrlError};

#[inline(always)]
#[cfg(feature = "qr")]
fn estimated_png_capacity(raw_len: usize) -> usize {
    // Conservative estimate tuned from bounded ASCII otpauth payloads.
    // Keeps capacity slack controlled while avoiding reallocs for common cases.
    raw_len / 48 + 512
}

#[cfg(feature = "qr")]
fn draw_png_with_capacity(text: &str) -> Result<Vec<u8>, String> {
    use qrcodegen_image::image::ImageEncoder as _;

    let qr = qrcodegen_image::qrcodegen::QrCode::encode_text(
        text,
        qrcodegen_image::qrcodegen::QrCodeEcc::Medium,
    )
    .map_err(|err| err.to_string())?;

    // Keep the same scaling/quiet-zone behavior as qrcodegen-image::draw_png.
    let image_size = (qr.size() as u32) * 8 + 8 * 8;
    let canvas = qrcodegen_image::draw_canvas(qr);
    let raw = canvas.into_raw();

    let mut png = Vec::with_capacity(estimated_png_capacity(raw.len()));
    let encoder = qrcodegen_image::image::codecs::png::PngEncoder::new(&mut png);
    encoder
        .write_image(
            &raw,
            image_size,
            image_size,
            qrcodegen_image::image::ExtendedColorType::L8,
        )
        .map_err(|err| err.to_string())?;

    Ok(png)
}

#[cfg(feature = "qr")]
fn draw_base64_with_capacity(text: &str) -> Result<String, String> {
    use base64::{engine::general_purpose, Engine as _};
    draw_png_with_capacity(text).map(|png| general_purpose::STANDARD.encode(png))
}

/// Maximum byte length for a raw secret.
pub const SECRET_CAPACITY: usize = 24;
/// Maximum character length for a base32-encoded secret.
pub const SECRET_ENCODED_CAPACITY: usize = 40;
/// Maximum byte length for an issuer string.
pub const ISSUER_CAPACITY: usize = 64;
/// Maximum byte length for an account name string.
pub const ACCOUNT_NAME_CAPACITY: usize = 128;

/// Stack-allocated raw secret bytes. Alias for the `ArrayVec` used in
/// [`Secret::Raw`], [`Totp::secret`], and [`Rfc6238`] constructors.
pub type SecretBytes = ArrayVec<u8, SECRET_CAPACITY>;
/// Stack-allocated base32-encoded secret. Alias for the `ArrayString` used
/// in [`Secret::Encoded`].
pub type SecretEncoded = ArrayString<SECRET_ENCODED_CAPACITY>;
/// Stack-allocated issuer string.
pub type Issuer = ArrayString<ISSUER_CAPACITY>;
/// Stack-allocated account name string.
pub type AccountName = ArrayString<ACCOUNT_NAME_CAPACITY>;

/// Stack-allocated shared secret. Equivalent to [`crate::Secret`] but backed
/// by [`ArrayVec`] / [`ArrayString`] instead of [`Vec`] / [`String`].
#[derive(Debug, Clone, Eq)]
pub enum Secret {
    /// Non-encoded "raw" secret.
    Raw(SecretBytes),
    /// Base32 encoded secret.
    Encoded(SecretEncoded),
}

impl PartialEq for Secret {
    /// Compares secrets by their decoded byte representation using constant-time equality.
    fn eq(&self, other: &Self) -> bool {
        match (self.to_bytes(), other.to_bytes()) {
            (Ok(a), Ok(b)) => constant_time_eq(&a, &b),
            _ => false,
        }
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Secret::Raw(bytes) => {
                for b in bytes {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            Secret::Encoded(s) => write!(f, "{}", s),
        }
    }
}

impl Secret {
    /// Get the inner value as raw bytes.
    ///
    /// For `Encoded`, this decodes the base32 string (using a transient heap
    /// allocation from the `base32` crate) and copies into an [`ArrayVec`].
    pub fn to_bytes(&self) -> Result<SecretBytes, SecretParseError> {
        match self {
            Secret::Raw(s) => Ok(s.clone()),
            Secret::Encoded(s) => {
                let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
                    .ok_or(SecretParseError::ParseBase32)?;
                if decoded.len() > SECRET_CAPACITY {
                    return Err(SecretParseError::Capacity(decoded.len()));
                }
                let mut arr = ArrayVec::new();
                arr.try_extend_from_slice(&decoded)
                    .map_err(|_| SecretParseError::Capacity(decoded.len()))?;
                Ok(arr)
            }
        }
    }

    /// Try to transform an `Encoded` secret into a `Raw` secret.
    pub fn to_raw(&self) -> Result<Self, SecretParseError> {
        match self {
            Secret::Raw(_) => Ok(self.clone()),
            Secret::Encoded(s) => {
                let decoded = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
                    .ok_or(SecretParseError::ParseBase32)?;
                if decoded.len() > SECRET_CAPACITY {
                    return Err(SecretParseError::Capacity(decoded.len()));
                }
                let mut arr = ArrayVec::new();
                arr.try_extend_from_slice(&decoded)
                    .map_err(|_| SecretParseError::Capacity(decoded.len()))?;
                Ok(Secret::Raw(arr))
            }
        }
    }

    /// Transform a `Raw` secret into an `Encoded` secret (base32, no padding).
    pub fn to_encoded(&self) -> Self {
        match self {
            Secret::Raw(s) => {
                let mut buf = ArrayString::new();
                encoding::write_base32(&mut buf, s).expect("base32 of secret fits in ArrayString");
                Secret::Encoded(buf)
            }
            Secret::Encoded(_) => self.clone(),
        }
    }

    /// Generate a CSPRNG secret of [`SECRET_CAPACITY`] bytes.
    #[cfg(feature = "gen_secret")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gen_secret")))]
    pub fn generate_secret() -> Secret {
        use rand::Rng;
        let mut rng = rand::rng();
        let mut secret_bytes = [0u8; SECRET_CAPACITY];
        rng.fill(&mut secret_bytes[..]);
        let mut arr = ArrayVec::new();
        arr.try_extend_from_slice(&secret_bytes)
            .expect("secret_bytes len == SECRET_CAPACITY");
        Secret::Raw(arr)
    }
}

#[cfg(feature = "gen_secret")]
#[cfg_attr(docsrs, doc(cfg(feature = "gen_secret")))]
impl Default for Secret {
    fn default() -> Self {
        Secret::generate_secret()
    }
}

/// Stack-allocated TOTP. Equivalent to [`crate::TOTP`] but backed by
/// [`ArrayVec`] / [`ArrayString`] instead of [`Vec`] / [`String`].
#[derive(Debug, Clone)]
pub struct Totp {
    pub algorithm: Algorithm,
    pub digits: usize,
    pub skew: u8,
    pub step: u64,
    pub secret: SecretBytes,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub issuer: Option<Issuer>,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub account_name: AccountName,
}

impl PartialEq for Totp {
    /// Compares algorithm, digits, skew, step, and secret (constant-time).
    /// Does not compare issuer or account_name.
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm
            && self.digits == other.digits
            && self.skew == other.skew
            && self.step == other.step
            && constant_time_eq(&self.secret, &other.secret)
    }
}

#[cfg(feature = "otpauth")]
impl fmt::Display for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "digits: {}; step: {}; alg: {}; issuer: <{}>({})",
            self.digits,
            self.step,
            self.algorithm,
            self.issuer.as_deref().unwrap_or("None"),
            self.account_name,
        )
    }
}

#[cfg(not(feature = "otpauth"))]
impl fmt::Display for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "digits: {}; step: {}; alg: {}",
            self.digits, self.step, self.algorithm,
        )
    }
}

impl Totp {
    #[cfg(feature = "otpauth")]
    /// Create a new stack-allocated TOTP with validation.
    ///
    /// Accepts borrowed data (`&[u8]`, `&str`) and copies into internal
    /// fixed-capacity storage. Returns an error if any capacity is exceeded,
    /// if digits are out of range, if the secret is too short, or if issuer /
    /// account_name contain `:`.
    pub fn new(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: &[u8],
        issuer: Option<&str>,
        account_name: &str,
    ) -> Result<Self, TotpUrlError> {
        crate::rfc::assert_digits(&digits)?;
        crate::rfc::assert_secret_length(secret)?;
        if secret.len() > SECRET_CAPACITY {
            return Err(TotpUrlError::SecretTooLong(secret.len()));
        }
        if let Some(issuer) = issuer {
            if issuer.contains(':') {
                return Err(TotpUrlError::Issuer(issuer.to_string()));
            }
            if issuer.len() > ISSUER_CAPACITY {
                return Err(TotpUrlError::IssuerTooLong(issuer.len()));
            }
        }
        if account_name.contains(':') {
            return Err(TotpUrlError::AccountName(account_name.to_string()));
        }
        if account_name.len() > ACCOUNT_NAME_CAPACITY {
            return Err(TotpUrlError::AccountNameTooLong(account_name.len()));
        }
        Ok(Self::new_unchecked(
            algorithm,
            digits,
            skew,
            step,
            secret,
            issuer,
            account_name,
        ))
    }

    #[cfg(feature = "otpauth")]
    /// Create a new stack-allocated TOTP **without** validation.
    ///
    /// # Panics
    ///
    /// Panics if any field exceeds its fixed capacity.
    pub fn new_unchecked(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: &[u8],
        issuer: Option<&str>,
        account_name: &str,
    ) -> Self {
        let mut secret_arr = ArrayVec::new();
        secret_arr
            .try_extend_from_slice(secret)
            .expect("secret fits in ArrayVec");
        Totp {
            algorithm,
            digits,
            skew,
            step,
            secret: secret_arr,
            issuer: issuer.map(|s| ArrayString::from(s).expect("issuer fits in ArrayString")),
            account_name: ArrayString::from(account_name)
                .expect("account_name fits in ArrayString"),
        }
    }

    #[cfg(not(feature = "otpauth"))]
    /// Create a new stack-allocated TOTP with validation.
    pub fn new(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: &[u8],
    ) -> Result<Self, TotpUrlError> {
        crate::rfc::assert_digits(&digits)?;
        crate::rfc::assert_secret_length(secret)?;
        if secret.len() > SECRET_CAPACITY {
            return Err(TotpUrlError::SecretTooLong(secret.len()));
        }
        Ok(Self::new_unchecked(algorithm, digits, skew, step, secret))
    }

    #[cfg(not(feature = "otpauth"))]
    /// Create a new stack-allocated TOTP **without** validation.
    ///
    /// # Panics
    ///
    /// Panics if secret exceeds capacity.
    pub fn new_unchecked(
        algorithm: Algorithm,
        digits: usize,
        skew: u8,
        step: u64,
        secret: &[u8],
    ) -> Self {
        let mut secret_arr = ArrayVec::new();
        secret_arr
            .try_extend_from_slice(secret)
            .expect("secret fits in ArrayVec");
        Totp {
            algorithm,
            digits,
            skew,
            step,
            secret: secret_arr,
        }
    }

    /// Create from the given [`Rfc6238`] configuration.
    pub fn from_rfc6238(rfc: Rfc6238) -> Result<Totp, TotpUrlError> {
        Totp::try_from(rfc)
    }
}

impl Totp {
    /// Generate a token for the given timestamp, writing it directly into `w`.
    /// This method performs **zero** heap allocations.
    pub fn generate_to(&self, time: u64, w: &mut impl fmt::Write) -> fmt::Result {
        encoding::totp_generate_to(
            self.algorithm,
            self.digits,
            &self.secret,
            self.step,
            time,
            w,
        )
    }

    /// Generate a token for the current system time, writing it directly into `w`.
    /// This method is allocation free.
    pub fn generate_current_to(&self, w: &mut impl fmt::Write) -> Result<(), SystemTimeError> {
        let t = crate::system_time()?;
        self.generate_to(t, w)
            .expect("fmt::Write should not fail for correctly sized buffer");
        Ok(())
    }

    /// Check if `token` is valid for the given timestamp, accounting for
    /// [`skew`](Totp::skew). Performs zero heap allocations.
    pub fn check(&self, token: &str, time: u64) -> bool {
        let basestep = time / self.step - (self.skew as u64);
        for i in 0..(self.skew as u16) * 2 + 1 {
            let step_time = (basestep + (i as u64)) * self.step;
            let mut buf = ArrayString::<16>::new();
            self.generate_to(step_time, &mut buf)
                .expect("token fits in ArrayString<16>");
            if constant_time_eq(buf.as_bytes(), token.as_bytes()) {
                return true;
            }
        }
        false
    }

    /// Check if `token` is valid for the current system time.
    pub fn check_current(&self, token: &str) -> Result<bool, SystemTimeError> {
        let t = crate::system_time()?;
        Ok(self.check(token, t))
    }

    /// Timestamp of the first second of the next step.
    pub fn next_step(&self, time: u64) -> u64 {
        let step = time / self.step;
        (step + 1) * self.step
    }

    /// Timestamp of the first second of the next step (current system time).
    pub fn next_step_current(&self) -> Result<u64, SystemTimeError> {
        let t = crate::system_time()?;
        Ok(self.next_step(t))
    }

    /// TTL (in seconds) of the current token.
    pub fn ttl(&self) -> Result<u64, SystemTimeError> {
        let t = crate::system_time()?;
        Ok(self.step - (t % self.step))
    }

    /// Write the base32-encoded secret into `w`. Zero allocations.
    pub fn write_secret_base32(&self, w: &mut impl fmt::Write) -> fmt::Result {
        encoding::write_base32(w, &self.secret)
    }
}

#[cfg(feature = "otpauth")]
#[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
impl Totp {
    /// Write a standard `otpauth://` URL into `w`. Zero allocations.
    pub fn write_url(&self, w: &mut impl fmt::Write) -> fmt::Result {
        encoding::write_totp_url(
            w,
            self.algorithm,
            self.digits,
            self.step,
            &self.secret,
            self.issuer.as_deref(),
            &self.account_name,
        )
    }

    /// Parse a standard `otpauth://` URL into a stack-allocated `Totp`.
    ///
    /// This parser is fully self-contained and performs zero heap
    /// allocations on the happy path. It manually parses the URL scheme,
    /// host, path and query parameters, percent-decodes path components
    /// into [`ArrayString`] buffers, and base32-decodes the secret directly
    /// into a [`SecretBytes`].
    ///
    /// Error paths may allocate when constructing [`TotpUrlError`] variants
    /// that carry a `String` payload (these are exceptional and non-critical).
    pub fn from_url(url: &str) -> Result<Self, TotpUrlError> {
        // 1. Scheme
        let rest = url.strip_prefix("otpauth://").ok_or_else(|| {
            let scheme = url.split_once("://").map_or(url, |p| p.0);
            TotpUrlError::Scheme(scheme.to_string())
        })?;

        // 2. Host — determines default algorithm
        let mut algorithm = Algorithm::SHA1;

        #[cfg(feature = "steam")]
        let rest = if let Some(r) = rest.strip_prefix("totp/") {
            r
        } else if let Some(r) = rest.strip_prefix("steam/") {
            algorithm = Algorithm::Steam;
            r
        } else {
            let host = rest.split('/').next().unwrap_or(rest);
            return Err(TotpUrlError::Host(host.to_string()));
        };

        #[cfg(not(feature = "steam"))]
        let rest = if let Some(r) = rest.strip_prefix("totp/") {
            r
        } else {
            let host = rest.split('/').next().unwrap_or(rest);
            return Err(TotpUrlError::Host(host.to_string()));
        };

        // 3. Separate path from query string
        let (path, query) = match rest.find('?') {
            Some(i) => (&rest[..i], &rest[i + 1..]),
            None => (rest, ""),
        };

        // 4. Percent-decode path, split optional issuer:account
        const PATH_CAP: usize = ISSUER_CAPACITY + 1 + ACCOUNT_NAME_CAPACITY;
        let mut path_buf = ArrayString::<PATH_CAP>::new();
        percent_decode_to(path, &mut path_buf)
            .map_err(|_| TotpUrlError::AccountNameDecoding(path.to_string()))?;

        let mut issuer: Option<Issuer> = None;
        let account_name: AccountName;

        if let Some((iss_str, acct_str)) = path_buf.split_once(':') {
            issuer = Some(
                Issuer::try_from(iss_str)
                    .map_err(|_| TotpUrlError::IssuerTooLong(iss_str.len()))?,
            );
            account_name = AccountName::try_from(acct_str)
                .map_err(|_| TotpUrlError::AccountNameTooLong(acct_str.len()))?;
        } else {
            account_name = AccountName::try_from(path_buf.as_str())
                .map_err(|_| TotpUrlError::AccountNameTooLong(path_buf.len()))?;
        }

        // 5. Parse query parameters
        let mut digits = 6usize;
        let mut step = 30u64;
        let mut secret = SecretBytes::new();

        for pair in query.split('&').filter(|s| !s.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            match key {
                #[cfg(feature = "steam")]
                "algorithm" if algorithm == Algorithm::Steam => {
                    // Do not override algorithm for Steam URLs.
                }
                "algorithm" => {
                    algorithm = match value {
                        "SHA1" => Algorithm::SHA1,
                        "SHA256" => Algorithm::SHA256,
                        "SHA512" => Algorithm::SHA512,
                        _ => return Err(TotpUrlError::Algorithm(value.to_string())),
                    };
                }
                "digits" => {
                    digits = value
                        .parse()
                        .map_err(|_| TotpUrlError::Digits(value.to_string()))?;
                }
                "period" => {
                    step = value
                        .parse()
                        .map_err(|_| TotpUrlError::Step(value.to_string()))?;
                }
                "secret" => {
                    if !base32_decode_to(value, &mut secret) {
                        return Err(TotpUrlError::Secret(value.to_string()));
                    }
                }
                #[cfg(feature = "steam")]
                "issuer" if value.eq_ignore_ascii_case("steam") => {
                    algorithm = Algorithm::Steam;
                    digits = 5;
                    issuer = Some(Issuer::try_from("Steam").unwrap());
                }
                "issuer" => {
                    // Percent-decode the issuer query value.
                    let mut param_issuer = Issuer::new();
                    percent_decode_to(value, &mut param_issuer)
                        .map_err(|_| TotpUrlError::IssuerDecoding(value.to_string()))?;

                    if let Some(ref path_issuer) = issuer {
                        if path_issuer.as_str() != param_issuer.as_str() {
                            return Err(TotpUrlError::IssuerMistmatch(
                                path_issuer.to_string(),
                                param_issuer.to_string(),
                            ));
                        }
                    }
                    issuer = Some(param_issuer);

                    #[cfg(feature = "steam")]
                    if param_issuer.as_str() == "Steam" {
                        algorithm = Algorithm::Steam;
                    }
                }
                _ => {}
            }
        }

        #[cfg(feature = "steam")]
        if algorithm == Algorithm::Steam {
            digits = 5;
            step = 30;
            issuer = Some(Issuer::try_from("Steam").unwrap());
        }

        if secret.is_empty() {
            return Err(TotpUrlError::Secret(String::new()));
        }

        // 6. Construct — skipping redundant validation since we parsed directly
        crate::rfc::assert_digits(&digits)?;
        crate::rfc::assert_secret_length(&secret)?;
        if secret.len() > SECRET_CAPACITY {
            return Err(TotpUrlError::SecretTooLong(secret.len()));
        }

        Ok(Totp {
            algorithm,
            digits,
            skew: 1,
            step,
            secret,
            issuer,
            account_name,
        })
    }
}

#[cfg(feature = "qr")]
#[cfg_attr(docsrs, doc(cfg(feature = "qr")))]
impl Totp {
    /// Return a QR code as a base64-encoded PNG string.
    ///
    /// Generates the `otpauth://` URL into a heap-allocated `String`
    /// (unavoidable for the QR encoder), then encodes through a pre-sized
    /// PNG buffer to reduce realloc churn in allocation-sensitive paths.
    pub fn get_qr_base64(&self) -> Result<String, String> {
        let mut url = String::new();
        self.write_url(&mut url)
            .expect("writing to String cannot fail");
        draw_base64_with_capacity(&url)
    }

    /// Return a QR code as PNG bytes.
    ///
    /// Same as [`get_qr_base64`](Self::get_qr_base64) but returns raw PNG data.
    pub fn get_qr_png(&self) -> Result<Vec<u8>, String> {
        let mut url = String::new();
        self.write_url(&mut url)
            .expect("writing to String cannot fail");
        draw_png_with_capacity(&url)
    }
}

/// Convert a hex ASCII digit to its 4-bit numeric value.
#[cfg(feature = "otpauth")]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `input` into a [`fmt::Write`] sink (e.g. `ArrayString`).
///
/// Handles multi-byte UTF-8 sequences that span multiple `%XX` triplets.
/// Returns `Err(())` on malformed percent-encoding or invalid UTF-8.
#[cfg(feature = "otpauth")]
fn percent_decode_to(input: &str, w: &mut impl fmt::Write) -> Result<(), ()> {
    let bytes = input.as_bytes();
    let mut i = 0;
    let mut utf8_buf = [0u8; 4];
    let mut utf8_len: usize = 0;
    let mut utf8_expected: usize = 0;

    while i < bytes.len() {
        let byte = if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = hex_val(bytes[i + 1]).ok_or(())?;
            let lo = hex_val(bytes[i + 2]).ok_or(())?;
            i += 3;
            (hi << 4) | lo
        } else {
            let b = bytes[i];
            i += 1;
            b
        };

        if utf8_len > 0 {
            // We are in a multi-byte UTF-8 sequence — expect continuation byte.
            if byte & 0xC0 != 0x80 {
                return Err(());
            }
            utf8_buf[utf8_len] = byte;
            utf8_len += 1;
            if utf8_len == utf8_expected {
                let s = core::str::from_utf8(&utf8_buf[..utf8_len]).map_err(|_| ())?;
                w.write_str(s).map_err(|_| ())?;
                utf8_len = 0;
            }
        } else if byte < 0x80 {
            // Plain ASCII byte.
            w.write_char(byte as char).map_err(|_| ())?;
        } else if byte & 0xE0 == 0xC0 {
            utf8_buf[0] = byte;
            utf8_len = 1;
            utf8_expected = 2;
        } else if byte & 0xF0 == 0xE0 {
            utf8_buf[0] = byte;
            utf8_len = 1;
            utf8_expected = 3;
        } else if byte & 0xF8 == 0xF0 {
            utf8_buf[0] = byte;
            utf8_len = 1;
            utf8_expected = 4;
        } else {
            return Err(());
        }
    }

    if utf8_len > 0 {
        // Truncated multi-byte sequence at end of input.
        return Err(());
    }
    Ok(())
}

/// Decode RFC 4648 base32 (no padding, case-insensitive) directly into a
/// [`SecretBytes`] buffer. Returns `false` on invalid characters or overflow.
#[cfg(feature = "otpauth")]
fn base32_decode_to(input: &str, out: &mut SecretBytes) -> bool {
    let input = input.trim_end_matches('=');
    let bytes = input.as_bytes();
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;

    for &b in bytes {
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return false,
        };

        buf = (buf << 5) | val as u64;
        bits += 5;

        if bits >= 8 {
            bits -= 8;
            if out.try_push((buf >> bits) as u8).is_err() {
                return false;
            }
        }
    }

    true
}

/// Stack-allocated [RFC 6238](https://tools.ietf.org/html/rfc6238) configuration.
#[derive(Debug, Clone)]
pub struct Rfc6238 {
    algorithm: Algorithm,
    digits: usize,
    skew: u8,
    step: u64,
    secret: SecretBytes,
    #[cfg(feature = "otpauth")]
    issuer: Option<Issuer>,
    #[cfg(feature = "otpauth")]
    account_name: AccountName,
}

impl Rfc6238 {
    #[cfg(feature = "otpauth")]
    /// Create a validated RFC 6238 configuration, taking ownership of the secret.
    pub fn new(
        digits: usize,
        secret: SecretBytes,
        issuer: Option<&str>,
        account_name: &str,
    ) -> Result<Self, Rfc6238Error> {
        crate::rfc::assert_digits(&digits)?;
        crate::rfc::assert_secret_length(&secret)?;
        Ok(Rfc6238 {
            algorithm: Algorithm::SHA1,
            digits,
            skew: 1,
            step: 30,
            secret,
            issuer: issuer.map(|s| Issuer::from(s).expect("issuer fits in ArrayString")),
            account_name: AccountName::from(account_name)
                .expect("account_name fits in ArrayString"),
        })
    }

    #[cfg(not(feature = "otpauth"))]
    /// Create a validated RFC 6238 configuration, taking ownership of the secret.
    pub fn new(digits: usize, secret: SecretBytes) -> Result<Self, Rfc6238Error> {
        crate::rfc::assert_digits(&digits)?;
        crate::rfc::assert_secret_length(&secret)?;
        Ok(Rfc6238 {
            algorithm: Algorithm::SHA1,
            digits,
            skew: 1,
            step: 30,
            secret,
        })
    }

    #[cfg(feature = "otpauth")]
    /// Create with default values: 6 digits, no issuer, empty account name.
    pub fn with_defaults(secret: SecretBytes) -> Result<Self, Rfc6238Error> {
        Rfc6238::new(6, secret, Some(""), "")
    }

    #[cfg(not(feature = "otpauth"))]
    /// Create with default values: 6 digits.
    pub fn with_defaults(secret: SecretBytes) -> Result<Self, Rfc6238Error> {
        Rfc6238::new(6, secret)
    }

    /// Set the number of digits (must be 6-8).
    pub fn digits(&mut self, value: usize) -> Result<(), Rfc6238Error> {
        crate::rfc::assert_digits(&value)?;
        self.digits = value;
        Ok(())
    }

    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// Set the issuer. Panics if `value` exceeds [`ISSUER_CAPACITY`].
    pub fn issuer(&mut self, value: &str) {
        self.issuer = Some(ArrayString::from(value).expect("issuer fits in ArrayString"));
    }

    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    /// Set the account name. Panics if `value` exceeds [`ACCOUNT_NAME_CAPACITY`].
    pub fn account_name(&mut self, value: &str) {
        self.account_name = ArrayString::from(value).expect("account_name fits in ArrayString");
    }
}

#[cfg(feature = "otpauth")]
impl TryFrom<Rfc6238> for Totp {
    type Error = TotpUrlError;

    /// Moves all fields directly from the [`Rfc6238`] into the [`Totp`].
    /// No re-validation or copying is performed since [`Rfc6238::new`]
    /// already validated the inputs.
    fn try_from(rfc: Rfc6238) -> Result<Self, Self::Error> {
        Ok(Totp {
            algorithm: rfc.algorithm,
            digits: rfc.digits,
            skew: rfc.skew,
            step: rfc.step,
            secret: rfc.secret,
            issuer: rfc.issuer,
            account_name: rfc.account_name,
        })
    }
}

#[cfg(not(feature = "otpauth"))]
impl TryFrom<Rfc6238> for Totp {
    type Error = TotpUrlError;

    fn try_from(rfc: Rfc6238) -> Result<Self, Self::Error> {
        Ok(Totp {
            algorithm: rfc.algorithm,
            digits: rfc.digits,
            skew: rfc.skew,
            step: rfc.step,
            secret: rfc.secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_BYTES: &[u8] = b"TestSecretSuperSecret";
    const SECRET_BASE32: &str = "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ";

    #[test]
    fn secret_raw_to_bytes() {
        let mut arr = ArrayVec::new();
        arr.try_extend_from_slice(SECRET_BYTES).unwrap();
        let secret = Secret::Raw(arr);
        assert_eq!(secret.to_bytes().unwrap().as_slice(), SECRET_BYTES);
    }

    #[test]
    fn secret_encoded_to_bytes() {
        let secret = Secret::Encoded(ArrayString::from(SECRET_BASE32).unwrap());
        assert_eq!(secret.to_bytes().unwrap().as_slice(), SECRET_BYTES);
    }

    #[test]
    fn secret_raw_to_encoded() {
        let mut arr = ArrayVec::new();
        arr.try_extend_from_slice(SECRET_BYTES).unwrap();
        let raw = Secret::Raw(arr);
        let encoded = raw.to_encoded();
        match &encoded {
            Secret::Encoded(s) => assert_eq!(s.as_str(), SECRET_BASE32),
            _ => panic!("expected Encoded"),
        }
    }

    #[test]
    fn secret_encoded_to_raw() {
        let encoded = Secret::Encoded(ArrayString::from(SECRET_BASE32).unwrap());
        let raw = encoded.to_raw().unwrap();
        match &raw {
            Secret::Raw(v) => assert_eq!(v.as_slice(), SECRET_BYTES),
            _ => panic!("expected Raw"),
        }
    }

    #[test]
    fn secret_equality() {
        let mut arr = ArrayVec::new();
        arr.try_extend_from_slice(SECRET_BYTES).unwrap();
        let raw = Secret::Raw(arr);
        let encoded = Secret::Encoded(ArrayString::from(SECRET_BASE32).unwrap());
        assert_eq!(raw, encoded);
    }

    #[test]
    fn secret_display() {
        let encoded = Secret::Encoded(ArrayString::from(SECRET_BASE32).unwrap());
        assert_eq!(encoded.to_string(), SECRET_BASE32);
    }

    #[cfg(feature = "gen_secret")]
    #[test]
    fn secret_generate() {
        let sec = Secret::generate_secret();
        assert!(matches!(sec, Secret::Raw(_)));
        assert_eq!(sec.to_bytes().unwrap().len(), SECRET_CAPACITY);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn generate_token() {
        let totp = Totp::new(Algorithm::SHA1, 6, 1, 1, SECRET_BYTES).unwrap();
        let mut buf = ArrayString::<8>::new();
        totp.generate_to(1000, &mut buf).unwrap();
        assert_eq!(buf.as_str(), "659761");
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn generate_token_sha256() {
        let totp = Totp::new(Algorithm::SHA256, 6, 1, 1, SECRET_BYTES).unwrap();
        let mut buf = ArrayString::<8>::new();
        totp.generate_to(1000, &mut buf).unwrap();
        assert_eq!(buf.as_str(), "076417");
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn generate_token_sha512() {
        let totp = Totp::new(Algorithm::SHA512, 6, 1, 1, SECRET_BYTES).unwrap();
        let mut buf = ArrayString::<8>::new();
        totp.generate_to(1000, &mut buf).unwrap();
        assert_eq!(buf.as_str(), "473536");
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn check_token() {
        let totp = Totp::new(Algorithm::SHA1, 6, 0, 1, SECRET_BYTES).unwrap();
        assert!(totp.check("659761", 1000));
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn check_token_with_skew() {
        let totp = Totp::new(Algorithm::SHA1, 6, 1, 1, SECRET_BYTES).unwrap();
        assert!(totp.check("174269", 1000));
        assert!(totp.check("659761", 1000));
        assert!(totp.check("260393", 1000));
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn check_token_current() {
        let totp = Totp::new(Algorithm::SHA1, 6, 0, 1, SECRET_BYTES).unwrap();
        let t = crate::system_time().unwrap();
        let mut buf = ArrayString::<8>::new();
        totp.generate_to(t, &mut buf).unwrap();
        assert!(totp.check_current(buf.as_str()).unwrap());
        assert!(!totp.check_current("bogus").unwrap());
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn base32_output() {
        let totp = Totp::new(Algorithm::SHA1, 6, 1, 1, SECRET_BYTES).unwrap();
        let mut buf = ArrayString::<64>::new();
        totp.write_secret_base32(&mut buf).unwrap();
        assert_eq!(buf.as_str(), SECRET_BASE32);
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn next_step_values() {
        let totp = Totp::new(Algorithm::SHA1, 6, 1, 30, SECRET_BYTES).unwrap();
        assert_eq!(totp.next_step(0), 30);
        assert_eq!(totp.next_step(29), 30);
        assert_eq!(totp.next_step(30), 60);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_sha1_no_issuer() {
        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            SECRET_BYTES,
            None,
            "constantoine@github.com",
        )
        .unwrap();
        let mut buf = ArrayString::<256>::new();
        totp.write_url(&mut buf).unwrap();
        assert_eq!(
            buf.as_str(),
            "otpauth://totp/constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ"
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_sha1_with_issuer() {
        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            SECRET_BYTES,
            Some("Github"),
            "constantoine@github.com",
        )
        .unwrap();
        let mut buf = ArrayString::<256>::new();
        totp.write_url(&mut buf).unwrap();
        assert_eq!(
            buf.as_str(),
            "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&issuer=Github"
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn url_sha256() {
        let totp = Totp::new(
            Algorithm::SHA256,
            6,
            1,
            30,
            SECRET_BYTES,
            Some("Github"),
            "constantoine@github.com",
        )
        .unwrap();
        let mut buf = ArrayString::<256>::new();
        totp.write_url(&mut buf).unwrap();
        assert_eq!(
            buf.as_str(),
            "otpauth://totp/Github:constantoine%40github.com?secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&algorithm=SHA256&issuer=Github"
        );
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn from_url_roundtrip() {
        let url = "otpauth://totp/Github:constantoine%40github.com?issuer=Github&secret=KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ&digits=6&algorithm=SHA1";
        let totp = Totp::from_url(url).unwrap();
        assert_eq!(totp.algorithm, Algorithm::SHA1);
        assert_eq!(totp.digits, 6);
        assert_eq!(totp.skew, 1);
        assert_eq!(totp.step, 30);
        assert_eq!(totp.secret.as_slice(), SECRET_BYTES);
        assert_eq!(totp.issuer.as_deref(), Some("Github"));
        assert_eq!(totp.account_name.as_str(), "constantoine@github.com");
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr() {
        use qrcodegen_image::qrcodegen;
        use sha2::{Digest, Sha512};

        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            SECRET_BYTES,
            Some("Github"),
            "constantoine@github.com",
        )
        .unwrap();
        let mut url = ArrayString::<512>::new();
        totp.write_url(&mut url).unwrap();
        let qr = qrcodegen::QrCode::encode_text(url.as_str(), qrcodegen::QrCodeEcc::Medium)
            .expect("could not generate qr");
        let data = qrcodegen_image::draw_canvas(qr).into_raw();

        // Create hash from image
        let hash_digest = Sha512::digest(data);
        assert_eq!(
            format!("{:x}", hash_digest).as_str(),
            "fbb0804f1e4f4c689d22292c52b95f0783b01b4319973c0c50dd28af23dbbbe663dce4eb05a7959086d9092341cb9f103ec5a9af4a973867944e34c063145328"
        );
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr_base64_ok() {
        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            SECRET_BYTES,
            Some("Github"),
            "constantoine@github.com",
        )
        .unwrap();
        let qr = totp.get_qr_base64();
        assert!(qr.is_ok());
    }

    #[test]
    #[cfg(feature = "qr")]
    fn generates_qr_png_ok() {
        let totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            SECRET_BYTES,
            Some("Github"),
            "constantoine@github.com",
        )
        .unwrap();
        let qr = totp.get_qr_png();
        assert!(qr.is_ok());
    }

    #[test]
    #[cfg(feature = "qr")]
    fn draw_png_with_capacity_gap_reasonable_for_ascii_cases() {
        let cases = [
            ("short", "Auth", "a@b.co"),
            ("typical", "Github", "constantoine@github.com"),
            (
                "long_ascii",
                "ExampleCorpAPAC",
                "averylongbutrealisticaddressstyleidentifier@example.com",
            ),
            (
                "near_max_ascii",
                "IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com",
            ),
        ];

        for (label, issuer, account_name) in cases {
            let totp = Totp::new(
                Algorithm::SHA1,
                6,
                1,
                1,
                SECRET_BYTES,
                Some(issuer),
                account_name,
            )
            .unwrap();

            let mut url = ArrayString::<512>::new();
            totp.write_url(&mut url).unwrap();

            let qr = qrcodegen_image::qrcodegen::QrCode::encode_text(
                url.as_str(),
                qrcodegen_image::qrcodegen::QrCodeEcc::Medium,
            )
            .expect("could not generate qr");
            let raw_len = qrcodegen_image::draw_canvas(qr).into_raw().len();
            let expected_initial_capacity = estimated_png_capacity(raw_len);

            let png = draw_png_with_capacity(url.as_str()).expect("could not draw png");
            let len = png.len();
            let cap = png.capacity();
            let gap = cap - len;
            let grew = cap > expected_initial_capacity;

            assert!(
                !grew,
                "draw_png_with_capacity reallocated for {label}: url_len={}, len={}, cap={}, initial={}",
                url.len(),
                len,
                cap,
                expected_initial_capacity
            );

            assert!(
                gap <= 1024,
                "draw_png_with_capacity oversized for {label}: url_len={}, len={}, cap={}, gap={}",
                url.len(),
                len,
                cap,
                gap
            );
        }
    }
    #[test]
    #[cfg(feature = "qr")]
    fn stack_and_heap_qr_outputs_match() {
        use crate::TOTP;

        let heap_totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            SECRET_BYTES.to_vec(),
            Some("Github".to_string()),
            "constantoine@github.com".to_string(),
        )
        .unwrap();

        let stack_totp = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            SECRET_BYTES,
            Some("Github"),
            "constantoine@github.com",
        )
        .unwrap();

        let heap_png = heap_totp.get_qr_png().unwrap();
        let stack_png = stack_totp.get_qr_png().unwrap();
        assert_eq!(stack_png, heap_png);

        let heap_base64 = heap_totp.get_qr_base64().unwrap();
        let stack_base64 = stack_totp.get_qr_base64().unwrap();
        assert_eq!(stack_base64, heap_base64);
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn wrong_issuer_rejected() {
        let result = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            SECRET_BYTES,
            Some("Github:"),
            "test",
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TotpUrlError::Issuer(_)));
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn wrong_account_name_rejected() {
        let result = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            1,
            SECRET_BYTES,
            Some("Github"),
            "test:bad",
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), TotpUrlError::AccountName(_)));
    }

    fn secret_arrayvec() -> SecretBytes {
        let mut arr = ArrayVec::new();
        arr.try_extend_from_slice(SECRET_BYTES).unwrap();
        arr
    }

    #[test]
    #[cfg(feature = "otpauth")]
    fn rfc6238_to_totp() {
        let rfc = Rfc6238::with_defaults(secret_arrayvec()).unwrap();
        let totp = Totp::from_rfc6238(rfc);
        assert!(totp.is_ok());
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn rfc6238_to_totp_no_otpauth() {
        let rfc = Rfc6238::with_defaults(secret_arrayvec()).unwrap();
        let totp = Totp::from_rfc6238(rfc);
        assert!(totp.is_ok());
    }

    #[test]
    fn secret_too_long() {
        let long_secret = [0u8; 25];
        let result = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            &long_secret,
            #[cfg(feature = "otpauth")]
            None,
            #[cfg(feature = "otpauth")]
            "",
        );
        assert!(result.is_err());
    }

    #[test]
    fn secret_too_short() {
        let short_secret = [0u8; 10];
        let result = Totp::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            &short_secret,
            #[cfg(feature = "otpauth")]
            None,
            #[cfg(feature = "otpauth")]
            "",
        );
        assert!(result.is_err());
    }

    /// Prop-test: verify that the stack URL parser produces the same round-trip
    /// URL as the heap URL parser for randomly generated TOTP configurations.
    #[cfg(feature = "otpauth")]
    mod prop {
        use proptest::prelude::*;

        use super::Totp;
        use crate::{Algorithm, TOTP};

        fn email_strategy() -> impl Strategy<Value = String> {
            // Local part: 1-64 chars from the valid set.  Domain: simple
            // ASCII label + TLD to keep things realistic.
            (
                "[A-Za-z0-9_+.-]{1,64}",
                "[A-Za-z0-9]{1,30}",
                "[A-Za-z]{2,6}",
            )
                .prop_map(|(local, domain, tld)| format!("{}@{}.{}", local, domain, tld))
        }

        /// Issuer: ASCII printable, no `:`, 1-60 chars (fits in ISSUER_CAPACITY).
        fn issuer_strategy() -> impl Strategy<Value = String> {
            "[A-Za-z0-9 _.!@#$%^&*()-]{1,60}"
        }

        /// Secret: 16-24 random bytes (valid range for both heap and stack types).
        fn secret_strategy() -> impl Strategy<Value = Vec<u8>> {
            proptest::collection::vec(any::<u8>(), 16..=24)
        }

        fn algorithm_strategy() -> impl Strategy<Value = Algorithm> {
            prop_oneof![
                Just(Algorithm::SHA1),
                Just(Algorithm::SHA256),
                Just(Algorithm::SHA512),
            ]
        }

        proptest! {
            #[test]
            fn stack_from_url_matches_heap(
                account_name in email_strategy(),
                issuer in issuer_strategy(),
                secret in secret_strategy(),
                algorithm in algorithm_strategy(),
                digits in (6u8..=8u8),
            ) {
                // 1. Build a heap TOTP (the known-good reference).
                let heap_totp = TOTP::new(
                    algorithm,
                    digits as usize,
                    1,
                    30,
                    secret,
                    Some(issuer),
                    account_name,
                ).unwrap();

                // 2. Generate the canonical URL from the heap type.
                let url = heap_totp.get_url();

                // 3. Parse with both parsers.
                let heap_parsed = TOTP::from_url(&url)
                    .expect("heap from_url should succeed on its own output");
                let stack_parsed = Totp::from_url(&url)
                    .expect("stack from_url should succeed on heap-generated URL");

                // 4. Re-generate URLs and compare.
                let heap_url = heap_parsed.get_url();
                let mut stack_url = arrayvec::ArrayString::<512>::new();
                stack_parsed.write_url(&mut stack_url).unwrap();

                prop_assert_eq!(
                    heap_url.as_str(),
                    stack_url.as_str(),
                    "Round-tripped URLs must be identical.\n  Original: {}\n  Heap:     {}\n  Stack:    {}",
                    url, heap_url, stack_url,
                );
            }
        }
    }
}
