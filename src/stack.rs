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

/// Maximum byte length for a raw secret.
pub const SECRET_CAPACITY: usize = 24;
/// Maximum character length for a base32-encoded secret.
pub const SECRET_ENCODED_CAPACITY: usize = 40;
/// Maximum byte length for an issuer string.
pub const ISSUER_CAPACITY: usize = 64;
/// Maximum byte length for an account name string.
pub const ACCOUNT_NAME_CAPACITY: usize = 128;

/// Stack-allocated shared secret. Equivalent to [`crate::Secret`] but backed
/// by [`ArrayVec`] / [`ArrayString`] instead of [`Vec`] / [`String`].
#[derive(Debug, Clone, Eq)]
pub enum Secret {
    /// Non-encoded "raw" secret.
    Raw(ArrayVec<u8, SECRET_CAPACITY>),
    /// Base32 encoded secret.
    Encoded(ArrayString<SECRET_ENCODED_CAPACITY>),
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
    pub fn to_bytes(&self) -> Result<ArrayVec<u8, SECRET_CAPACITY>, SecretParseError> {
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
    pub secret: ArrayVec<u8, SECRET_CAPACITY>,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub issuer: Option<ArrayString<ISSUER_CAPACITY>>,
    #[cfg(feature = "otpauth")]
    #[cfg_attr(docsrs, doc(cfg(feature = "otpauth")))]
    pub account_name: ArrayString<ACCOUNT_NAME_CAPACITY>,
}

impl PartialEq for Totp {
    /// Compares algorithm, digits, skew, step, and secret (constant-time).
    /// Does **not** compare issuer or account_name.
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

    /// Check if `token` is valid for the given timestamp, accounting for
    /// [`skew`](Totp::skew). Performs **zero** heap allocations.
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
    /// Internally uses the existing URL parser (which performs transient heap
    /// allocations) and copies the results into fixed-capacity storage.
    pub fn from_url(url: &str) -> Result<Self, TotpUrlError> {
        let (algorithm, digits, skew, step, secret, issuer, account_name) =
            crate::TOTP::parts_from_url(url)?;
        Totp::new(
            algorithm,
            digits,
            skew,
            step,
            &secret,
            issuer.as_deref(),
            &account_name,
        )
    }
}

// ---------------------------------------------------------------------------
// Rfc6238
// ---------------------------------------------------------------------------

/// Stack-allocated [RFC 6238](https://tools.ietf.org/html/rfc6238) configuration.
#[derive(Debug, Clone)]
pub struct Rfc6238 {
    algorithm: Algorithm,
    digits: usize,
    skew: u8,
    step: u64,
    secret: ArrayVec<u8, SECRET_CAPACITY>,
    #[cfg(feature = "otpauth")]
    issuer: Option<ArrayString<ISSUER_CAPACITY>>,
    #[cfg(feature = "otpauth")]
    account_name: ArrayString<ACCOUNT_NAME_CAPACITY>,
}

impl Rfc6238 {
    #[cfg(feature = "otpauth")]
    /// Create a validated RFC 6238 configuration from borrowed data.
    pub fn new(
        digits: usize,
        secret: &[u8],
        issuer: Option<&str>,
        account_name: &str,
    ) -> Result<Self, Rfc6238Error> {
        crate::rfc::assert_digits(&digits)?;
        crate::rfc::assert_secret_length(secret)?;
        if secret.len() > SECRET_CAPACITY {
            return Err(Rfc6238Error::SecretTooLong(secret.len()));
        }
        let mut secret_arr = ArrayVec::new();
        secret_arr
            .try_extend_from_slice(secret)
            .map_err(|_| Rfc6238Error::SecretTooLong(secret.len()))?;
        Ok(Rfc6238 {
            algorithm: Algorithm::SHA1,
            digits,
            skew: 1,
            step: 30,
            secret: secret_arr,
            issuer: issuer.map(|s| ArrayString::from(s).expect("issuer fits in ArrayString")),
            account_name: ArrayString::from(account_name)
                .expect("account_name fits in ArrayString"),
        })
    }

    #[cfg(not(feature = "otpauth"))]
    /// Create a validated RFC 6238 configuration from borrowed data.
    pub fn new(digits: usize, secret: &[u8]) -> Result<Self, Rfc6238Error> {
        crate::rfc::assert_digits(&digits)?;
        crate::rfc::assert_secret_length(secret)?;
        if secret.len() > SECRET_CAPACITY {
            return Err(Rfc6238Error::SecretTooLong(secret.len()));
        }
        let mut secret_arr = ArrayVec::new();
        secret_arr
            .try_extend_from_slice(secret)
            .map_err(|_| Rfc6238Error::SecretTooLong(secret.len()))?;
        Ok(Rfc6238 {
            algorithm: Algorithm::SHA1,
            digits,
            skew: 1,
            step: 30,
            secret: secret_arr,
        })
    }

    #[cfg(feature = "otpauth")]
    /// Create with default values: 6 digits, no issuer, empty account name.
    pub fn with_defaults(secret: &[u8]) -> Result<Self, Rfc6238Error> {
        Rfc6238::new(6, secret, Some(""), "")
    }

    #[cfg(not(feature = "otpauth"))]
    /// Create with default values: 6 digits.
    pub fn with_defaults(secret: &[u8]) -> Result<Self, Rfc6238Error> {
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

    fn try_from(rfc: Rfc6238) -> Result<Self, Self::Error> {
        Totp::new(
            rfc.algorithm,
            rfc.digits,
            rfc.skew,
            rfc.step,
            &rfc.secret,
            rfc.issuer.as_deref(),
            &rfc.account_name,
        )
    }
}

#[cfg(not(feature = "otpauth"))]
impl TryFrom<Rfc6238> for Totp {
    type Error = TotpUrlError;

    fn try_from(rfc: Rfc6238) -> Result<Self, Self::Error> {
        Totp::new(rfc.algorithm, rfc.digits, rfc.skew, rfc.step, &rfc.secret)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_BYTES: &[u8] = b"TestSecretSuperSecret";
    const SECRET_BASE32: &str = "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ";

    // -- Secret tests -------------------------------------------------------

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

    // -- Totp tests (no otpauth) --------------------------------------------

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

    // -- Totp tests (otpauth) -----------------------------------------------

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

    // -- Rfc6238 tests ------------------------------------------------------

    #[test]
    #[cfg(feature = "otpauth")]
    fn rfc6238_to_totp() {
        let rfc = Rfc6238::with_defaults(SECRET_BYTES).unwrap();
        let totp = Totp::from_rfc6238(rfc);
        assert!(totp.is_ok());
    }

    #[test]
    #[cfg(not(feature = "otpauth"))]
    fn rfc6238_to_totp_no_otpauth() {
        let rfc = Rfc6238::with_defaults(SECRET_BYTES).unwrap();
        let totp = Totp::from_rfc6238(rfc);
        assert!(totp.is_ok());
    }

    // -- Capacity error tests -----------------------------------------------

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
}
