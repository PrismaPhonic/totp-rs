//! Zero-allocation encoding helpers and shared TOTP logic.

use core::fmt;

/// Stack-allocated HMAC output buffer. Maximum size is 64 bytes (SHA-512).
pub(crate) struct HmacOutput {
    buf: [u8; 64],
    len: u8,
}

impl HmacOutput {
    /// Create a new `HmacOutput` from a byte slice. Panics in debug mode if data exceeds 64 bytes.
    pub(crate) fn new(data: &[u8]) -> Self {
        debug_assert!(data.len() <= 64, "HMAC output exceeds 64 bytes");
        let mut buf = [0u8; 64];
        buf[..data.len()].copy_from_slice(data);
        HmacOutput {
            buf,
            len: data.len() as u8,
        }
    }

    /// View the HMAC output as a byte slice.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encode `bytes` as base32 (RFC 4648, no padding) directly into a [`fmt::Write`].
pub(crate) fn write_base32(w: &mut impl fmt::Write, bytes: &[u8]) -> fmt::Result {
    let mut buffer: u64 = 0;
    let mut bits_left: u32 = 0;

    for &byte in bytes {
        buffer = (buffer << 8) | byte as u64;
        bits_left += 8;
        while bits_left >= 5 {
            bits_left -= 5;
            let index = ((buffer >> bits_left) & 0x1F) as usize;
            w.write_char(BASE32_ALPHABET[index] as char)?;
        }
    }

    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1F) as usize;
        w.write_char(BASE32_ALPHABET[index] as char)?;
    }

    Ok(())
}

/// Percent-encode `s` directly into a [`fmt::Write`] (RFC 3986 unreserved characters pass through).
pub(crate) fn write_url_encoded(w: &mut impl fmt::Write, s: &str) -> fmt::Result {
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                w.write_char(byte as char)?;
            }
            _ => {
                write!(w, "%{:02X}", byte)?;
            }
        }
    }
    Ok(())
}

/// Write an `otpauth://` URL into a [`fmt::Write`] with zero heap allocations.
#[cfg(feature = "otpauth")]
pub(crate) fn write_totp_url(
    w: &mut impl fmt::Write,
    algorithm: crate::Algorithm,
    digits: usize,
    step: u64,
    secret: &[u8],
    issuer: Option<&str>,
    account_name: &str,
) -> fmt::Result {
    #[allow(unused_mut)]
    let mut host = "totp";
    #[cfg(feature = "steam")]
    if algorithm == crate::Algorithm::Steam {
        host = "steam";
    }

    write!(w, "otpauth://{}/", host)?;

    if let Some(issuer) = issuer {
        write_url_encoded(w, issuer)?;
        w.write_char(':')?;
    }
    write_url_encoded(w, account_name)?;

    w.write_str("?secret=")?;
    write_base32(w, secret)?;

    if digits != 6 {
        write!(w, "&digits={}", digits)?;
    }
    if algorithm != crate::Algorithm::SHA1 {
        write!(w, "&algorithm={}", algorithm)?;
    }
    if let Some(issuer) = issuer {
        w.write_str("&issuer=")?;
        write_url_encoded(w, issuer)?;
    }
    if step != 30 {
        write!(w, "&period={}", step)?;
    }

    Ok(())
}

/// Alphabet for Steam tokens.
#[cfg(feature = "steam")]
const STEAM_CHARS: &str = "23456789BCDFGHJKMNPQRTVWXY";

/// Write a TOTP token into a [`fmt::Write`] with zero heap allocations.
pub(crate) fn totp_generate_to(
    algorithm: crate::Algorithm,
    digits: usize,
    secret: &[u8],
    step: u64,
    time: u64,
    w: &mut impl fmt::Write,
) -> fmt::Result {
    let hmac_result = algorithm.sign(secret, (time / step).to_be_bytes().as_ref());
    let result_bytes = hmac_result.as_bytes();
    let offset = (result_bytes.last().unwrap() & 15) as usize;
    #[allow(unused_mut)]
    let mut result =
        u32::from_be_bytes(result_bytes[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;

    match algorithm {
        crate::Algorithm::SHA1 | crate::Algorithm::SHA256 | crate::Algorithm::SHA512 => {
            write!(w, "{1:00$}", digits, result % 10_u32.pow(digits as u32))
        }
        #[cfg(feature = "steam")]
        crate::Algorithm::Steam => {
            for _ in 0..digits {
                let c = STEAM_CHARS.as_bytes()[result as usize % STEAM_CHARS.len()] as char;
                w.write_char(c)?;
                result /= STEAM_CHARS.len() as u32;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_empty() {
        let mut buf = String::new();
        write_base32(&mut buf, b"").unwrap();
        assert_eq!(buf, "");
    }

    #[test]
    fn base32_rfc4648_vectors() {
        // RFC 4648 test vectors (without padding)
        let cases: &[(&[u8], &str)] = &[
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ];
        for &(input, expected) in cases {
            let mut buf = String::new();
            write_base32(&mut buf, input).unwrap();
            assert_eq!(buf, expected, "base32 of {:?}", core::str::from_utf8(input));
        }
    }

    #[test]
    fn base32_totp_secret() {
        let mut buf = String::new();
        write_base32(&mut buf, b"TestSecretSuperSecret").unwrap();
        assert_eq!(buf, "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ");
    }

    #[test]
    fn url_encode_unreserved() {
        let mut buf = String::new();
        write_url_encoded(&mut buf, "hello-world_123.test~ok").unwrap();
        assert_eq!(buf, "hello-world_123.test~ok");
    }

    #[test]
    fn url_encode_special_chars() {
        let mut buf = String::new();
        write_url_encoded(&mut buf, "user@example.com").unwrap();
        assert_eq!(buf, "user%40example.com");
    }

    #[test]
    fn url_encode_space() {
        let mut buf = String::new();
        write_url_encoded(&mut buf, "hello world").unwrap();
        assert_eq!(buf, "hello%20world");
    }

    #[test]
    fn hmac_output_round_trip() {
        let data = [1u8, 2, 3, 4, 5];
        let output = HmacOutput::new(&data);
        assert_eq!(output.as_bytes(), &[1, 2, 3, 4, 5]);
    }
}
