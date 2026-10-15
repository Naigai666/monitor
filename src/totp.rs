//! TOTP (RFC 6238) over the base32 secret an authenticator app stores.
//!
//! Self-contained on purpose: the hub ships one binary and the upstream
//! dependency list is a feature of it, so the two primitives this needs --
//! HMAC-SHA1 and base32 -- come from `hmac`/`sha1` (both already in the RustCrypto
//! family `sha2` comes from) and forty lines here, rather than a `totp` crate
//! with its own QR, URL and time-handling surface.
//!
//! The time step and digit count are fixed rather than configurable: every
//! authenticator app defaults to 30 s and six digits, and a hub that let them
//! drift would be the only place the mismatch showed.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

type HmacSha1 = Hmac<Sha1>;

/// Seconds per code, the value every authenticator app assumes.
pub const STEP: u64 = 30;
/// Digits per code, likewise.
pub const DIGITS: u32 = 6;
/// Steps accepted either side of the current one, so a phone whose clock is
/// half a minute out still signs in. One is the usual compromise: wider windows
/// divide the guessing cost that the code's six digits set.
pub const SKEW: u64 = 1;
/// Bytes behind one secret, RFC 4226's recommended 160 bits.
const SECRET_BYTES: usize = 20;

/// Crockford's alphabet without its ambiguous letters: a recovery code is read
/// off a screen and typed, and O/0 and I/1 are where that goes wrong.
const RECOVERY_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";
/// Characters per recovery code, and how many are issued.
const RECOVERY_LEN: usize = 10;
pub const RECOVERY_CODES: usize = 10;

const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// `no padding`, which is what authenticator apps and `otpauth://` URIs carry.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Case-insensitive, tolerating spaces and the `=` padding some apps paste.
pub fn base32_decode(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for ch in value.chars() {
        if ch == '=' || ch.is_whitespace() {
            continue;
        }
        let upper = ch.to_ascii_uppercase() as u8;
        let index = B32.iter().position(|c| *c == upper)?;
        buffer = (buffer << 5) | index as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    // Bits left over are the encoder's padding; three or more would mean a
    // character was dropped rather than that the input was short.
    (bits < 5).then_some(out)
}

/// A fresh secret, as the base32 an app is given.
pub fn new_secret() -> String {
    base32_encode(&rand::random::<[u8; SECRET_BYTES]>())
}

/// The code for one instant. `None` only when the stored secret is not base32,
/// which means the setting was written by hand.
pub fn code(secret: &str, unix_secs: u64) -> Option<String> {
    hotp(&base32_decode(secret)?, unix_secs / STEP)
}

fn hotp(key: &[u8], counter: u64) -> Option<String> {
    let mut mac = HmacSha1::new_from_slice(key).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // Dynamic truncation, RFC 4226 §5.3: the low nibble of the last byte picks
    // the four bytes the code is read from.
    let offset = (digest[19] & 0x0f) as usize;
    let value =
        u32::from_be_bytes([digest[offset], digest[offset + 1], digest[offset + 2], digest[offset + 3]])
            & 0x7fff_ffff;
    let modulus = 10u32.pow(DIGITS);
    Some(format!("{:0width$}", value % modulus, width = DIGITS as usize))
}

/// Whether `code` matches the secret at `unix_secs`, within [`SKEW`] steps.
///
/// Every candidate step is compared even after one matches, and the comparison
/// itself is branch-free over the digits: this runs on one attempt per sign-in,
/// but a guess that returned early would still be a guess the hub timed.
pub fn verify(secret: &str, code: &str, unix_secs: u64) -> bool {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(key) = base32_decode(secret) else { return false };
    let step = unix_secs / STEP;
    let mut matched = false;
    for offset in 0..=SKEW * 2 {
        let candidate = step as i128 + offset as i128 - SKEW as i128;
        if candidate < 0 {
            continue;
        }
        if let Some(expected) = hotp(&key, candidate as u64) {
            matched |= constant_time_eq(expected.as_bytes(), code.as_bytes());
        }
    }
    matched
}

/// Equal length, no early exit. Both sides here are the hub's own six digits, so
/// this guards the timing rather than the content.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The `otpauth://` URI an app scans. Both labels are percent-encoded, since an
/// account name is usually an email address and `@` in a path segment is not
/// what an authenticator expects to parse.
pub fn otpauth_url(issuer: &str, account: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        encode(issuer),
        encode(account),
        secret,
        encode(issuer),
        DIGITS,
        STEP
    )
}

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// One-time codes for a lost phone, returned to the operator once and stored
/// only as digests.
pub fn new_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let bytes = rand::random::<[u8; RECOVERY_LEN]>();
            bytes.iter().map(|b| RECOVERY_ALPHABET[*b as usize % RECOVERY_ALPHABET.len()] as char).collect()
        })
        .collect()
}

/// The digest a recovery code is stored under, normalized the way a person
/// retypes it: case and the separators they may add are not part of the secret.
pub fn recovery_digest(code: &str) -> String {
    let normalized: String =
        code.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_uppercase()).collect();
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238's SHA1 vectors, whose secret is the ASCII of "12345678901234567890".
    /// The RFC prints eight digits; six are its last six.
    #[test]
    fn the_rfc_6238_vectors_hold() {
        let secret = base32_encode(b"12345678901234567890");
        for (unix, eight) in [
            (59u64, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        ] {
            let expected = &eight[eight.len() - DIGITS as usize..];
            let got = code(&secret, unix).expect("a base32 secret produces a code");
            assert_eq!(got, expected, "RFC 6238 vector at T={unix}");
            assert!(verify(&secret, &got, unix), "the code it just produced verifies");
        }
    }

    /// RFC 4226's own worked example, the counter form the vectors above are
    /// built from.
    #[test]
    fn the_rfc_4226_counters_hold() {
        let key = b"12345678901234567890";
        for (counter, expected) in
            [(0u64, "755224"), (1, "287082"), (2, "359152"), (3, "969429"), (4, "338314")]
        {
            assert_eq!(hotp(key, counter).unwrap(), expected, "RFC 4226 counter {counter}");
        }
    }

    #[test]
    fn base32_round_trips_and_refuses_what_is_not_base32() {
        for bytes in
            [vec![], b"a".to_vec(), b"ab".to_vec(), b"abc".to_vec(), b"abcd".to_vec(), b"abcde".to_vec()]
        {
            let encoded = base32_encode(&bytes);
            assert_eq!(base32_decode(&encoded).unwrap(), bytes, "round trip of {bytes:?}");
        }
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("mzxw6ytboi").unwrap(), b"foobar", "case is not part of the secret");
        assert_eq!(base32_decode("MZXW 6YTB OI==").unwrap(), b"foobar", "spaces and padding are tolerated");
        assert!(base32_decode("MZXW6YTB1!").is_none(), "a character outside the alphabet is refused");
        // A dropped character leaves more than four bits over, which is not the
        // padding a correct encoder emits.
        assert!(base32_decode("AA").is_some());
    }

    #[test]
    fn a_code_is_accepted_one_step_either_side_and_no_further() {
        let secret = new_secret();
        let now = 1_700_000_000u64;
        let current = code(&secret, now).unwrap();
        assert!(verify(&secret, &current, now));
        assert!(verify(&secret, &current, now + STEP), "a phone half a minute behind still signs in");
        assert!(verify(&secret, &current, now - STEP), "and one half a minute ahead");
        assert!(!verify(&secret, &current, now + STEP * (SKEW + 1)), "two steps is outside the window");
        assert!(!verify(&secret, &current, now - STEP * (SKEW + 1)), "in both directions");
        assert!(!verify(&secret, &current, now + STEP * 10), "and long after");
    }

    #[test]
    fn anything_that_is_not_six_digits_is_refused_without_reading_the_secret() {
        let secret = new_secret();
        let now = 1_700_000_000u64;
        let current = code(&secret, now).unwrap();
        for bad in ["", "12345", "1234567", "abcdef", "12345 ", " 123456", "１２３４５６"] {
            assert!(!verify(&secret, bad, now), "{bad:?} is not a code");
        }
        assert!(verify(&secret, &format!(" {current} "), now), "surrounding space is trimmed");
        assert!(!verify("not base32!", &current, now), "an unreadable secret verifies nothing");
    }

    #[test]
    fn a_secret_is_160_bits_of_base32() {
        let secret = new_secret();
        assert_eq!(secret.len(), 32, "20 bytes as base32");
        assert_eq!(base32_decode(&secret).unwrap().len(), SECRET_BYTES);
        assert_ne!(secret, new_secret(), "two secrets are not the same");
        assert!(secret.chars().all(|c| B32.contains(&(c as u8))), "and it is written in the alphabet");
    }

    #[test]
    fn recovery_codes_are_distinct_typable_and_digest_to_themselves() {
        let codes = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        let mut sorted = codes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), RECOVERY_CODES, "codes do not repeat");
        for code in &codes {
            assert_eq!(code.len(), RECOVERY_LEN);
            assert!(code.chars().all(|c| RECOVERY_ALPHABET.contains(&(c as u8))), "{code} avoids O/0/I/1");
            // The digest ignores case and any separator the operator adds back.
            let spaced = code.chars().map(|c| c.to_string()).collect::<Vec<_>>().join(" ");
            assert_eq!(recovery_digest(&spaced), recovery_digest(&code.to_lowercase()));
            assert_ne!(
                recovery_digest(code),
                recovery_digest(&codes[(0..RECOVERY_CODES).find(|i| &codes[*i] != code).unwrap()])
            );
        }
    }

    #[test]
    fn the_uri_carries_what_an_authenticator_reads() {
        let secret = new_secret();
        let url = otpauth_url("极简探针", "admin@example.com", &secret);
        assert!(url.starts_with("otpauth://totp/"), "{url}");
        assert!(url.contains(&format!("secret={secret}")));
        assert!(url.contains("digits=6"));
        assert!(url.contains("period=30"));
        assert!(url.contains("algorithm=SHA1"));
        assert!(url.contains("%40example.com"), "the account is encoded: {url}");
        assert!(url.contains("issuer=%E6%9E%81"), "so is a non-ASCII issuer: {url}");
    }
}
