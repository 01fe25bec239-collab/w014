//! Exact-width SHA-256 digest value object with canonical base64 form.
//!
//! WI-0201 frozen semantics require content hashes to be represented exactly:
//! a SHA-256 is exactly 32 bytes, never a lossy string and never an
//! open-ended byte blob. The canonical base64 form (44 chars, `=`-padded)
//! matches the repaired `upload_intents.expected_sha256_b64` physical shape.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as Sha2Digest, Sha256 as Sha256Hasher};

use crate::error::DomainError;
use crate::limits::SHA256_BYTE_LEN;

/// A validated 32-byte SHA-256 digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256([u8; SHA256_BYTE_LEN]);

impl Sha256 {
    /// Wraps an already exact-width digest array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SHA256_BYTE_LEN]) -> Self {
        Self(bytes)
    }

    /// Validates that a byte slice is exactly 32 bytes and wraps it.
    ///
    /// # Errors
    /// Fails closed when the slice is not exactly [`SHA256_BYTE_LEN`] bytes.
    pub fn from_slice(field: &'static str, bytes: &[u8]) -> Result<Self, DomainError> {
        let arr: [u8; SHA256_BYTE_LEN] =
            bytes
                .try_into()
                .map_err(|_| DomainError::InvalidSha256Length {
                    field,
                    actual: bytes.len(),
                })?;
        Ok(Self(arr))
    }

    /// Computes the SHA-256 digest of the given data (server-side authority).
    #[must_use]
    pub fn digest(data: &[u8]) -> Self {
        let mut hasher = Sha256Hasher::new();
        hasher.update(data);
        Self(<[u8; SHA256_BYTE_LEN]>::from(hasher.finalize()))
    }

    /// Returns the exact 32-byte digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_BYTE_LEN] {
        &self.0
    }

    /// Lowercase hexadecimal representation (64 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(SHA256_BYTE_LEN * 2);
        for b in self.0 {
            out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            out.push(char::from_digit(u32::from(b & 0x0F), 16).unwrap_or('0'));
        }
        out
    }

    /// Parses a lowercase/uppercase hexadecimal representation of 64 chars.
    ///
    /// # Errors
    /// Fails closed unless the input is exactly 64 hex characters.
    pub fn from_hex(field: &'static str, hex: &str) -> Result<Self, DomainError> {
        let raw = hex.as_bytes();
        if raw.len() != SHA256_BYTE_LEN * 2 {
            return Err(DomainError::InvalidSha256Length {
                field,
                actual: raw.len(),
            });
        }
        let mut out = [0u8; SHA256_BYTE_LEN];
        for (i, pair) in raw.chunks_exact(2).enumerate() {
            let hi = hex_val(pair[0]).ok_or(DomainError::InvalidSha256Length {
                field,
                actual: raw.len(),
            })?;
            let lo = hex_val(pair[1]).ok_or(DomainError::InvalidSha256Length {
                field,
                actual: raw.len(),
            })?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }

    /// Canonical base64 representation: 44 ASCII chars ending in `'='`,
    /// exactly the shape enforced by the physical
    /// `chk_upload_intents_sha256_b64_shape` CHECK constraint.
    #[must_use]
    pub fn to_base64(&self) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(44);
        for chunk in self.0.chunks_exact(3) {
            let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
            out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
            out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
            out.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
            out.push(ALPHABET[n as usize & 0x3F] as char);
        }
        // 32 bytes leave a final 2-byte chunk; one padding character completes
        // the canonical 44-char form.
        let last = self.0[30];
        let n = (u32::from(last) << 16) | (u32::from(self.0[31]) << 8);
        out.push(ALPHABET[(n >> 18) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3F] as char);
        out.push(ALPHABET[(n >> 6) as usize & 0x3F] as char);
        out.push('=');
        out
    }

    /// Parses the canonical 44-char padded base64 representation.
    ///
    /// # Errors
    /// Fails closed unless the input decodes to exactly 32 bytes under the
    /// strict canonical shape (`^[A-Za-z0-9+/]{43}=$`).
    pub fn from_base64(field: &'static str, b64: &str) -> Result<Self, DomainError> {
        let err = || DomainError::ValidationError {
            field,
            reason: format!("'{b64}' is not canonical 32-byte base64"),
        };
        let raw = b64.as_bytes();
        if raw.len() != 44 || raw[43] != b'=' {
            return Err(err());
        }
        let mut out = [0u8; SHA256_BYTE_LEN];
        for (i, quad) in raw.chunks_exact(4).enumerate() {
            let is_last = i == 10;
            for (k, byte) in quad.iter().enumerate() {
                let ok = if is_last && k == 3 {
                    *byte == b'='
                } else {
                    b64_val(*byte).is_some()
                };
                if !ok {
                    return Err(err());
                }
            }
            let v0 = b64_val(quad[0]).unwrap_or(0);
            let v1 = b64_val(quad[1]).unwrap_or(0);
            let v2 = if is_last && quad[2] == b'=' {
                0
            } else {
                b64_val(quad[2]).unwrap_or(0)
            };
            let v3 = if is_last {
                0
            } else {
                b64_val(quad[3]).unwrap_or(0)
            };
            let n = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
            let base = i * 3;
            out[base] = ((n >> 16) & 0xFF) as u8;
            if base + 1 < SHA256_BYTE_LEN {
                out[base + 1] = ((n >> 8) & 0xFF) as u8;
            }
            if base + 2 < SHA256_BYTE_LEN {
                out[base + 2] = (n & 0xFF) as u8;
            }
        }
        Ok(Self(out))
    }
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn b64_val(byte: u8) -> Option<u32> {
    match byte {
        b'A'..=b'Z' => Some(u32::from(byte - b'A')),
        b'a'..=b'z' => Some(u32::from(byte - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(byte - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl Serialize for Sha256 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Sha256::from_hex("sha256", &s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_and_roundtrip() {
        let d = Sha256::digest(b"abc");
        assert_eq!(
            d.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let parsed = Sha256::from_hex("sha256", &d.to_hex()).unwrap();
        assert_eq!(d, parsed);
    }

    #[test]
    fn test_slice_length_enforced_exactly() {
        assert!(Sha256::from_slice("h", &[0u8; 31]).is_err());
        assert!(Sha256::from_slice("h", &[0u8; 33]).is_err());
        assert!(Sha256::from_slice("h", &[0u8; 32]).is_ok());
    }

    #[test]
    fn test_canonical_base64_matches_physical_shape() {
        let d = Sha256::digest(b"w014");
        let b64 = d.to_base64();
        assert_eq!(b64.len(), 44);
        assert!(b64.ends_with('='));
        assert_eq!(Sha256::from_base64("h", &b64).unwrap(), d);

        // Zero digest has the exact all-zero canonical form accepted by M002R.
        let zero = Sha256::from_bytes([0u8; 32]);
        assert_eq!(
            zero.to_base64(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn test_noncanonical_base64_rejected() {
        assert!(Sha256::from_base64("h", "not-base64!!").is_err());
        assert!(Sha256::from_base64("h", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=A").is_err());
        assert!(Sha256::from_base64("h", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==").is_err());
        assert!(Sha256::from_base64("h", "AAAA").is_err());
    }

    #[test]
    fn test_serde_hex_representation() {
        let d = Sha256::digest(b"x");
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{}\"", d.to_hex()));
        let back: Sha256 = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }
}
