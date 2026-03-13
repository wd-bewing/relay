//! Cryptographic abstraction for Relay with optional FIPS 140-3 support.
//!
//! By default uses pure-Rust implementations. With the `fips` feature, all
//! operations go through OpenSSL's FIPS-validated provider (must be loaded at
//! application startup).

#![warn(missing_docs)]

#[cfg(not(feature = "fips"))]
mod default;

#[cfg(feature = "fips")]
mod fips;

mod backend;

pub use backend::{
    ed25519_generate_keypair, ed25519_public_from_secret, ed25519_sign, ed25519_sign_prehashed,
    ed25519_verify, ed25519_verify_prehashed, fill_random_bytes, hmac_sha256, hmac_sha512, sha256,
    sha512,
};

#[cfg(feature = "fips")]
pub use backend::ensure_fips_loaded;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let h = sha256(b"hello");
        assert_eq!(h.len(), 32);
        assert_ne!(h, sha256(b"world"));
        assert_eq!(sha256(b""), sha256(b""));
    }

    #[test]
    fn test_sha512() {
        let h = sha512(b"hello");
        assert_eq!(h.len(), 64);
        assert_ne!(h, sha512(b"world"));
    }

    #[test]
    fn test_hmac_sha256() {
        let tag = hmac_sha256(b"key", b"data");
        assert_eq!(tag.len(), 32);
        assert_ne!(tag, hmac_sha256(b"key", b"other"));
        assert_ne!(tag, hmac_sha256(b"other", b"data"));
    }

    #[test]
    fn test_hmac_sha512() {
        let tag = hmac_sha512(b"key", b"data");
        assert_eq!(tag.len(), 64);
    }

    #[test]
    fn test_ed25519_sign_verify() {
        let (secret, public) = ed25519_generate_keypair();
        let msg = b"test message";
        let sig = ed25519_sign(msg, &secret);
        assert!(ed25519_verify(msg, &sig, &public));
        assert!(!ed25519_verify(b"wrong", &sig, &public));
    }

    #[test]
    fn test_ed25519_sign_verify_keypair_64() {
        let (secret, public) = ed25519_generate_keypair();
        let keypair_64: Vec<u8> = secret.iter().chain(public.iter()).copied().collect();
        let msg = b"test";
        let sig = ed25519_sign(msg, &keypair_64);
        assert!(ed25519_verify(msg, &sig, &public));
    }

    #[test]
    fn test_ed25519_public_from_secret() {
        let (secret, public) = ed25519_generate_keypair();
        let derived = ed25519_public_from_secret(&secret);
        assert_eq!(derived, public);
    }

    #[test]
    fn test_ed25519_prehashed() {
        let (secret, public) = ed25519_generate_keypair();
        let digest = sha512(b"prehashed message");
        let sig = ed25519_sign_prehashed(&digest, &secret);
        assert!(ed25519_verify_prehashed(&digest, &sig, &public));
        assert!(!ed25519_verify_prehashed(&sha512(b"other"), &sig, &public));
    }

    #[test]
    fn test_fill_random_bytes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill_random_bytes(&mut a);
        fill_random_bytes(&mut b);
        assert_ne!(a, b);
    }
}
