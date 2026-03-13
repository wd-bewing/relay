//! Crypto backend dispatch: default (pure Rust) or FIPS (OpenSSL).

#[cfg(not(feature = "fips"))]
use crate::default as imp;

#[cfg(feature = "fips")]
use crate::fips as imp;

/// SHA-256 hash of `data`. Returns 32 bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    imp::sha256(data)
}

/// SHA-512 hash of `data`. Returns 64 bytes.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    imp::sha512(data)
}

/// HMAC-SHA256 of `data` with `key`. Returns 32 bytes.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    imp::hmac_sha256(key, data)
}

/// HMAC-SHA512 of `data` with `key`. Returns 64 bytes.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    imp::hmac_sha512(key, data)
}

/// Fill `buf` with cryptographically secure random bytes.
pub fn fill_random_bytes(buf: &mut [u8]) {
    imp::fill_random_bytes(buf);
}

/// Generate a new Ed25519 key pair. Returns (secret_key_32_bytes, public_key_32_bytes).
/// The secret is the 32-byte seed; for keypair format (64 bytes) use secret followed by public.
pub fn ed25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    imp::ed25519_generate_keypair()
}

/// Ed25519 sign `message` with `secret_key`. `secret_key` must be 32 bytes (seed) or 64 bytes (keypair; first 32 used).
pub fn ed25519_sign(message: &[u8], secret_key: &[u8]) -> [u8; 64] {
    imp::ed25519_sign(message, secret_key)
}

/// Ed25519 sign a prehashed message (SHA-512 digest) with `secret_key`.
/// `digest` must be 64 bytes (SHA-512 output); `secret_key` 32 or 64 bytes.
pub fn ed25519_sign_prehashed(digest: &[u8; 64], secret_key: &[u8]) -> [u8; 64] {
    imp::ed25519_sign_prehashed(digest, secret_key)
}

/// Ed25519 verify `signature` over `message` with `public_key` (32 bytes). Returns true if valid.
pub fn ed25519_verify(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    imp::ed25519_verify(message, signature, public_key)
}

/// Ed25519 verify a prehashed signature. `digest` is 64 bytes (SHA-512), `signature` 64 bytes, `public_key` 32 bytes.
pub fn ed25519_verify_prehashed(
    digest: &[u8; 64],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> bool {
    imp::ed25519_verify_prehashed(digest, signature, public_key)
}

/// Derive Ed25519 public key (32 bytes) from secret key (32 bytes seed or 64 bytes keypair).
pub fn ed25519_public_from_secret(secret_key: &[u8]) -> [u8; 32] {
    imp::ed25519_public_from_secret(secret_key)
}

#[cfg(feature = "fips")]
pub use crate::fips::ensure_fips_loaded;
