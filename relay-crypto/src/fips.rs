//! FIPS 140-3 backend using OpenSSL's FIPS-validated provider.
//!
//! Call `ensure_fips_loaded()` at application startup before any crypto or TLS.

use std::sync::Once;

use openssl::hash::{hash, MessageDigest};
use openssl::pkey::Id;
use openssl::sign::{Signer, Verifier};
use openssl::pkey::PKey;

static FIPS_LOADED: Once = Once::new();

/// Loads the OpenSSL FIPS provider if not already loaded. Call once at startup.
/// Requires OpenSSL 3.x built with FIPS and `OPENSSL_MODULES` set to the provider directory.
pub fn ensure_fips_loaded() -> Result<(), openssl::error::ErrorStack> {
    let mut err = Ok(());
    FIPS_LOADED.call_once(|| {
        if let Err(e) = try_load_fips() {
            err = Err(e);
        }
    });
    err
}

fn try_load_fips() -> Result<(), openssl::error::ErrorStack> {
    let provider = openssl::provider::Provider::load(None, "fips")?;
    // Prevent the provider from being unloaded when the handle goes out of scope.
    std::mem::forget(provider);
    Ok(())
}

/// SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let out = hash(MessageDigest::sha256(), data).expect("SHA-256 in FIPS");
    out.as_ref().try_into().expect("SHA-256 output is 32 bytes")
}

/// SHA-512 hash.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let out = hash(MessageDigest::sha512(), data).expect("SHA-512 in FIPS");
    out.as_ref().try_into().expect("SHA-512 output is 64 bytes")
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let pkey = PKey::hmac(key).expect("HMAC key");
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("HMAC-SHA256 signer");
    signer.update(data).expect("update");
    let sig = signer.sign_to_vec().expect("HMAC-SHA256 sign");
    sig.as_slice().try_into().expect("HMAC-SHA256 is 32 bytes")
}

/// HMAC-SHA512.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let pkey = PKey::hmac(key).expect("HMAC key");
    let mut signer = Signer::new(MessageDigest::sha512(), &pkey).expect("HMAC-SHA512 signer");
    signer.update(data).expect("update");
    let sig = signer.sign_to_vec().expect("HMAC-SHA512 sign");
    sig.as_slice().try_into().expect("HMAC-SHA512 is 64 bytes")
}

/// Fill buffer with FIPS-approved RNG.
pub fn fill_random_bytes(buf: &mut [u8]) {
    openssl::rand::rand_bytes(buf).expect("RNG in FIPS");
}

/// Extract 32-byte secret from 32 or 64 byte input.
fn secret_32(s: &[u8]) -> [u8; 32] {
    if s.len() == 64 {
        s[..32].try_into().expect("length checked")
    } else {
        s.try_into().expect("caller must pass 32 or 64 bytes")
    }
}

/// Generate Ed25519 key pair.
pub fn ed25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    let pkey = PKey::generate_ed25519().expect("Ed25519 keygen in FIPS");
    let secret = pkey.raw_private_key().expect("raw private key");
    let public = pkey.raw_public_key().expect("raw public key");
    (
        secret.as_slice().try_into().expect("Ed25519 secret is 32 bytes"),
        public.as_slice().try_into().expect("Ed25519 public is 32 bytes"),
    )
}

/// Ed25519 sign.
pub fn ed25519_sign(message: &[u8], secret_key: &[u8]) -> [u8; 64] {
    let secret = secret_32(secret_key);
    let pkey =
        PKey::private_key_from_raw_bytes(&secret, Id::ED25519).expect("Ed25519 private key");
    let mut signer = Signer::new_without_digest(&pkey).expect("Ed25519 signer");
    let sig = signer.sign_oneshot_to_vec(message).expect("Ed25519 sign");
    sig.as_slice().try_into().expect("Ed25519 signature is 64 bytes")
}

/// Ed25519 sign prehashed (SHA-512 digest).
pub fn ed25519_sign_prehashed(digest: &[u8; 64], secret_key: &[u8]) -> [u8; 64] {
    let secret = secret_32(secret_key);
    let pkey =
        PKey::private_key_from_raw_bytes(&secret, Id::ED25519).expect("Ed25519 private key");
    let mut signer = Signer::new_without_digest(&pkey).expect("Ed25519 signer");
    let sig = signer.sign_oneshot_to_vec(digest).expect("Ed25519 sign prehashed");
    sig.as_slice().try_into().expect("Ed25519 signature is 64 bytes")
}

/// Ed25519 verify.
pub fn ed25519_verify(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let pkey =
        PKey::public_key_from_raw_bytes(public_key, Id::ED25519).expect("Ed25519 public key");
    let mut verifier = Verifier::new_without_digest(&pkey).expect("Ed25519 verifier");
    verifier.update(message).expect("update");
    verifier.verify_oneshot(signature, message).unwrap_or(false)
}

/// Ed25519 verify prehashed.
pub fn ed25519_verify_prehashed(
    digest: &[u8; 64],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> bool {
    let pkey =
        PKey::public_key_from_raw_bytes(public_key, Id::ED25519).expect("Ed25519 public key");
    let mut verifier = Verifier::new_without_digest(&pkey).expect("Ed25519 verifier");
    verifier.update(digest).expect("update");
    verifier.verify_oneshot(signature, digest).unwrap_or(false)
}

/// Derive public key from secret (32 or 64 bytes).
pub fn ed25519_public_from_secret(secret_key: &[u8]) -> [u8; 32] {
    let secret = secret_32(secret_key);
    let pkey =
        PKey::private_key_from_raw_bytes(&secret, Id::ED25519).expect("Ed25519 private key");
    let raw = pkey.raw_public_key().expect("raw public key");
    raw.as_slice().try_into().expect("Ed25519 public is 32 bytes")
}
