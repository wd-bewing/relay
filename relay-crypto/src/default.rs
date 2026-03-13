//! Default crypto backend using pure-Rust crates (not FIPS-validated).

use digest::generic_array::typenum::U64;
use digest::generic_array::GenericArray;
use digest::{FixedOutput, FixedOutputReset, HashMarker, OutputSizeUser, Reset, Update};
use ed25519_dalek::{DigestSigner, DigestVerifier, Signer, Verifier};
use hmac::{Hmac, Mac};
use rand::RngCore as _;
use sha2::{Digest as Sha2Digest, Sha256, Sha512};

/// SHA-256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// SHA-512 hash.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().into()
}

/// HMAC-SHA512.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac =
        Hmac::<Sha512>::new_from_slice(key).expect("HMAC-SHA512 accepts any key length");
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().into()
}

/// Fill buffer with OS RNG.
pub fn fill_random_bytes(buf: &mut [u8]) {
    rand::rng().fill_bytes(buf);
}

/// Extract 32-byte secret from 32 or 64 byte input.
fn secret_bytes(s: &[u8]) -> &[u8; 32] {
    let bytes: &[u8; 32] = if s.len() == 64 {
        s[..32].try_into().expect("length checked")
    } else {
        s.try_into().expect("caller must pass 32 or 64 bytes")
    };
    bytes
}

/// Generate Ed25519 key pair.
pub fn ed25519_generate_keypair() -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    fill_random_bytes(&mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let pk = sk.verifying_key();
    (secret, pk.to_bytes())
}

/// Ed25519 sign.
pub fn ed25519_sign(message: &[u8], secret_key: &[u8]) -> [u8; 64] {
    let secret: &[u8; 32] = secret_bytes(secret_key);
    let sk = ed25519_dalek::SigningKey::from_bytes(secret);
    sk.sign(message).to_bytes()
}

/// Wrapper to use precomputed SHA-512 digest (64 bytes) with ed25519-dalek's sign_digest.
#[derive(Clone)]
struct PrehashedSha512([u8; 64]);

impl Default for PrehashedSha512 {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl OutputSizeUser for PrehashedSha512 {
    type OutputSize = U64;
}

impl HashMarker for PrehashedSha512 {}

impl Update for PrehashedSha512 {
    fn update(&mut self, data: &[u8]) {
        if data.len() >= 64 {
            self.0.copy_from_slice(&data[..64]);
        }
    }
}

impl FixedOutput for PrehashedSha512 {
    fn finalize_into(self, out: &mut GenericArray<u8, U64>) {
        out.copy_from_slice(&self.0);
    }
}

impl Reset for PrehashedSha512 {
    fn reset(&mut self) {
        self.0 = [0; 64];
    }
}

impl FixedOutputReset for PrehashedSha512 {
    fn finalize_into_reset(&mut self, out: &mut GenericArray<u8, U64>) {
        out.copy_from_slice(&self.0);
        Reset::reset(self);
    }
}

/// Ed25519 sign prehashed (SHA-512 digest).
pub fn ed25519_sign_prehashed(digest: &[u8; 64], secret_key: &[u8]) -> [u8; 64] {
    let secret: &[u8; 32] = secret_bytes(secret_key);
    let sk = ed25519_dalek::SigningKey::from_bytes(secret);
    let mut d = PrehashedSha512(*digest);
    Update::update(&mut d, digest);
    sk.sign_digest(d).to_bytes()
}

/// Ed25519 verify.
pub fn ed25519_verify(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let pk = match ed25519_dalek::VerifyingKey::from_bytes(public_key) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    pk.verify(message, &sig).is_ok()
}

/// Ed25519 verify prehashed.
pub fn ed25519_verify_prehashed(
    digest: &[u8; 64],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> bool {
    let pk = match ed25519_dalek::VerifyingKey::from_bytes(public_key) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    let mut d = PrehashedSha512(*digest);
    Update::update(&mut d, digest);
    pk.verify_digest(d, &sig).is_ok()
}

/// Derive public key from secret (32 or 64 bytes).
pub fn ed25519_public_from_secret(secret_key: &[u8]) -> [u8; 32] {
    let secret: &[u8; 32] = secret_bytes(secret_key);
    let sk = ed25519_dalek::SigningKey::from_bytes(secret);
    sk.verifying_key().to_bytes()
}
