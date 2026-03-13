# FIPS 140-3 Compatibility

Relay can be built and run with FIPS 140-3 compatible cryptography. In this mode, all cryptographic operations (authentication, HMAC, hashing, and TLS) use OpenSSL's FIPS-validated provider.

## Requirements

- **OpenSSL 3.x** built with FIPS support (e.g. OpenSSL 3.0.0+ with the FIPS provider).
- At build time: OpenSSL development headers and library in a FIPS configuration, or a FIPS-built OpenSSL install pointed to by `OPENSSL_DIR` (see below).
- At runtime: The FIPS provider must be loadable; set `OPENSSL_MODULES` to the directory containing the FIPS provider shared library (e.g. `openssl-modules` or `ossl-modules`).

## Building Relay with FIPS

1. **Build or install OpenSSL 3.x with FIPS**

   Example (Linux; adjust paths and options per your environment):

   ```bash
   # Example: build OpenSSL 3.x with FIPS module
   ./config --prefix=/opt/openssl-fips --openssldir=/opt/openssl-fips fips
   make && make install
   ```

   Ensure the FIPS provider is built and installed under the OpenSSL prefix (e.g. in `lib/ossl-modules/` or similar).

2. **Build Relay with the `fips` feature**

   Point Cargo to your FIPS OpenSSL (if not in a default system path):

   ```bash
   export OPENSSL_DIR=/opt/openssl-fips
   export OPENSSL_LIB_DIR=/opt/openssl-fips/lib
   export OPENSSL_INCLUDE_DIR=/opt/openssl-fips/include
   cargo build --features fips -p relay
   ```

   If using system OpenSSL that is already FIPS-built, you may only need:

   ```bash
   cargo build --features fips -p relay
   ```

   The `relay` binary is the one that must be built with `fips`; it will load the FIPS provider at startup.

3. **Runtime**

   Ensure the FIPS provider is available when starting Relay:

   ```bash
   export OPENSSL_MODULES=/opt/openssl-fips/lib/ossl-modules
   ./relay run
   ```

   If the provider fails to load, Relay will exit at startup with an error.

## What changes in FIPS mode

- **Crypto backend**: The `relay-crypto` crate uses the OpenSSL backend (hashing, HMAC, Ed25519, RNG) instead of pure-Rust implementations.
- **Startup**: The Relay process loads the OpenSSL FIPS provider before any other crypto or TLS.
- **TLS**: All TLS (reqwest, Redis, Kafka) should use the same OpenSSL that was built with FIPS; when linking against a FIPS-built OpenSSL and loading the FIPS provider, TLS uses FIPS-approved algorithms.
- **Algorithms**: MD5 is not used; hashing uses SHA-256/SHA-512. HMAC uses SHA-256 or SHA-512. Ed25519 and approved TLS ciphers are used.
- **Event normalization**: The `relay-event-normalization` crate uses regex capture group names `md5` and `sha1` only to match URL path segments that look like 32- or 40-character hex strings (e.g. `/clients/563712f9.../project/01234`). No MD5 or SHA-1 hashing is performed there; hashing in that crate uses SHA-256 where needed.

## Notes

- **Validation**: This setup uses a FIPS-validated cryptographic module (OpenSSL's FIPS provider). Relay as an application is not itself FIPS 140-3 validated; formal product validation would require the CMVP process.
- **Platform**: FIPS builds are typically used on Linux with a FIPS-built OpenSSL. Windows and macOS may have different options (e.g. platform FIPS crypto); refer to your OpenSSL or platform documentation.
- **Default build**: The default Relay build does **not** enable FIPS and does not depend on OpenSSL for the crypto abstraction (it uses pure-Rust crates). Only with `--features fips` does Relay link to OpenSSL and load the FIPS provider.

## Testing

Run the crypto abstraction tests (default backend):

```bash
cargo test -p relay-crypto
```

To run with the FIPS backend, build and test with the feature (requires OpenSSL 3.x with FIPS on the system):

```bash
cargo test -p relay-crypto --no-default-features --features fips
```

Integration and auth tests should pass with the default build; when building with `fips`, ensure OpenSSL FIPS is available as described above.
