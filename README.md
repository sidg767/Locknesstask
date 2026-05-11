# locknesstask

`locknesstask` is a small Rust crate offering a no_std-compatible sample ECIES-style encryption implementation over generic elliptic curves.

## Highlights

- `no_std` friendly with `alloc`
- Uses `generic-ec` for curve-agnostic cryptography
- Supports feature-gated curves:
  - `curve-ed25519`
  - `curve-secp256k1`
  - `curve-secp384r1`
- Provides a compact sample ECIES encryption/decryption API
- Includes deterministic test vectors and roundtrip encryption tests

## Crate API

### Public items

- `lnesstask::Error`
  - `WrongPoint`
  - `LessBytes`
- `lnesstask::encrypt`
- `lnesstask::decrypt`

### `encrypt`

```rust
use generic_ec::{curves::Ed25519, Point};
use rand::thread_rng;
use lnesstask::encrypt;

let mut rng = thread_rng();
let sk = generic_ec::Scalar::<Ed25519>::random(&mut rng);
let pk = Point::<Ed25519>::generator() * &sk;
let plaintext = b"hello world";
let ciphertext = encrypt::<Ed25519>(plaintext, &pk, &mut rng);
```

### `decrypt`

```rust
use generic_ec::{curves::Ed25519, Scalar};
use lnesstask::{decrypt, Error};

let plaintext = decrypt::<Ed25519>(&sk, &ciphertext)?;
assert_eq!(plaintext, b"hello world");
```

## How it works

This crate demonstrates a simple ECIES-style construction:

1. Generate an ephemeral scalar and ephemeral public key.
2. Compute a shared secret using the recipient public key.
3. Hash and expand the shared secret into a keystream.
4. XOR the plaintext with the keystream.
5. Output the encoded ephemeral public key followed by ciphertext bytes.

On decryption, the recipient recovers the shared secret from the ephemeral public key and their private scalar, then reverses the XOR.

## Features

Enable one or more curve features in `Cargo.toml`:

```toml
[dependencies.lnesstask]
version = "0.1.0"
default-features = false
features = ["curve-ed25519"]
```

## Development

Run the full test suite with:

```sh
cargo test
```

## Notes

- This crate is an educational sample and not intended as a production-ready encryption library.
- It relies on `generic-ec` for curve operations and `sha2` for hashing.
- The implementation is intentionally minimal and designed to demonstrate generic curve encryption patterns.
