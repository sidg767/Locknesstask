//! Logic:
//! receiver has: private key-sk, public key- pk = G * sk
//! Sender needs to encrypt msg M, to do so he generates a temporary primary key eph and it's temp public key  R= G*eph
//! Then sender derives the shared secret S = pk * eph = G * sk * eph. This is the whole basis of this encryption.
//! Then sender encodes S(turning curve points to byte strings as hashing algs work on fixed len input)
//! It is then hashed to get a key K of 32 bytes, which is then expanded to the length of M.
//! Next, each byte of M is XORed with the corresponding K byte to get the ciphertext.
//! The output returned is the concatenation of R and Ciphertext.
//! Encrypt(pk, M):
//!   eph <- Zq
//!   R   = G * eph
//!   K   = Expand(H(encode(pk * eph)), len(M))
//!   return encode(R) || (M XOR K)

//! To decrypt, receiver takes the first part of the ciphertext(ct) to get R,
//! Then he computes the shared secret S = R * sk = G * eph * sk, which is the same as the sender's shared secret.
//! Then the receiver can encode(S), hash it and expand it to get K.
//! Now to get the msg M, as XOR is self-inverse, the receiver XORs K with the second part of the ciphertext to get M.
//! Decrypt(sk, ct):
//!   R   = decode(ct[..point_len])
//!   K   = Expand(H(encode(R * sk)), len(ct[point_len..]))
//!   return ct[point_len..] XOR K

use crate::helpers::{Error, expand, h, xor};
use alloc::vec::Vec;
use generic_ec::{Curve, EncodedPoint, Point, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};

/// Used u8 instead of any other types so that we can encrypt any arbitrary data,
/// and &[u8] because it works with arrays, vectors, and slices equally.
/// not just UTF-8. Used &mut because generating randomness changes RNG's internal state
pub fn encrypt<E: Curve>(
    plaintxt: &[u8],
    pk: &Point<E>,
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<u8> {
    // SecretScalar zeroizes itself on drop, so the ephemeral private key doesn't linger in memory after encryption.
    let eph = SecretScalar::<E>::random(rng);
    // I used to_bytes to serialize the points to compressed bytes, so that it can be used as input for the hash function
    let r: EncodedPoint<E> = (Point::generator() * &eph).to_bytes(true);
    let shared_secret: EncodedPoint<E> = (pk * &eph).to_bytes(true);
    // as_ref() gives a byte slice without copying, using h gives type mismatch, so used &h as &[u8;32] needed
    let key = expand(&h(shared_secret.as_ref()), plaintxt.len());
    // with_capacity() is an optimization to avoid multiple reallocations as we know the final size
    let mut encryd = Vec::with_capacity(r.as_ref().len() + plaintxt.len());

    encryd.extend_from_slice(r.as_ref());
    // push adds only one element, so used extend_from_slice, can't use &r because we need to convert to &[u8]
    encryd.extend_from_slice(plaintxt);
    xor(&mut encryd[r.as_ref().len()..], &key);
    encryd
}

pub fn decrypt<E: Curve>(sk: &Scalar<E>, ciphertxt: &[u8]) -> Result<Vec<u8>, Error> {
    let rlen = Point::<E>::serialized_len(true);
    // Depending on the curve we determine the size of the compressed point
    // If ct is less than rlen, then there's nothing to decrypt
    if ciphertxt.len() < rlen {
        return Err(Error::LessBytes);
    }
    let (r_bytes, ct) = ciphertxt.split_at(rlen);
    // from_bytes returns error if bytes don't represent a point on the curve
    let r = Point::<E>::from_bytes(r_bytes).map_err(|_| Error::WrongPoint)?;

    let shared_secret: EncodedPoint<E> = (r * sk).to_bytes(true);
    let key = expand(&h(shared_secret.as_ref()), ct.len());
    let mut plaintxt = ct.to_vec();
    xor(&mut plaintxt, &key);
    Ok(plaintxt)
}
