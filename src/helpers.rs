use alloc::vec::Vec; // Didn't use heapless Vec because size of Ciphertext unknown, we can add try_reserve to avoid OOM panic, but for simplicity not used here
use sha2::{Digest, Sha256};

#[derive(Debug, PartialEq)]
pub enum Error {
    WrongPoint,
    LessBytes,
}

pub fn h(data: &[u8]) -> [u8; 32] {
    //hashes data at once and coverts to [u8;32]
    Sha256::digest(data).into()
}

pub fn expand(block: &[u8], len: usize) -> Vec<u8> {
    // Repeatedly appends the block to itself till len reached
    let mut encryd = Vec::with_capacity(len);
    while encryd.len() < len {
        let left = len - encryd.len();
        let take = left.min(block.len());
        encryd.extend_from_slice(&block[..take]);
    }
    encryd
}

pub fn xor(buf: &mut [u8], key: &[u8]) {
    // mutable byte buffer store xor of ct and key, modifies in place
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= key[i];
    }
}
