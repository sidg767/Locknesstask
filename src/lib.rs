#![no_std] //I used no_std so that it can work in embedded, wasm and other environments as well

extern crate alloc;

pub mod helpers;
pub mod sample_ecies;

#[cfg(test)]
mod tests;

pub use helpers::Error;
pub use sample_ecies::{decrypt, encrypt};
