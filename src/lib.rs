#![deny(missing_docs)]

//! A library for hashing passwords and deriving encryption keys using
//! [Argon2](https://en.wikipedia.org/wiki/Argon2). Argon2 is a memory-hard
//! [key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function) and was
//! the winner of the [Password Hashing Competition](https://www.password-hashing.net). It can
//! generate exceptionally strong hashes.
//!
//! This crate is an alternative to the
//! [argon2 crate](https://docs.rs/rust-argon2/latest/argon2/). The argon2 crate is a pure Rust
//! implementation, whereas this crate uses
//! [the original C Argon2 library](https://github.com/P-H-C/phc-winner-argon2). The original C
//! implementation usually benchmarks faster than the argon2 crate's implementation (though you
//! really should test it on your own machine--performance benchmarks are rarely universally
//! applicable).
//!
//! This crate was designed with simplicity and ease-of-use in mind. Just take a look at the
//! examples!
//!
//! # Usage
//!
//! To use argon2-kdf, add the following to your Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! argon2-kdf = "1.0"
//! ```
//!
//! # Examples
//!
//! Hash a password, then verify the hash:
//! 
//! ```rust
//! use argon2_kdf::Hasher;
//!
//! let password = "password";
//! let hash = Hasher::default().hash(&password).unwrap();
//! assert!(hash.verify(&password));
//! ```
//!
//! Change the parameters used for hashing:
//!
//! ```rust
//! use argon2_kdf::{Algorithm, Hasher};
//!
//! let password = "password";
//!
//! let hash = Hasher::new()
//!         .algorithm(Algorithm::Argon2id)
//!         .salt_length(24)
//!         .hash_length(42)
//!         .iterations(12)
//!         .memory_cost_kib(125000)
//!         .threads(2)
//!         .hash(&password)
//!         .unwrap();
//!
//! assert!(hash.verify(&password));
//! assert_eq!(hash.as_bytes().len(), 42);
//! assert_eq!(hash.salt().len(), 24);
//! ```
//!
//! Verify a hash from a hash string:
//!
//! ```rust
//! use argon2_kdf::{Hash, Hasher};
//! use std::str::FromStr;
//!
//! let password = "password";
//! let hash_string = "$argon2id$v=19$m=128,t=2,p=1$VnZ3ZFNhZkc$djHLRc+4K/DqQL0f8DMAQQ";
//!
//! let hash = Hash::from_str(hash_string).unwrap();
//! assert!(hash.verify(&password));
//! ```
//!
//! Generate a hash string:
//!
//! ```rust
//! use argon2_kdf::{Hash, Hasher};
//! use std::str::FromStr;
//!
//! let password = "password";
//! let hash = Hasher::default().hash(&password).unwrap();
//!
//! let hash_string = hash.to_string();
//!
//! assert!(Hash::from_str(&hash_string).unwrap().verify(&password));
//! ```
//!
//! Use a secret (sometimes called a
//! "[pepper](https://en.wikipedia.org/wiki/Pepper_(cryptography))") for hashing and
//! verification:
//!
//! ```rust
//! use argon2_kdf::{Hasher, Secret};
//!
//! let password = "password";
//! let secret = b"secret";
//!
//! let hash = Hasher::default()
//!         .secret(Secret::using_bytes(secret))
//!         .hash(&password)
//!         .unwrap();
//!
//! assert!(hash.verify_with_secret(&password, Secret::using_bytes(secret)));
//! ```
//!
//! Use your own salt (by default, the hasher will use a secure-random salt):
//!
//! ```rust
//! use argon2_kdf::Hasher;
//!
//! let password = "password";
//! let salt = b"dontusethissalt";
//!
//! let hash = Hasher::default()
//!         .custom_salt(salt)
//!         .hash(&password)
//!         .unwrap();
//!
//! assert!(hash.verify(&password));
//! ```

mod bindings;
mod error;
mod hasher;
mod lexer;

pub use error::Argon2Error;
pub use hasher::{Algorithm, Hash, Hasher, Secret};
