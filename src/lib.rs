//! CSIDH algorithm implementation
//!
//! Pure Rust implementation of the CSIDH cryptographic algorithm for secret key exchange.
//!
//! # Features
//!
//! Countermeasures against side-channel attacks can be disabled by enabling the following
//! features:
//!
//! ```toml
//! features = ["no_cm"]
//! ```
//!
//! ```
//! use csidh::{CsidhParams, PrivateKey, PublicKey, SharedSecret};
//!
//! let params = CsidhParams::CSIDH_512;
//!
//! // Alice
//! let alice_path = [
//!     8, 2, 9, 3, 3, 0, 7, 2, 0, 8, 1, 9, 9, 4, 0, 10, 6, 3, 10, 7, 2, 3, 1, 4, 5, 3, 9, 10, 9,
//!     3, 8, 5, 1, 10, 2, 4, 2, 10, 1, 1, 10, 8, 0, 9, 1, 8, 7, 6, 10, 9, 9, 4, 10, 6, 4, 4, 2, 3,
//!     5, 5, 5, 3, 0, 9, 6, 9, 8, 5, 5, 9, 2, 0, 3, 6,
//! ];
//! let alice_private_key = PrivateKey::new(params, alice_path);
//! let alice_public_key = PublicKey::associated_with(alice_private_key);
//!
//! // Bob
//! let bob_path = [
//!     1, 2, 0, 6, 2, 1, 2, 6, 4, 3, 10, 1, 4, 0, 1, 7, 5, 6, 9, 10, 8, 9, 7, 5, 4, 7, 10, 10, 5,
//!     6, 5, 2, 1, 4, 0, 6, 0, 3, 8, 7, 0, 10, 0, 3, 0, 3, 6, 9, 2, 3, 4, 4, 3, 3, 0, 10, 10, 2,
//!     1, 4, 8, 10, 6, 0, 7, 1, 2, 7, 2, 0, 9, 9, 0, 6,
//! ];
//! let bob_private_key = PrivateKey::new(params, bob_path);
//! let bob_public_key = PublicKey::associated_with(bob_private_key);
//!
//! // Shared secret
//! let alice_shared_secret = SharedSecret::from(bob_public_key, alice_private_key);
//! let bob_shared_secret = SharedSecret::from(alice_public_key, bob_private_key);
//! assert_eq!(alice_shared_secret, bob_shared_secret);
//! ```

#![no_std]
#![warn(missing_docs)]

mod csidh_params;
mod private_key;
mod public_key;
mod shared_secret;
mod csidh;
mod elliptic_curve;

pub use csidh_params::CsidhParams;
pub use public_key::PublicKey;
pub use private_key::PrivateKey;
pub use shared_secret::SharedSecret;
