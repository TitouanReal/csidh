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
//! in your Cargo.toml. This features disables all countermeasures. One can also remove
//! countermeasures one by one:
//!
//! ```toml
//! features = ["no_cm_velu"]
//! ```
//!
//! ```toml
//! features = ["no_cm_order"]
//! ```
//!
//! ```toml
//! features = ["no_cm_p_plus_1_over_4"]
//! ```
//!
//! # Examples
//!
//! An example using the primes [3, 5, 7]:
//!
//! ```
//! use csidh::{CsidhParams, PrivateKey, PublicKey};
//!
//! let params = CsidhParams::EXAMPLE_0;
//! let path = [2, 4, 4];
//! let private_key = PrivateKey::new(params, path);
//! let public_key = PublicKey::associated_with(private_key.clone());
//! ```
//!
//! An example using CSIDH-512 as defined in Castryck, W., Lange, T., Martindale, C., Panny, L.,
//! Renes, J.: CSIDH: An efficient post-quantum commutative group action. In: Peyrin, T.,
//! Galbraith, S. (eds.) ASIACRYPT 2018, LNCS 11274. pp. 395–427. Springer (2018):
//!
//! ```no_run
//! use csidh::{CsidhParams, PrivateKey, PublicKey};
//!
//! let params = CsidhParams::CSIDH_512;
//! let path = [
//!     8, 2, 9, 3, 3, 0, 7, 2, 0, 8, 1, 9, 9, 4, 0, 10, 6, 3, 10, 7, 2, 3, 1, 4, 5, 3, 9, 10, 9,
//!     3, 8, 5, 1, 10, 2, 4, 2, 10, 1, 1, 10, 8, 0, 9, 1, 8, 7, 6, 10, 9, 9, 4, 10, 6, 4, 4, 2, 3,
//!     5, 5, 5, 3, 0, 9, 6, 9, 8, 5, 5, 9, 2, 0, 3, 6,
//! ];
//! let private_key = PrivateKey::new(params, path);
//! let public_key = PublicKey::associated_with(private_key.clone());
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
