# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Impl `Eq` for `CsidhParams`, `PublicKey` and `SharedSecret`.
- Make `MontgomeryCurve::new` `const`.
- Add `private_key::{PrivateKeyCsidh512, PrivateKeyCsidh1024, PrivateKeyCsidh1792}` to easily
create `PrivateKey` in a `const` context.

### Changed

- Require `rng: &mut impl CryptoRngCore` parameter for `PublicKey::from`, `PublicKey::new` and
`SharedSecret::from` instead of using internal non-CSRNG.
- Require `sqrt_of_p_times_4: Uint<LIMBS>` parameter for `CsidhParams::new`.
- Fix public key validation in `PublicKey::new`. This function would enter an infinite loop. It now
behaves correctly.

### Removed

- Remove impl `PartialEq` for `PrivateKey`.
- Remove impl `Display` for `PrivateKey`, `PublicKey` and `SharedSecret`.

## [0.4] - 2024-06-09

### Added

- `CsidhParams::CSIDH_1024` and `CsidhParams::CSIDH_1792` are now available.
The prime numbers used are not standard, as there is no such standard.
- `CsidhParams::new` is now available, allowing to create custom params.

### Changed

- `PublicKey::from` and `SharedSecret::from` now take about 20% less time.

## [0.3] - 2024-06-02

### Changed

- `PrivateKey::new` now panics if a key element is greater than 10.
This is due to the addition of dummy operations meant to prevent side-channel attacks.
- `PublicKey::from` and `SharedSecret::from` are now about 9 times faster.

## [0.2] - 2024-05-25

### Added

- Impl `Copy` for `PrivateKey`, `PublicKey` and `SharedSecret`.

### Changed

- `PublicKey::associated_with` is renamed to `PublicKey::from` and is now about 60 times faster.
- `PublicKey::new` now performs key validation.
- `SharedSecret::from` does not perform key validation anymore and is now about 60 times faster.

### Removed

- `CsidhParams::EXAMPLE_0`
- `CsidhParams::EXAMPLE_1`
- `CsidhParams::new`
- `CsidhParams::new_no_verif`
- `CsidhParams::lis`
- `CsidhParams::lis_product`
- `CsidhParams::p`
- `PrivateKey::params`
- `PrivateKey::key`
- `PublicKey::key`
- `no_cm` feature
- `no_cm_velu` feature
- `no_cm_order` feature
- `no_cm_p_plus_1_over_4` feature

## [0.1] - 2024-04-30

- Initial release
