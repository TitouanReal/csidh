# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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