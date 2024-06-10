# CSIDH

[![Crate](https://img.shields.io/crates/v/csidh.svg)](https://crates.io/crates/csidh)
[![API](https://docs.rs/csidh/badge.svg)](https://docs.rs/csidh)

Pure Rust implementation of the CSIDH cryptographic algorithm for secret key exchange.
Provides a no_std-friendly implementation. Not constant-time yet.

CSIDH-512, CSIDH-1024 and CSIDH-1792 are available. Custom parameters are also supported.

The current implementation is far from being as fast as the state of the art implementations.
Work is underway to improve its efficiency.

## License

This project is licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](https://github.com/TitouanReal/csidh/blob/HEAD/LICENSE-APACHE))

* [MIT License](https://opensource.org/licenses/MIT)
  ([LICENSE-MIT](https://github.com/TitouanReal/csidh/blob/HEAD/LICENSE-MIT))

at your option.

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in `csidh` by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
