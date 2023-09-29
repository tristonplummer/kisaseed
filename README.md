# KISA SEED
[![crate][crate-image]][crate-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![Build][build-badge]][build]

Experimental pure Rust implementation of the [KISA SEED block cipher][1].

## ⚠️ Security Warning: Hazmat!

This crate does not ensure ciphertexts are authentic (i.e. by using a MAC to verify ciphertext integrity), which can lead to serious vulnerabilities if used incorrectly!

No security audits of this crate have ever been performed, and it has not been thoroughly assessed to ensure its operation is constant-time on common CPU architectures.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

Rust **1.56** or higher.

Minimum supported Rust version can be changed in future releases, but it will
be done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of:

* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.56+-blue.svg
[hazmat-image]: https://img.shields.io/badge/crypto-hazmat%E2%9A%A0-red.svg
[build]: https://github.com/cupsocino/kisaseed/actions
[build-badge]: https://github.com/cupsocino/kisaseed/actions/workflows/build.yml/badge.svg
[crate-image]: https://img.shields.io/crates/v/kisaseed.svg
[crate-link]: https://crates.io/crates/kisaseed

[//]: # (general links)
[1]: https://en.wikipedia.org/wiki/SEED