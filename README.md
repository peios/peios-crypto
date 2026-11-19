# peios-crypto

`peios-crypto` is the Peios cryptography library family. It will contain:

- `libpcrypto` and `libpssl`: the OpenSSL-compatible libraries Peios
  provides, generated forwarders over AWS-LC with Peios crypto policy
  enforced at one chokepoint.
- `libpeios-crypto`: the opinionated Peios cryptography API, with a C ABI.
- The private AWS-LC build both sit on, and the generator, policy data and
  policy runtime.

The design and its decisions are recorded in Acta under PEI-1721. The Rust
crate `peios-crypto` lives in peios-rs.

Peios-authored code is MIT-licensed. AWS-LC and other dependencies retain
their own licences.
