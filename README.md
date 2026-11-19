# peios-crypto

`peios-crypto` is the Peios cryptography library family. It will contain:

- `libpcrypto` and `libpssl`: the OpenSSL-compatible libraries Peios
  provides. Each links AWS-LC in, with its symbols renamed, and exports
  OpenSSL's names through generated forwarders, so that Peios crypto
  policy is enforced at one chokepoint. They ship AWS-LC's headers,
  pkg-config files and Rust bindings, so that C programs and aws-lc-rs
  use them as the system's OpenSSL and AWS-LC.
- `libpeios-crypto`: the opinionated Peios cryptography API, with a C ABI.
- The forwarder generator, policy data and policy runtime.

`pekit build pcrypto` builds the libraries; `pekit test` runs AWS-LC's own
test suites and an aws-lc-rs program against them.

The design and its decisions are recorded in Acta under PEI-1721. The Rust
crate `peios-crypto` lives in peios-rs.

Peios-authored code is MIT-licensed. AWS-LC and other dependencies retain
their own licences.
