# peios-crypto

`peios-crypto` is the Peios cryptography library family. It will contain:

- `libpcrypto` and `libpssl`: the OpenSSL-compatible libraries Peios
  provides. Each links AWS-LC in, with its symbols renamed, and exports
  OpenSSL's names through generated forwarders, so that Peios crypto
  policy is enforced at one chokepoint. They ship AWS-LC's headers,
  pkg-config files and Rust bindings, so that C programs and aws-lc-rs
  use them as the system's OpenSSL and AWS-LC.
- `libpeios-crypto`: the opinionated Peios cryptography API, with a C ABI.
- The generator, `generate.py`, and the data it reads:
  - `bindings.toml` classifies every function AWS-LC's API offers as
    forwarded unchanged, hooked, or pending a hook, and the build fails on
    any it misses. An internal hook also checks AWS-LC's own calls to its
    function from AWS-LC's other source files, through the linker's
    `--wrap`.
  - `algorithms.toml` grades each algorithm and operation the hooks
    govern.
- The policy runtime, in `runtime/`, which the hooks ask.

`pekit build pcrypto` builds the libraries; `pekit test` runs AWS-LC's own
test suites, an aws-lc-rs program and the policy's tests against them.

The design and its decisions are recorded in Acta under PEI-1721. The Rust
crate `peios-crypto` lives in peios-rs.

Peios-authored code is MIT-licensed. AWS-LC and other dependencies retain
their own licences.
