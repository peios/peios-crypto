---
title: Using the OpenSSL-Compatible Libraries
type: how-to
description: Build C programs and aws-lc-rs crates against libpcrypto and libpssl, the Peios libraries with OpenSSL's API.
related:
  - peios/cryptography/using-cryptography-from-rust
---

Peios provides cryptography and TLS through two libraries with OpenSSL's
API: libpcrypto, for cryptography, and libpssl, for TLS. Software written
for OpenSSL builds against them with its source unchanged, and Rust
crates built on aws-lc-rs, such as rustls, can use them in place of a copy
of their own.

Both libraries are built from AWS-LC, Amazon's cryptography library, and
provide the API AWS-LC does. They link AWS-LC in and export each function
under its OpenSSL name, so that every call a program makes passes through
one place where Peios can apply its crypto policy.

For new Rust code written for Peios, use the `peios-crypto` crate instead;
see [Using Cryptography from Rust](~peios/cryptography/using-cryptography-from-rust).

## Before you start

- Build libpcrypto and libpssl from the peios-crypto repository with
  `pekit build pcrypto`, and install the tree it gives under `/usr`. Peios
  doesn't ship them as a package yet.
- Install a C compiler and pkg-config.
- Expect Peios crypto policy to apply to these libraries' callers. The
  current libraries apply it when a program computes a digest or a MAC
  (HMAC, CMAC, Poly1305, or SipHash), starts or keys a cipher or an AEAD,
  derives a key, encrypts or decrypts a private key, PEM file, PKCS #12
  file or PKCS #7 message, generates or uses a public key, verifies a
  signature in a certificate, OCSP response or PKCS #7 message, or
  finishes a TLS handshake. Data that names its own algorithm, such as an
  encrypted PKCS #12 file, is checked as it's read, before it's
  decrypted. The libraries enforce only the policy's floor, which no
  machine can loosen: the null ciphers, the 40-bit export-grade RC2
  cipher, and RSA keys and Diffie-Hellman parameters under 1024 bits.
  Two calls still go straight to AWS-LC: `EVP_CIPHER_CTX_set_key_length`
  and `EVP_CIPHER_CTX_ctrl`, which can change a cipher's key length or
  parameters after the cipher was checked.
- Expect TLS to be checked once each handshake has negotiated, before any
  data is sent or received on it: its version, cipher suite, key-exchange
  group, keys, signatures, and the peer's certificate chain. If policy
  refuses any of them, the connection fails with an `insufficient_security`
  alert, as if the handshake itself had failed, and every later call on it
  fails too. A call such as `SSL_write` that runs the handshake itself
  checks it before sending anything. TLS 1.3's early data isn't checked: a
  client sends it before the handshake negotiates anything, using a
  session that an earlier handshake negotiated.

## Build a C program

1. Include OpenSSL's headers as usual. This program prints the library's
   version and the SHA-256 digest of `abc`:

   ```c
   #include <stdio.h>

   #include <openssl/crypto.h>
   #include <openssl/sha.h>

   int main(void) {
       unsigned char digest[SHA256_DIGEST_LENGTH];
       SHA256((const unsigned char *)"abc", 3, digest);
       printf("%s\n", OpenSSL_version(OPENSSL_VERSION));
       for (size_t i = 0; i < sizeof(digest); i++) {
           printf("%02x", digest[i]);
       }
       printf("\n");
       return 0;
   }
   ```

2. Save it as `digest.c`, and compile it with the flags pkg-config gives
   for `libcrypto`:

   ```sh
   cc -o digest digest.c $(pkg-config --cflags --libs libcrypto)
   ```

   For a program that uses TLS, ask for `openssl` instead, which gives
   both libraries.

A build that links `-lssl -lcrypto` without asking pkg-config works too:
`libssl.so` and `libcrypto.so` lead to libpssl and libpcrypto.

## Check the result

Run the program:

```sh
./digest
```

It prints AWS-LC's version and the digest:

```text
AWS-LC 5.15.0
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

## Build a Rust crate that uses aws-lc-rs

aws-lc-rs normally compiles its own copy of AWS-LC. Set
`AWS_LC_SYS_SYSTEM_DIR` when you build, and it uses libpcrypto instead:

```sh
AWS_LC_SYS_SYSTEM_DIR=/usr cargo build
```

aws-lc-rs reads the Rust bindings that libpcrypto installs at
`/usr/share/rust/aws_lc_bindings.rs`, and links `libcrypto.so`. The program
it builds loads libpcrypto when it runs, and contains no AWS-LC of its own.

## Differences from OpenSSL

AWS-LC provides OpenSSL 1.1.1's API, with some of OpenSSL 3's functions,
not all of OpenSSL 3. Expect to change a program that needs:

- **OpenSSL 3's providers, or engines loaded by name.** AWS-LC has no
  providers, and its algorithms are built in. Its `ENGINE` can only stand
  in for RSA and EC key operations, with methods the program supplies.
- **A newer OpenSSL version.** libpcrypto reports version 1.1.1 to
  pkg-config and in `OPENSSL_VERSION_NUMBER`, so a build that insists on
  OpenSSL 3 refuses it.
- **Elliptic curves of your own.** A key on a curve given by its
  parameters is accepted only if the curve is one of the named curves
  AWS-LC provides, such as P-256; any other curve is refused.
- **`PKCS12_create`'s defaults.** AWS-LC encrypts a PKCS #12 file's
  certificates with 40-bit RC2 unless told otherwise, and Peios crypto
  policy refuses it. Pass -1 as `cert_nid` to leave the certificates,
  which are public, unencrypted. Files that other software encrypted
  this way still read.

AWS-LC's porting documents, in its repository's `docs/porting` directory,
list the functions it leaves out and those that behave differently.

A call that Peios crypto policy refuses fails as any failed OpenSSL call
does, and leaves an error on the thread's error queue whose library is
`ERR_LIB_USER`. A few functions can't report failure, or have callers
that never check: the low-level digest functions, such as `SHA256` and
`MD5_Init`, the low-level cipher keying functions, such as
`AES_set_encrypt_key`, and Poly1305's and SipHash's. When policy refuses
one of those, the program ends with a message naming the function,
rather than carry on with a digest or key that was never computed. Use
the `EVP_` functions where a refusal should be handled.

The libraries export only the API AWS-LC's headers declare. Functions
AWS-LC exports only for its own tests, such as its ML-KEM internals, aren't
available. Use only OpenSSL's names: libpcrypto also exports names
beginning `peios_awslc_`, which libpssl uses internally. They aren't part
of the API, and a program that calls them won't pass Peios crypto policy.
