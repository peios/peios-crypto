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
  current libraries enforce only its floor, which no machine can loosen:
  they refuse the null cipher, the 40-bit export-grade RC2 cipher and RSA
  keys under 1024 bits when a program
  starts a digest, an HMAC or a cipher, or generates an RSA key, through
  `EVP_DigestInit_ex`, `HMAC_Init_ex`, `EVP_EncryptInit_ex`,
  `EVP_DecryptInit_ex` or `RSA_generate_key_ex`. Other calls go straight
  to AWS-LC for now.

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

AWS-LC's porting documents, in its repository's `docs/porting` directory,
list the functions it leaves out and those that behave differently.

A call that Peios crypto policy refuses fails as any failed OpenSSL call
does, and leaves an error on the thread's error queue whose library is
`ERR_LIB_USER`.

The libraries export only the API AWS-LC's headers declare. Functions
AWS-LC exports only for its own tests, such as its ML-KEM internals, aren't
available. Use only OpenSSL's names: libpcrypto also exports names
beginning `peios_awslc_`, which libpssl uses internally. They aren't part
of the API, and a program that calls them won't pass Peios crypto policy.
