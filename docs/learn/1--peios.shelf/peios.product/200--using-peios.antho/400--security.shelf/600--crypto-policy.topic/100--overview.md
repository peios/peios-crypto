---
title: How Crypto Policy Works
type: concept
description: How Peios decides which cryptography programs can use, records the weak cryptography in use, and lets particular programs keep using what they need.
related:
  - peios/crypto-policy/configuring-crypto-policy
  - peios/crypto-policy/cryptod-reference
  - peios/cryptography/using-the-openssl-compatible-libraries
---

Peios applies one crypto policy to every program on the machine that uses
libpcrypto or libpssl, its libraries with OpenSSL's API. The policy decides
which algorithms a program can use, records the use of weak ones, and lets
named programs keep using an algorithm that they need and that the policy
would otherwise refuse.

The policy is configured under `Machine\System\Cryptography`. cryptod, the
crypto policy service, publishes it as a file that the libraries read, and
records what programs report of their weak cryptography.

## Grades

Each use of cryptography is graded as an **entry**: an algorithm and the
operation it's used for, such as `md5.hmac` for HMAC-MD5 or `md5.digest`
for an MD5 digest. The same algorithm can have different grades for
different operations. MD5 is broken as a digest, but HMAC-MD5 has no
practical attack.

Grades run from U to A:

| Grade | Meaning |
|---|---|
| U | Practically broken, or forbidden by current standards |
| D | No practical break, but under 112-bit security or deprecated |
| C | 112-bit security |
| B | 128-bit security |
| A | 192-bit security or more |

Separately, each entry records whether FIPS 140-3 approves it. FIPS
approval isn't a grade: FIPS approves some entries below A, such as
HMAC-SHA-1, and doesn't approve some A-grade ones.

`/usr/share/peios-crypto/algorithms.tsv` lists every entry, with its grade
and whether FIPS approves it.

A few entries are on the **floor**: they're refused under every policy, and
no exception can allow them. The floor holds ciphers and TLS suites that
encrypt nothing, the 40-bit export-grade RC2 cipher, RSA keys and
Diffie-Hellman parameters under 1024 bits, and ECDSA signing with a fixed
nonce, which gives away the private key.

## Thresholds

The policy has two thresholds:

- **Reject:** entries below this grade are refused. By default it's U, so
  only the floor is refused.
- **Warn:** entries below this grade are allowed, but their use is
  recorded. By default it's C, so the use of anything graded U or D is
  recorded.

Each can also apply to every entry FIPS doesn't approve, whatever its
grade. Turning that on for Reject doesn't make the machine operate in a
FIPS-approved mode, because the libraries' module isn't validated.

A refused call fails as if the algorithm weren't supported. A few
low-level functions can't report failure, such as `SHA256` and `MD5_Init`,
so a program that calls one for a refused entry ends. Before raising the
Reject threshold, find out what would stop working: see
[Configuring Crypto Policy](~peios/crypto-policy/configuring-crypto-policy).

## Exceptions

An exception lets particular programs use particular entries: a RADIUS
server that must use HMAC-MD5 because the protocol requires it, for
example. Each exception is a key under
`Machine\System\Cryptography\Exceptions`, named `Owner.Purpose`, such as
`Radius.PacketAuth`. It names the entries it allows, and has a security
descriptor, `ProgramSecurity`, granting the programs that can use it.

Packages add the exceptions their software needs when they install, and
remove them when they uninstall.

> [!IMPORTANT]
> **An exception applies to a program, not to whoever it's acting for.**
> `ProgramSecurity` is checked against each process's primary token, the
> identity the program runs as. Impersonation is ignored. This is unusual
> on Peios, where access is normally decided by whose behalf a thread is
> acting on.
>
> An exception answers "which software needs this algorithm". If it
> followed impersonation, a service would lose its exception while it
> served a client, and a client could weaken a service's cryptography.
>
> Grant a service's own SID, `S-1-5-80-...`, to except one service. A user
> or group SID is accepted, but it excepts every program that runs as that
> user or group, including ones that don't need the algorithm.

An exception allows an entry the Reject threshold refuses only while
`Exceptions\AllowExceptionsToReject` is 1, its default. When it's 0,
exceptions only stop warnings. An exception never allows an entry on the
floor.

## When changes apply

cryptod publishes the policy when it starts, and again a moment after
`Machine\System\Cryptography` changes. Each process reads the policy once,
at its first use of the libraries, and keeps it for as long as it runs.

So a change applies to processes started after it's published. A service
that's already running keeps the policy it started with until it's
restarted. Exceptions work the same way, so a service doesn't lose one
partway through a request.

cryptod also keeps a copy of the policy that survives a reboot. A process
that starts before cryptod reads that copy. A process uses Peios's built-in
defaults only on a machine where cryptod has never run, or if it can't use
either copy.

## What's recorded

The libraries report to cryptod, and cryptod records each report as an
event:

- `cryptod.algorithm.warned`: a process's first use of each entry below
  the Warn threshold.
- `cryptod.exception.used`: a process's first use of each exception,
  whether or not the exception warns. An audit can always find the weak
  cryptography in use.
- `cryptod.policy.failed`: a policy cryptod couldn't publish as written,
  or one a process couldn't use.
- `cryptod.policy.applied`: each policy cryptod publishes.

Each process reports each use once, so the records show which programs
use what without one for every call. A process is named by the identity
and process ID the kernel recorded when it connected to cryptod.

cryptod also keeps a summary of what's been used, and by whom, since it
started. See the [cryptod reference](~peios/crypto-policy/cryptod-reference).

## When something is wrong

cryptod checks the policy when it publishes it:

- If a setting such as a threshold can't be read, cryptod keeps the policy
  it last published, and records `cryptod.policy.failed`. Falling back to
  defaults could loosen a policy an administrator had tightened.
- If an exception can't apply as written, cryptod drops that exception
  alone, so it allows nothing, publishes the rest, and records why. A
  misspelled entry, such as `md5.hmca`, is the usual cause.

A process uses a copy of the policy only if SYSTEM or cryptod owns it and
nobody else can change it. Otherwise it uses the next copy, or the
defaults, and reports it.

## Limits

- A process that starts before cryptod is listening can't report, so its
  first uses aren't recorded. It still applies the policy.
- A report is attributed to the identity of the reporting thread when it
  connected. A thread that was impersonating a user then is recorded as
  that user. The process ID still identifies the process.
- A process that replaces its primary token keeps the exceptions of the
  token it started with.
- Policy is applied to programs that use libpcrypto and libpssl. A
  program with cryptography of its own, or a statically linked copy of
  another library, is outside it.
