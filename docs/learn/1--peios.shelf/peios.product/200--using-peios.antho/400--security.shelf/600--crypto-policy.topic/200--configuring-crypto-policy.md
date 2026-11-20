---
title: Configuring Crypto Policy
type: how-to
description: Find the weak cryptography in use, tighten the machine's crypto policy, and let a particular service keep an algorithm it needs.
related:
  - peios/crypto-policy/overview
  - peios/crypto-policy/cryptod-reference
  - peios/reading-records/querying-records
---

Tighten the crypto policy in steps: find what would stop working, give the
services that need a weak algorithm an exception, then raise the threshold.
Check the result after each change.

The regman entry for `Machine\System\Cryptography` owns the complete
configuration reference. `evman cryptod` describes the records cryptod
writes.

## Before you start

- Check that cryptod is running: `svctl status cryptod`.
- Obtain write access to `Machine\System\Cryptography`. SYSTEM and
  Administrators have it.
- Obtain read access to cryptod's events in eventd.
- Allow time for the machine to run its normal workload under the current
  policy, so that the records show everything it uses.

## Find the weak cryptography in use

1. List the programs that used an entry below the Warn threshold:

   ```sh
   evctl 'EVENTS cryptod.algorithm.warned SINCE 7d ago'
   ```

   Each record names the entry, its grade, and the process that used it.

2. List the uses of a grade that a new threshold would refuse. For
   example, before refusing everything below C:

   ```sh
   evctl 'EVENTS cryptod.algorithm.warned SINCE 7d ago WHERE object.crypto-algorithm.grade == "U"'
   evctl 'EVENTS cryptod.algorithm.warned SINCE 7d ago WHERE object.crypto-algorithm.grade == "D"'
   ```

3. List the exceptions in use, and by which programs:

   ```sh
   evctl 'EVENTS cryptod.exception.used SINCE 7d ago'
   ```

Every program in these results would fail to use its entry under the new
threshold, unless it has an exception. A program that calls a low-level
digest function, such as `SHA256` or `MD5_Init`, for a refused entry
ends.

## Let a service keep an algorithm

Give an exception to a service that must keep using an entry, such as a
RADIUS server that needs HMAC-MD5. Grant it to the service's own SID, so
that no other program gets it.

1. Find the service's SID. Read its main process ID from
   `svctl status <service>`, then list that process's token groups:

   ```sh
   token groups --pid <pid>
   ```

   The service SID is the group that begins `S-1-5-80-`.

2. Create the exception, named for its owner and purpose. This one allows
   HMAC-MD5 for one service:

   ```sh
   reg set -p Machine/System/Cryptography/Exceptions/Example.LegacyRadius \
       Algorithms multi:md5.hmac
   reg set Machine/System/Cryptography/Exceptions/Example.LegacyRadius \
       ProgramSecurity 'sz:D:(A;;0x1;;;S-1-5-80-<service SID>)'
   ```

   Name each entry as an algorithm and an operation. `md5.hmac` doesn't
   allow `md5.digest`.

3. Check that cryptod published it, and didn't drop it:

   ```sh
   evctl 'EVENTS cryptod.policy.* SINCE 10m ago'
   ```

   A `cryptod.policy.failed` record naming the exception says why it was
   dropped. A dropped exception allows nothing.

4. Restart the service, so that it reads the new policy:

   ```sh
   svctl restart <service>
   ```

## Raise the reject threshold

1. Set the lowest grade the policy allows. This refuses everything graded
   U or D:

   ```sh
   reg set Machine/System/Cryptography/Reject MinimumGrade sz:C
   ```

2. Check that cryptod published the policy, as above. If a
   `cryptod.policy.failed` record says a setting is invalid, cryptod kept
   the previous policy: correct the value and check again.

3. Restart the services that should take up the new policy. Processes
   started from now on use it; running ones keep the policy they started
   with.

To refuse everything FIPS 140-3 doesn't approve, whatever its grade, set
`Reject\FIPS` to 1:

```sh
reg set Machine/System/Cryptography/Reject FIPS dword:1
```

## Check the result

Watch for refusals and new warnings after the change:

```sh
evctl 'EVENTS cryptod.* SINCE 1h ago'
```

A program refused an algorithm reports an error from its own calls, such
as a failed TLS handshake with an `insufficient_security` alert. If a
service stops working, give it an exception or lower the threshold, then
restart it.

To undo a change, set the value back, or delete it to return to Peios's
default, then restart the affected services:

```sh
reg del Machine/System/Cryptography/Reject MinimumGrade
```
