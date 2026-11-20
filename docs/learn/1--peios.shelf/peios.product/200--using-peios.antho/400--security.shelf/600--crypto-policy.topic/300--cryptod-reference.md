---
title: cryptod Reference
type: reference
description: The files and sockets of cryptod, the crypto policy service, the policy file's format, the rules a process uses to trust it, and the reports and posture cryptod handles.
related:
  - peios/crypto-policy/overview
  - peios/crypto-policy/configuring-crypto-policy
---

cryptod compiles `Machine\System\Cryptography` into the policy file that
libpcrypto reads, and records what processes report of their weak
cryptography. Its configuration is documented by regman, and its records
by evman.

## Service

| Property | Value |
|---|---|
| Service | `cryptod` |
| Program | `/usr/sbin/cryptod` |
| Identity | `Service`: its own SID, `S-1-5-80-2691053820-547492864-353945177-641201782-1210658655` |
| Privileges | `SeChangeNotifyPrivilege`, `SeAuditPrivilege` |
| Readiness | Notify, once it has published the policy and is listening |
| Event root | `cryptod` |

cryptod must run as its own service SID. Processes trust a policy copy only
if SYSTEM or that SID owns it, and a file cryptod writes is owned by its
token's user.

## Files and sockets

| Path | What it is |
|---|---|
| `/run/cryptod/policy` | The current policy |
| `/var/state/cryptod/policy` | The policy kept across reboots, for processes that start before cryptod |
| `/run/cryptod/report` | Where processes report, a `SOCK_SEQPACKET` socket everyone can connect to |
| `/run/cryptod/posture` | Where the posture is served, a `SOCK_STREAM` socket for SYSTEM and Administrators |
| `/usr/share/peios-crypto/algorithms.tsv` | Every graded entry, which cryptod checks policies against |

A process reads `/run/cryptod/policy`, then `/var/state/cryptod/policy`,
then uses Peios's defaults: refuse only the floor, warn below C, FIPS
ignored, exceptions allowed to override refusal. It moves to the next if a
copy is absent or can't be used, and reports why.

cryptod writes each copy whole: to a new file beside it, which it gives
the copy's descriptor, then renames over the copy. Each copy's descriptor
is protected, grants full access to SYSTEM and cryptod, and grants reading
to Everyone, `S-1-15-2-1` and `S-1-15-2-2`, so that confined applications
can read it too. Both directories grant the same readers traversal.

`algorithms.tsv` has one line per entry: its identifier, its grade or
`floor`, and `1` or `0` for whether FIPS 140-3 approves it, separated by
tabs. cryptod doesn't start without it.

## Trusting a copy

A process uses a copy only if its descriptor shows that nobody but SYSTEM
and cryptod could have written it:

- Its owner is SYSTEM or cryptod's SID.
- It has a DACL. A copy with none lets everyone change it.
- No entry of the DACL grants anyone else a right that could change the
  file: writing or appending data, writing extended attributes or
  attributes, deleting it, changing its descriptor or owner, or a generic
  or maximum-allowed right that includes them. Entries that deny, and
  entries that only pass to children, are ignored.

The check fails closed. A descriptor over 4 KiB, or an entry granting
CREATOR OWNER a right to change the file, is refused as insecure, even
where it would be harmless. A process that refuses a copy reports
`copy-insecure`.

## The policy file

The file is version 1 of a binary format, at most 1 MiB less one byte.
Integers are big-endian. A process reads the whole file before using any
of it, and refuses a file of another version.

| Field | Size | Meaning |
|---|---|---|
| Magic | 8 bytes | `PEIOSCPL` |
| Version | 2 | 1 |
| Reject below | 1 | A grade: 0 for U, then 1 to 4 for D to A |
| Warn below | 1 | A grade, as above |
| Flags | 1 | `0x01` reject non-FIPS, `0x02` warn non-FIPS, `0x04` exceptions can override refusal |
| Exception count | 2 | The number of exceptions that follow |

Each exception follows in turn:

| Field | Size | Meaning |
|---|---|---|
| Name | 1-byte length, then the name | `Owner.Purpose` |
| Flags | 1 | `0x01` warn about its use |
| ProgramSecurity | 2-byte length, then the descriptor | A self-relative security descriptor |
| Entry count | 2 | The number of entries that follow |
| Entries | each a 1-byte length, then the identifier | Such as `md5.hmac` |

cryptod resolves `Exceptions\Enabled`, `WarnByDefault` and `WarnAlways`
as it compiles, so the file holds only what applies. It leaves out
exceptions it dropped. A process ignores an entry it doesn't grade, and
any entry on the floor.

## Reports

A process connects to `/run/cryptod/report`, sends one datagram, and
closes. It doesn't wait, and doesn't retry: a report that can't be sent is
lost. A datagram has four fields:

| Field | Size | Meaning |
|---|---|---|
| Kind | 1 | 1 warned, 2 exception used, 3 policy copy unusable |
| Problem | 1 | For kind 3, why; otherwise 0 |
| Entry | 1-byte length, then the identifier | For kinds 1 and 2; otherwise empty |
| Exception | 1-byte length, then the name | For kind 2; otherwise empty |

The problems are 1 unreadable, 2 insecure, 3 malformed, 4 an unknown
version, and 5 the process's token unreadable.

cryptod takes the sender's identity from the connection: the user of the
token the kernel captured at connect, and the process ID. Nothing in the
datagram names the sender. cryptod discards a datagram that libpcrypto
couldn't have sent, such as one naming an entry it doesn't grade.

## Rates

cryptod relays at most 512 reports at once from each user, then 8 a
second. It writes its records at up to 80 a second, below the lowest rate
KMES allows a process without `SeTcbPrivilege`, and queues up to 4096
records when more arrive. A full queue drops its oldest standard record to
make room, and turns a record away only when everything it holds is
essential. The posture counts what's turned away.

## Posture

Connecting to `/run/cryptod/posture` returns one MessagePack map, then the
connection closes. It describes the policy in force, and what's been used
since cryptod started:

| Key | Value |
|---|---|
| `policy` | The thresholds, flags, and exceptions in force; `dropped`, the exceptions dropped and why; `defaults`; and `last-failure`, a compile that failed since, or nil |
| `fips` | `requested`; `approved-mode`, always false while the module isn't validated; `reasons`; and `exceptions-admitting-non-fips` |
| `use` | One map per user SID: the exceptions it used, by entry, and the entries it was warned about, each with a count of reports |
| `turned-away` | Counts of reports `rate-limited`, `unattributed`, and `invalid`, and `overflow`: what didn't fit the queue or a table |

The posture is held in memory, so it starts again when cryptod restarts.
Its tables are bounded, at 4096 users and 256 exceptions each.
