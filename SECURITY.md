# Security Policy — limitless-fortran

This document is the threat model for **limitless-fortran**, a pure Fortran 2008
SDK that implements the Limitless ecosystem's cohort-canonical cryptographic and
governance primitives:

- `limitless_sha256` — SHA-256 (FIPS PUB 180-4) + HMAC-SHA256 (RFC 2104).
- `limitless_mirrormark` — L43 Mirror-Mark v1 sign/verify over HMAC-SHA256.
- `limitless_kat` — R151 KAT-1 cross-substrate parity anchor.
- `limitless_honest` — R143 LOUD-ONCE-WARNING advisory primitive.
- `limitless_legal` — R166 liability-footer + UK GDPR statutory string constants.

It is written against the source as it stands; it describes what the library
**does** and, equally importantly, what it **does not** do. If you change the
code, please keep this file in sync.

## Reporting a vulnerability

Report suspected vulnerabilities privately to **david@promptboy.dev** (the
maintainer address in `fpm.toml`). Please do not open a public issue for an
unfixed vulnerability. Include a minimal reproducer (input bytes, the expected
vs. observed mark/digest, and your `gfortran`/compiler version). A correctness
defect in SHA-256, HMAC-SHA256, or Mirror-Mark verification is treated as a
security issue, not merely a bug.

## What this library is

A **self-contained, dependency-free** primitive library. It links to **no**
external cryptographic library (no libcrypto / OpenSSL): SHA-256 and
HMAC-SHA256 are implemented in pure Fortran 2008 using `iso_fortran_env`. The
KAT-1 firewall anchor

```
239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

is the HMAC-SHA256 of `0x01 || (32 × 0x00)` under an empty key, and is
independently reproducible with `openssl` (see `README.md`). This anchor is the
cross-substrate parity firewall: a drift here means the Fortran build no longer
agrees byte-for-byte with the Go canonical foundation and the other cohort SDKs.

## Trust boundaries and attack surface

This is a **library**, not a service. It opens no sockets, reads no files, makes
no system calls, and consults no environment variables. The entire attack
surface is the **arguments callers pass to its public procedures**, plus one
text sink:

| Surface | Procedures | Notes |
|---|---|---|
| Mark signing | `sign_mark`, `assemble_mark_buf` | Consume `corpus_sha`, `payload`, `key` byte arrays; return a `lore@v1:` string. |
| Mark verification | `verify_mark`, `verify_bool` | Validate an untrusted mark string against `(corpus_sha, payload, key)`. |
| Hash / HMAC | `sha256_digest`, `hmac_sha256` | Pure functions over `int8` arrays. |
| Encoding | `base64url_encode/decode`, `bytes_to_hex`, `hex_to_bytes` | Parse untrusted text in the decode direction. |
| Advisory text sink | `loud_once` | Formats an `Advisory` and writes it to `error_unit` (stderr) by default, or to a caller-supplied unit. |

The threat actor of concern is an attacker who can influence one or more of
these inputs — most importantly a **mark string presented for verification** —
and wants to either (a) forge an accepted mark without the key, or (b) crash /
mislead the host through a malformed input.

## Security properties the library DOES provide

- **HMAC is the integrity boundary.** A Mirror-Mark binds
  `0x01 || corpus_sha || payload` under the HMAC key. `verify_mark` recomputes
  the HMAC and rejects any mismatch with `ERR_SIGNATURE_MISMATCH`. Forging an
  accepting mark requires the key (modulo the security of HMAC-SHA256).
- **Constant-time digest comparison.** Both the corpus-prefix check and the
  HMAC-digest check use `const_time_equal`, an OR-accumulating compare that does
  not early-exit on the first differing byte, reducing timing-oracle leakage on
  the secret-dependent comparison.
- **Length validation on the verify path.** `verify_mark` rejects a `corpus_sha`
  that is not exactly 32 bytes (`ERR_INVALID_CORPUS_LEN`), a too-short mark and a
  missing/wrong `lore@v1:` prefix (`ERR_UNKNOWN_MARK_VERSION`), and a decoded
  body of the wrong length (`ERR_MALFORMED_MARK`) — before any comparison runs.
- **Defensive base64url / hex decoders.** `base64url_decode`, `hex_to_bytes`
  reject invalid lengths and out-of-alphabet characters and return an
  **unallocated** array rather than partial/garbage output; callers should test
  `allocated(...)`. `verify_mark` already does this and maps the failure to
  `ERR_MALFORMED_MARK`.
- **Explicit, typed failure.** Fortran has no exceptions, so verification surfaces
  a closed set of integer status codes (`ERR_OK`, `ERR_INVALID_CORPUS_LEN`,
  `ERR_UNKNOWN_MARK_VERSION`, `ERR_MALFORMED_MARK`, `ERR_CORPUS_MISMATCH`,
  `ERR_SIGNATURE_MISMATCH`). There is no fail-open path: any code other than
  `ERR_OK` means "do not trust this mark".

## What this library DOES NOT do (caller responsibilities)

- **It is not access control or authentication.** A valid Mirror-Mark proves
  that whoever produced it held the HMAC key over those exact bytes. It does not
  identify a user, authorise an action, or carry an expiry. Those belong to the
  host application.
- **`sign_mark` trusts its `corpus_sha` length.** The documented precondition is
  "`corpus_sha` is exactly 32 bytes". `sign_mark` and `assemble_mark_buf` read
  `corpus_sha(1:8)` for the body prefix and do **not** themselves check the
  length (only `verify_mark` does). Passing a corpus shorter than 8 bytes is a
  caller contract violation and may read out of bounds. **Callers must pass a
  full 32-byte SHA-256 digest.** (Compiling with `-fcheck=bounds` during
  development will catch a violation.)
- **Key management is out of scope.** The library never generates, stores, rotates,
  or zeroises keys. Keys are plain `int8` arrays owned by the caller; Fortran does
  not guarantee secure erasure of stack/heap memory, so a caller handling
  long-lived secrets should manage that itself.
- **No replay or freshness protection.** Marks are deterministic for fixed inputs
  and carry no nonce or timestamp. If replay matters, the host must include a
  nonce/timestamp in the `payload`.
- **It does not transmit anything.** No `payload`, `key`, `corpus_sha`, or
  advisory leaves the process except whatever the host chooses to do with the
  returned strings, and the advisory line `loud_once` writes to its output unit.

## Operational and concurrency notes

- **`loud_once` is not thread-safe.** It keeps module-level `save` state
  (`seen_codes`, `n_seen`, `host_prefix`) with no synchronisation, and the
  registry is capped at `MAX_SEEN_CODES = 256` codes. The cohort discipline is to
  call `loud_once` only from the host's single-threaded boot phase. Concurrent
  calls are a data race, not a memory-safety guarantee. `loud_once_reset` is
  test-only.
- **`loud_once` writes caller-supplied strings to stderr.** The `Advisory`
  `code`, `message`, and `doc_link` are emitted verbatim. Do not place secrets or
  unsanitised attacker-controlled data that should not reach logs into an
  `Advisory`. The default sink is `error_unit`; pass an explicit `out_unit` to
  redirect.
- **The KAT-1 anchor is a parity gate, not a runtime secret.** `assert_kat1_parity`
  stops the program (`stop 1`) on drift. Wire it into boot so that a
  mis-compiled HMAC fails loudly and closed rather than silently producing
  non-canonical marks.

## Sensitive dependencies

**None.** The library depends only on the Fortran 2008 standard library
(`iso_fortran_env`). There is no third-party package, no FFI, and no transitive
supply chain beyond your Fortran compiler and its runtime. Reproduce the KAT-1
anchor offline to gain assurance independent of any Limitless toolchain.

## Supported versions

This SDK tracks the cohort canonical constants (KAT-1 hex, the `lore@v1:` mark
prefix, the `[LOUD-ONCE-WARNING]` line prefix, the `IMPORTANT:` liability-footer
prefix). Security fixes are applied to the latest `main`. The verification suite
(`fpm test`, or compile `test/test_mirrormark.f90` against `src/` with a Fortran
2008 compiler) must remain green; a red KAT-1 firewall is itself a security
signal.
