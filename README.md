# limitless-fortran

Cohort-canonical Fortran 2008 SDK for the Limitless ecosystem.

## What it ships

- **`limitless_sha256`** — pure Fortran 2008 SHA-256 + HMAC-SHA256 (FIPS PUB 180-4 + RFC 2104).
- **`limitless_kat`** — R151 KAT-1 anchor constants + `assert_kat1_parity()`.
- **`limitless_mirrormark`** — L43 Mirror-Mark v1 sign/verify with KAT-1 anchor.
- **`limitless_honest`** — R143 LOUD-ONCE-WARNING-FLAG primitive + Severity vocab.
- **`limitless_legal`** — R166 LIABILITY-FOOTER-CONST + UK GDPR statutory refs.

## R151 KAT-1 cross-substrate firewall

```
239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

Reproducible offline (no Fortran toolchain involved):

```sh
printf '\x01' > /tmp/kat1.bin
printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin
# → HMAC-SHA256(stdin) = 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
```

KAT-1 parity verified locally: 26/26 tests GREEN (gfortran 16.1.0, -std=f2008).

## Install (via fpm)

In your `fpm.toml`:

```toml
[dependencies]
limitless-fortran = { git = "https://github.com/davly/limitless-fortran" }
```

## Use

```fortran
program example
    use iso_fortran_env, only: int8
    use limitless_mirrormark
    use limitless_kat
    use limitless_honest
    implicit none

    integer(int8) :: corpus(32), payload(:), key(:)
    character(len=:), allocatable :: mark
    type(Advisory) :: adv
    logical :: emitted

    ! Boot-time KAT-1 self-test.
    call assert_kat1_parity()

    ! Mirror-Mark
    corpus = 0_int8
    ! ... your lore-corpus SHA-256 ...
    allocate(payload(11), key(13))
    ! ... your bytes ...
    mark = sign_mark(corpus, payload, key)
    if (verify_mark(mark, corpus, payload, key) /= ERR_OK) then
        error stop "mark verification failed"
    end if

    ! LoudOnce host-responsibility advisory
    adv%code = "MY_HOST_NO_DSAR"
    adv%severity = SEV_WARN
    adv%message = "DSAR endpoint not wired"
    adv%doc_link = "docs/dsar.md"
    emitted = loud_once(adv)
end program example
```

## Test

```sh
fpm test
```

26 test assertions across KAT-1 firewall + sign/verify round-trips + error
cases + base64url + hex + Honest + Legal. All GREEN locally.

## License

Apache-2.0. Cohort-canonical literals (KAT-1 hex, `[LOUD-ONCE-WARNING]`,
`IMPORTANT:` alert prefix, `lore@v1:` mark prefix) are byte-aligned with
the Go canonical foundation. Drift = parity fail.

## Notes on Fortran-native idioms (R157)

- HMAC-SHA256 is implemented in pure Fortran 2008 — no link to libcrypto.
  This means the SDK is self-contained and runs on any platform with a
  Fortran 2008 compiler (gfortran, Intel Fortran, NVIDIA HPC SDK, etc.).
- `int8` arrays carry binary data; arrays are 1-indexed per Fortran convention.
- Errors surface as integer status codes (`ERR_*` family) since Fortran
  has no native exception type. `verify_bool` provides the boolean idiom.
- The `Advisory` derived type uses `character(len=:), allocatable` for the
  three string fields per Fortran 2008 idiom; assign with `= "..."`.
