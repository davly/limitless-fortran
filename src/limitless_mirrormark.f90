!> limitless_mirrormark -- L43 Mirror-Mark v1 stamping (cohort-canonical Fortran SDK).
!>
!> Fortran 2008 port of the L43 Mirror-Mark v1 HMAC-SHA256-over-canonical-bytes
!> algorithm shipped across the Go cohort + the Python / C++ / .NET / Solidity
!> / Rust / Erlang/OTP / C99 / Gleam / Racket / Idris / D / Crystal / R cohort
!> siblings.
!>
!> Mark format:
!>     "lore@v1:" // base64url(corpusSHA[1:8] // HMAC-SHA256(0x01 // corpusSHA // payload, key))
!>
!> R151 KAT-1 anchor:
!>     239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
!>
!> R-rule alignment:
!>   - R151 KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN  -- KAT-1 hex anchor
!>   - R143 LOUD-ONCE-WARNING-FLAG                       -- placeholder hooks
!>   - R145.B SIBLING-NOT-STACKED                        -- pure primitive
!>   - R157 SUBSTRATE-NATIVE-IDIOM-OVER-LITERAL-TRANSLATION  -- pure F2008 + arrays
!>
!> Zero external dependencies (Fortran 2008 stdlib only).

module limitless_mirrormark
    use iso_fortran_env, only: int8
    use limitless_sha256, only: hmac_sha256, SHA256_DIGEST_SIZE
    implicit none
    private

    public :: MARK_VERSION
    public :: MARK_PREFIX
    public :: MARK_CORPUS_PREFIX_LEN
    public :: MARK_BODY_LEN
    public :: sign_mark, verify_mark, verify_bool
    public :: assemble_mark_buf
    public :: base64url_encode, base64url_decode
    public :: bytes_to_hex, hex_to_bytes
    public :: ERR_OK, ERR_INVALID_CORPUS_LEN, ERR_UNKNOWN_MARK_VERSION
    public :: ERR_MALFORMED_MARK, ERR_CORPUS_MISMATCH, ERR_SIGNATURE_MISMATCH

    integer(int8), parameter :: MARK_VERSION = int(z'01', int8)
    character(len=8), parameter :: MARK_PREFIX = "lore@v1:"
    integer, parameter :: MARK_CORPUS_PREFIX_LEN = 8
    integer, parameter :: MARK_BODY_LEN = MARK_CORPUS_PREFIX_LEN + SHA256_DIGEST_SIZE

    !> Status codes returned by verify_mark (Fortran lacks exception types).
    integer, parameter :: ERR_OK = 0
    integer, parameter :: ERR_INVALID_CORPUS_LEN = 1
    integer, parameter :: ERR_UNKNOWN_MARK_VERSION = 2
    integer, parameter :: ERR_MALFORMED_MARK = 3
    integer, parameter :: ERR_CORPUS_MISMATCH = 4
    integer, parameter :: ERR_SIGNATURE_MISMATCH = 5

    character(len=64), parameter :: B64_ALPHABET = &
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

contains

    !> Compute the canonical Mirror-Mark string for the given inputs.
    !>
    !> Pre-condition: corpus_sha is exactly 32 bytes.
    function sign_mark(corpus_sha, payload, key) result(mark)
        integer(int8), intent(in)   :: corpus_sha(:)
        integer(int8), intent(in)   :: payload(:)
        integer(int8), intent(in)   :: key(:)
        character(len=:), allocatable :: mark

        integer(int8), allocatable :: input(:)
        integer(int8) :: digest(SHA256_DIGEST_SIZE)
        integer(int8) :: body(MARK_BODY_LEN)
        character(len=:), allocatable :: body_b64
        integer :: i

        ! Build HMAC input: 0x01 || corpus_sha || payload
        allocate(input(1 + size(corpus_sha) + size(payload)))
        input(1) = MARK_VERSION
        do i = 1, size(corpus_sha)
            input(1 + i) = corpus_sha(i)
        end do
        do i = 1, size(payload)
            input(1 + size(corpus_sha) + i) = payload(i)
        end do

        call hmac_sha256(key, input, digest)
        deallocate(input)

        ! Assemble body: corpus_sha[1:8] || digest
        do i = 1, MARK_CORPUS_PREFIX_LEN
            body(i) = corpus_sha(i)
        end do
        do i = 1, SHA256_DIGEST_SIZE
            body(MARK_CORPUS_PREFIX_LEN + i) = digest(i)
        end do

        body_b64 = base64url_encode(body)
        mark = MARK_PREFIX // body_b64
    end function sign_mark

    !> Assemble a mark from a 32-byte HMAC digest + corpus_sha (used in tests).
    function assemble_mark_buf(corpus_sha, digest) result(mark)
        integer(int8), intent(in) :: corpus_sha(:)
        integer(int8), intent(in) :: digest(SHA256_DIGEST_SIZE)
        character(len=:), allocatable :: mark
        integer(int8) :: body(MARK_BODY_LEN)
        integer :: i

        do i = 1, MARK_CORPUS_PREFIX_LEN
            body(i) = corpus_sha(i)
        end do
        do i = 1, SHA256_DIGEST_SIZE
            body(MARK_CORPUS_PREFIX_LEN + i) = digest(i)
        end do
        mark = MARK_PREFIX // base64url_encode(body)
    end function assemble_mark_buf

    !> Verify a Mirror-Mark string against (corpus_sha, payload, key).
    !>
    !> Returns ERR_OK (0) on match, ERR_* code on failure.
    function verify_mark(mark, corpus_sha, payload, key) result(status)
        character(len=*), intent(in) :: mark
        integer(int8), intent(in)    :: corpus_sha(:)
        integer(int8), intent(in)    :: payload(:)
        integer(int8), intent(in)    :: key(:)
        integer :: status

        integer(int8), allocatable :: body(:)
        integer(int8), allocatable :: input(:)
        integer(int8) :: expected_digest(SHA256_DIGEST_SIZE)
        integer :: i

        if (size(corpus_sha) /= SHA256_DIGEST_SIZE) then
            status = ERR_INVALID_CORPUS_LEN
            return
        end if
        if (len(mark) < len(MARK_PREFIX)) then
            status = ERR_UNKNOWN_MARK_VERSION
            return
        end if
        if (mark(1:len(MARK_PREFIX)) /= MARK_PREFIX) then
            status = ERR_UNKNOWN_MARK_VERSION
            return
        end if

        body = base64url_decode(mark(len(MARK_PREFIX) + 1 : len(mark)))
        if (.not. allocated(body)) then
            status = ERR_MALFORMED_MARK
            return
        end if
        if (size(body) /= MARK_BODY_LEN) then
            status = ERR_MALFORMED_MARK
            deallocate(body)
            return
        end if

        ! Corpus-prefix compare (constant time).
        if (.not. const_time_equal(body(1:MARK_CORPUS_PREFIX_LEN), &
                                    corpus_sha(1:MARK_CORPUS_PREFIX_LEN))) then
            status = ERR_CORPUS_MISMATCH
            deallocate(body)
            return
        end if

        ! Recompute HMAC and compare digests.
        allocate(input(1 + size(corpus_sha) + size(payload)))
        input(1) = MARK_VERSION
        do i = 1, size(corpus_sha)
            input(1 + i) = corpus_sha(i)
        end do
        do i = 1, size(payload)
            input(1 + size(corpus_sha) + i) = payload(i)
        end do
        call hmac_sha256(key, input, expected_digest)
        deallocate(input)

        if (.not. const_time_equal(body(MARK_CORPUS_PREFIX_LEN + 1 : MARK_BODY_LEN), &
                                    expected_digest)) then
            status = ERR_SIGNATURE_MISMATCH
            deallocate(body)
            return
        end if
        deallocate(body)
        status = ERR_OK
    end function verify_mark

    !> Boolean form of verify_mark.
    function verify_bool(mark, corpus_sha, payload, key) result(ok)
        character(len=*), intent(in) :: mark
        integer(int8), intent(in)    :: corpus_sha(:)
        integer(int8), intent(in)    :: payload(:)
        integer(int8), intent(in)    :: key(:)
        logical :: ok
        ok = (verify_mark(mark, corpus_sha, payload, key) == ERR_OK)
    end function verify_bool

    !> Constant-time byte-equal.
    pure function const_time_equal(a, b) result(ok)
        integer(int8), intent(in) :: a(:)
        integer(int8), intent(in) :: b(:)
        logical :: ok
        integer :: i, diff

        if (size(a) /= size(b)) then
            ok = .false.
            return
        end if
        diff = 0
        do i = 1, size(a)
            diff = ior(diff, ieor(iand(int(a(i)), 255), iand(int(b(i)), 255)))
        end do
        ok = (diff == 0)
    end function const_time_equal

    !> RFC 4648 base64url-no-padding encode of bytes.
    function base64url_encode(data) result(out_str)
        integer(int8), intent(in) :: data(:)
        character(len=:), allocatable :: out_str

        integer :: n, i, out_len, oi
        integer :: v
        character(len=:), allocatable :: buf

        n = size(data)
        if (n == 0) then
            out_str = ''
            return
        end if
        ! Output length = ceil(n*4/3)
        out_len = (n * 4 + 2) / 3
        allocate(character(len=out_len) :: buf)
        oi = 0
        i = 1
        do while (i + 2 <= n)
            v = ior(ior( &
                ishft(iand(int(data(i)),     255), 16), &
                ishft(iand(int(data(i + 1)), 255), 8)), &
                       iand(int(data(i + 2)), 255))
            oi = oi + 1; buf(oi:oi) = B64_ALPHABET(iand(ishft(v, -18), 63) + 1 : iand(ishft(v, -18), 63) + 1)
            oi = oi + 1; buf(oi:oi) = B64_ALPHABET(iand(ishft(v, -12), 63) + 1 : iand(ishft(v, -12), 63) + 1)
            oi = oi + 1; buf(oi:oi) = B64_ALPHABET(iand(ishft(v,  -6), 63) + 1 : iand(ishft(v,  -6), 63) + 1)
            oi = oi + 1; buf(oi:oi) = B64_ALPHABET(iand(v,             63) + 1 : iand(v,             63) + 1)
            i = i + 3
        end do
        ! Tail: 1 or 2 bytes remaining.
        if (i <= n) then
            v = ishft(iand(int(data(i)), 255), 16)
            if (i + 1 <= n) v = ior(v, ishft(iand(int(data(i + 1)), 255), 8))
            oi = oi + 1; buf(oi:oi) = B64_ALPHABET(iand(ishft(v, -18), 63) + 1 : iand(ishft(v, -18), 63) + 1)
            oi = oi + 1; buf(oi:oi) = B64_ALPHABET(iand(ishft(v, -12), 63) + 1 : iand(ishft(v, -12), 63) + 1)
            if (i + 1 <= n) then
                oi = oi + 1; buf(oi:oi) = B64_ALPHABET(iand(ishft(v, -6), 63) + 1 : iand(ishft(v, -6), 63) + 1)
            end if
        end if
        out_str = buf(1:oi)
    end function base64url_encode

    !> RFC 4648 base64url decode; returns allocated array, or unallocated on invalid input.
    function base64url_decode(s) result(data)
        character(len=*), intent(in) :: s
        integer(int8), allocatable :: data(:)

        integer :: inv(0:127)
        integer :: n, full_groups, remainder
        integer :: i, oi, out_len
        integer :: a, b, c, d, v
        integer :: ch

        ! Build inverse table.
        inv = -1
        do i = 1, 64
            inv(iachar(B64_ALPHABET(i:i))) = i - 1
        end do

        n = len(s)
        if (n == 0) then
            allocate(data(0))
            return
        end if
        full_groups = n / 4
        remainder = mod(n, 4)
        if (remainder == 1) return  ! invalid

        out_len = full_groups * 3
        if (remainder >= 2) out_len = out_len + remainder - 1
        allocate(data(out_len))
        oi = 0
        i = 1
        do while (i + 3 <= n)
            ch = iachar(s(i:i));     if (ch < 0 .or. ch > 127) then; deallocate(data); return; end if
            a = inv(ch); if (a < 0) then; deallocate(data); return; end if
            ch = iachar(s(i+1:i+1)); if (ch < 0 .or. ch > 127) then; deallocate(data); return; end if
            b = inv(ch); if (b < 0) then; deallocate(data); return; end if
            ch = iachar(s(i+2:i+2)); if (ch < 0 .or. ch > 127) then; deallocate(data); return; end if
            c = inv(ch); if (c < 0) then; deallocate(data); return; end if
            ch = iachar(s(i+3:i+3)); if (ch < 0 .or. ch > 127) then; deallocate(data); return; end if
            d = inv(ch); if (d < 0) then; deallocate(data); return; end if
            v = ior(ior(ior(ishft(a, 18), ishft(b, 12)), ishft(c, 6)), d)
            oi = oi + 1; data(oi) = int(iand(ishft(v, -16), 255), int8)
            oi = oi + 1; data(oi) = int(iand(ishft(v, -8),  255), int8)
            oi = oi + 1; data(oi) = int(iand(v,             255), int8)
            i = i + 4
        end do
        if (remainder >= 2) then
            ch = iachar(s(i:i));     if (ch < 0 .or. ch > 127) then; deallocate(data); return; end if
            a = inv(ch); if (a < 0) then; deallocate(data); return; end if
            ch = iachar(s(i+1:i+1)); if (ch < 0 .or. ch > 127) then; deallocate(data); return; end if
            b = inv(ch); if (b < 0) then; deallocate(data); return; end if
            v = ior(ishft(a, 18), ishft(b, 12))
            oi = oi + 1; data(oi) = int(iand(ishft(v, -16), 255), int8)
            if (remainder == 3) then
                ch = iachar(s(i+2:i+2)); if (ch < 0 .or. ch > 127) then; deallocate(data); return; end if
                c = inv(ch); if (c < 0) then; deallocate(data); return; end if
                v = ior(v, ishft(c, 6))
                oi = oi + 1; data(oi) = int(iand(ishft(v, -8), 255), int8)
            end if
        end if
    end function base64url_decode

    !> Hex-encode bytes (lowercase, no separator).
    function bytes_to_hex(data) result(hex_str)
        integer(int8), intent(in) :: data(:)
        character(len=:), allocatable :: hex_str
        character(len=2) :: byte_hex
        integer :: i
        allocate(character(len=size(data) * 2) :: hex_str)
        do i = 1, size(data)
            write(byte_hex, '(z2.2)') iand(int(data(i)), 255)
            call to_lower(byte_hex)
            hex_str((i - 1) * 2 + 1 : i * 2) = byte_hex
        end do
    end function bytes_to_hex

    !> Hex-decode lowercase string; returns unallocated on invalid input.
    function hex_to_bytes(hex_str) result(data)
        character(len=*), intent(in) :: hex_str
        integer(int8), allocatable :: data(:)
        integer :: i, hi, lo
        if (mod(len(hex_str), 2) /= 0) return
        allocate(data(len(hex_str) / 2))
        do i = 1, len(hex_str) / 2
            hi = nibble(hex_str((i - 1) * 2 + 1 : (i - 1) * 2 + 1))
            lo = nibble(hex_str(i * 2 : i * 2))
            if (hi < 0 .or. lo < 0) then
                deallocate(data)
                return
            end if
            data(i) = int(ior(ishft(hi, 4), lo), int8)
        end do
    end function hex_to_bytes

    pure function nibble(c) result(v)
        character(len=1), intent(in) :: c
        integer :: v
        if (c >= '0' .and. c <= '9') then
            v = iachar(c) - iachar('0')
        else if (c >= 'a' .and. c <= 'f') then
            v = iachar(c) - iachar('a') + 10
        else if (c >= 'A' .and. c <= 'F') then
            v = iachar(c) - iachar('A') + 10
        else
            v = -1
        end if
    end function nibble

    subroutine to_lower(s)
        character(len=*), intent(inout) :: s
        integer :: i, c
        do i = 1, len(s)
            c = iachar(s(i:i))
            if (c >= iachar('A') .and. c <= iachar('Z')) then
                s(i:i) = achar(c + 32)
            end if
        end do
    end subroutine to_lower

end module limitless_mirrormark
