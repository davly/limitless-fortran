!> limitless_sha256 -- pure Fortran 2008 SHA-256 + HMAC-SHA256
!>
!> FIPS PUB 180-4 SHA-256 + RFC 2104 HMAC, expressed in pure Fortran 2008
!> using iso_fortran_env. Zero external dependencies.
!>
!> This is the cohort-canonical Fortran HMAC-SHA256 substrate-native
!> implementation per R157 SUBSTRATE-NATIVE-IDIOM-OVER-LITERAL-TRANSLATION.
!> Tested via the KAT-1 firewall in test_mirrormark.f90.
!>
!> Author: David Carson 2026.  License: Apache-2.0.

module limitless_sha256
    use iso_fortran_env, only: int8, int32, int64
    implicit none
    private

    public :: sha256_digest
    public :: hmac_sha256
    public :: SHA256_DIGEST_SIZE
    public :: SHA256_BLOCK_SIZE

    integer, parameter :: SHA256_DIGEST_SIZE = 32
    integer, parameter :: SHA256_BLOCK_SIZE = 64

    ! SHA-256 K constants (FIPS 180-4 4.2.2).
    integer(int32), parameter :: K(0:63) = [ &
        int(z'428a2f98', int32), int(z'71374491', int32), int(z'b5c0fbcf', int32), int(z'e9b5dba5', int32), &
        int(z'3956c25b', int32), int(z'59f111f1', int32), int(z'923f82a4', int32), int(z'ab1c5ed5', int32), &
        int(z'd807aa98', int32), int(z'12835b01', int32), int(z'243185be', int32), int(z'550c7dc3', int32), &
        int(z'72be5d74', int32), int(z'80deb1fe', int32), int(z'9bdc06a7', int32), int(z'c19bf174', int32), &
        int(z'e49b69c1', int32), int(z'efbe4786', int32), int(z'0fc19dc6', int32), int(z'240ca1cc', int32), &
        int(z'2de92c6f', int32), int(z'4a7484aa', int32), int(z'5cb0a9dc', int32), int(z'76f988da', int32), &
        int(z'983e5152', int32), int(z'a831c66d', int32), int(z'b00327c8', int32), int(z'bf597fc7', int32), &
        int(z'c6e00bf3', int32), int(z'd5a79147', int32), int(z'06ca6351', int32), int(z'14292967', int32), &
        int(z'27b70a85', int32), int(z'2e1b2138', int32), int(z'4d2c6dfc', int32), int(z'53380d13', int32), &
        int(z'650a7354', int32), int(z'766a0abb', int32), int(z'81c2c92e', int32), int(z'92722c85', int32), &
        int(z'a2bfe8a1', int32), int(z'a81a664b', int32), int(z'c24b8b70', int32), int(z'c76c51a3', int32), &
        int(z'd192e819', int32), int(z'd6990624', int32), int(z'f40e3585', int32), int(z'106aa070', int32), &
        int(z'19a4c116', int32), int(z'1e376c08', int32), int(z'2748774c', int32), int(z'34b0bcb5', int32), &
        int(z'391c0cb3', int32), int(z'4ed8aa4a', int32), int(z'5b9cca4f', int32), int(z'682e6ff3', int32), &
        int(z'748f82ee', int32), int(z'78a5636f', int32), int(z'84c87814', int32), int(z'8cc70208', int32), &
        int(z'90befffa', int32), int(z'a4506ceb', int32), int(z'bef9a3f7', int32), int(z'c67178f2', int32) ]

    ! Initial hash values (FIPS 180-4 5.3.3).
    integer(int32), parameter :: H_INIT(8) = [ &
        int(z'6a09e667', int32), int(z'bb67ae85', int32), int(z'3c6ef372', int32), int(z'a54ff53a', int32), &
        int(z'510e527f', int32), int(z'9b05688c', int32), int(z'1f83d9ab', int32), int(z'5be0cd19', int32) ]

contains

    !> SHA-256 digest. data is an int8 array; out_digest is 32 bytes.
    subroutine sha256_digest(data, out_digest)
        integer(int8), intent(in)  :: data(:)
        integer(int8), intent(out) :: out_digest(SHA256_DIGEST_SIZE)

        integer(int32) :: H(8)
        integer(int8), allocatable :: padded(:)
        integer(int64) :: msg_len_bits
        integer :: pad_zeros, total_len_bytes, num_blocks
        integer :: blk, i

        H = H_INIT

        msg_len_bits = int(size(data), int64) * 8_int64
        ! Padding: 1 byte 0x80, then zeros, then 8 bytes length (big-endian).
        ! Pad to align after appending 9 bytes (0x80 + length) to multiple of 64.
        pad_zeros = mod(56 - mod(size(data) + 1, 64) + 64, 64)
        total_len_bytes = size(data) + 1 + pad_zeros + 8
        allocate(padded(total_len_bytes))
        padded = 0_int8
        do i = 1, size(data)
            padded(i) = data(i)
        end do
        padded(size(data) + 1) = int(z'80', int8)
        ! Big-endian 64-bit length at end.
        do i = 0, 7
            padded(total_len_bytes - i) = int(iand(ishft(msg_len_bits, -8 * i), 255_int64), int8)
        end do

        num_blocks = total_len_bytes / 64
        do blk = 0, num_blocks - 1
            call sha256_compress(H, padded(blk * 64 + 1 : blk * 64 + 64))
        end do

        ! Output H as big-endian 32 bytes.
        do i = 1, 8
            out_digest((i - 1) * 4 + 1) = int(iand(ishft(H(i), -24), 255), int8)
            out_digest((i - 1) * 4 + 2) = int(iand(ishft(H(i), -16), 255), int8)
            out_digest((i - 1) * 4 + 3) = int(iand(ishft(H(i), -8),  255), int8)
            out_digest((i - 1) * 4 + 4) = int(iand(H(i),              255), int8)
        end do

        deallocate(padded)
    end subroutine sha256_digest

    !> Compress one 64-byte block into the hash state.
    subroutine sha256_compress(state, block)
        integer(int32), intent(inout) :: state(8)
        integer(int8),  intent(in)    :: block(64)

        integer(int32) :: W(0:63)
        integer(int32) :: wa, wb, wc, wd, we, wf, wg, wh
        integer(int32) :: T1, T2
        integer :: t

        ! Prepare message schedule: first 16 words from block (big-endian).
        do t = 0, 15
            W(t) = ior(ior(ior( &
                ishft(iand(int(block(t * 4 + 1), int32), 255), 24), &
                ishft(iand(int(block(t * 4 + 2), int32), 255), 16)), &
                ishft(iand(int(block(t * 4 + 3), int32), 255), 8)), &
                       iand(int(block(t * 4 + 4), int32), 255))
        end do
        do t = 16, 63
            W(t) = sigma1(W(t - 2)) + W(t - 7) + sigma0(W(t - 15)) + W(t - 16)
        end do

        wa = state(1); wb = state(2); wc = state(3); wd = state(4)
        we = state(5); wf = state(6); wg = state(7); wh = state(8)

        do t = 0, 63
            T1 = wh + bigsigma1(we) + ch(we, wf, wg) + K(t) + W(t)
            T2 = bigsigma0(wa) + maj(wa, wb, wc)
            wh = wg; wg = wf; wf = we
            we = wd + T1
            wd = wc; wc = wb; wb = wa
            wa = T1 + T2
        end do

        state(1) = state(1) + wa
        state(2) = state(2) + wb
        state(3) = state(3) + wc
        state(4) = state(4) + wd
        state(5) = state(5) + we
        state(6) = state(6) + wf
        state(7) = state(7) + wg
        state(8) = state(8) + wh
    end subroutine sha256_compress

    pure function ch(x, y, z) result(r)
        integer(int32), intent(in) :: x, y, z
        integer(int32) :: r
        r = ieor(iand(x, y), iand(not(x), z))
    end function ch

    pure function maj(x, y, z) result(r)
        integer(int32), intent(in) :: x, y, z
        integer(int32) :: r
        r = ieor(ieor(iand(x, y), iand(x, z)), iand(y, z))
    end function maj

    pure function bigsigma0(x) result(r)
        integer(int32), intent(in) :: x
        integer(int32) :: r
        r = ieor(ieor(rotr(x, 2), rotr(x, 13)), rotr(x, 22))
    end function bigsigma0

    pure function bigsigma1(x) result(r)
        integer(int32), intent(in) :: x
        integer(int32) :: r
        r = ieor(ieor(rotr(x, 6), rotr(x, 11)), rotr(x, 25))
    end function bigsigma1

    pure function sigma0(x) result(r)
        integer(int32), intent(in) :: x
        integer(int32) :: r
        r = ieor(ieor(rotr(x, 7), rotr(x, 18)), shr(x, 3))
    end function sigma0

    pure function sigma1(x) result(r)
        integer(int32), intent(in) :: x
        integer(int32) :: r
        r = ieor(ieor(rotr(x, 17), rotr(x, 19)), shr(x, 10))
    end function sigma1

    pure function rotr(x, n) result(r)
        integer(int32), intent(in) :: x
        integer, intent(in) :: n
        integer(int32) :: r
        r = ior(ishft(iand(x, int(z'FFFFFFFF', int32)), -n), &
                ishft(x, 32 - n))
        r = iand(r, int(z'FFFFFFFF', int32))
    end function rotr

    pure function shr(x, n) result(r)
        integer(int32), intent(in) :: x
        integer, intent(in) :: n
        integer(int32) :: r
        r = ishft(iand(x, int(z'FFFFFFFF', int32)), -n)
    end function shr

    !> HMAC-SHA256(key, data). Output is 32 bytes (int8 array).
    !> Empty key supported (KAT-1 vector).
    subroutine hmac_sha256(key, data, out_digest)
        integer(int8), intent(in)  :: key(:)
        integer(int8), intent(in)  :: data(:)
        integer(int8), intent(out) :: out_digest(SHA256_DIGEST_SIZE)

        integer(int8) :: k_pad(SHA256_BLOCK_SIZE)
        integer(int8) :: o_key_pad(SHA256_BLOCK_SIZE)
        integer(int8) :: i_key_pad(SHA256_BLOCK_SIZE)
        integer(int8), allocatable :: inner_input(:)
        integer(int8) :: inner_digest(SHA256_DIGEST_SIZE)
        integer(int8), allocatable :: outer_input(:)
        integer :: i

        k_pad = 0_int8

        ! If key > block size, hash it first.
        if (size(key) > SHA256_BLOCK_SIZE) then
            call sha256_digest(key, k_pad(1:SHA256_DIGEST_SIZE))
            ! Remaining bytes already zero.
        else
            do i = 1, size(key)
                k_pad(i) = key(i)
            end do
        end if

        ! Build outer + inner key pads.
        do i = 1, SHA256_BLOCK_SIZE
            o_key_pad(i) = ieor(k_pad(i), int(z'5c', int8))
            i_key_pad(i) = ieor(k_pad(i), int(z'36', int8))
        end do

        ! Inner: SHA-256(i_key_pad || data)
        allocate(inner_input(SHA256_BLOCK_SIZE + size(data)))
        do i = 1, SHA256_BLOCK_SIZE
            inner_input(i) = i_key_pad(i)
        end do
        do i = 1, size(data)
            inner_input(SHA256_BLOCK_SIZE + i) = data(i)
        end do
        call sha256_digest(inner_input, inner_digest)
        deallocate(inner_input)

        ! Outer: SHA-256(o_key_pad || inner_digest)
        allocate(outer_input(SHA256_BLOCK_SIZE + SHA256_DIGEST_SIZE))
        do i = 1, SHA256_BLOCK_SIZE
            outer_input(i) = o_key_pad(i)
        end do
        do i = 1, SHA256_DIGEST_SIZE
            outer_input(SHA256_BLOCK_SIZE + i) = inner_digest(i)
        end do
        call sha256_digest(outer_input, out_digest)
        deallocate(outer_input)
    end subroutine hmac_sha256

end module limitless_sha256
