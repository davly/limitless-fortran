!> limitless_kat -- KAT-1 cross-substrate parity assertion (cohort-canonical Fortran SDK).
!>
!> Exposes the R151 KAT-1 anchor constants + assert_kat1_parity() for use as
!> a boot-time parity gate.
!>
!> R151 KAT-AS-COHORT-INVARIANT-CROSS-SUBSTRATE-PIN: the canonical hex
!>     239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca
!> is the cohort firewall pin. assert_kat1_parity stops with non-zero status
!> on drift.
!>
!> KAT-1 inputs:
!>   - input bytes: 0x01 || 32 x 0x00  (33 bytes)
!>   - HMAC key:    empty
!>   - expected:    HMAC-SHA256 hex above
!>
!> Reproducible offline (no Fortran toolchain involved):
!>
!>     printf '\x01' > /tmp/kat1.bin
!>     printf '\x00%.0s' {1..32} >> /tmp/kat1.bin
!>     openssl dgst -sha256 -mac hmac -macopt key: /tmp/kat1.bin

module limitless_kat
    use iso_fortran_env, only: int8
    use limitless_sha256, only: hmac_sha256
    implicit none
    private

    public :: KAT1_DIGEST_HEX
    public :: KAT1_MARK
    public :: kat1_input
    public :: assert_kat1_parity

    !> KAT-1 HMAC-SHA256 hex digest -- cohort cross-substrate firewall.
    !> Byte-identical to foundation/pkg/mirrormark.KAT1Digest.
    character(len=64), parameter :: KAT1_DIGEST_HEX = &
        "239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca"

    !> KAT-1 mark string -- byte-identical to foundation/pkg/mirrormark.KAT1Mark.
    character(len=62), parameter :: KAT1_MARK = &
        "lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg"

contains

    !> Return KAT-1 input bytes: 0x01 followed by 32 x 0x00.
    function kat1_input() result(buf)
        integer(int8) :: buf(33)
        buf = 0_int8
        buf(1) = int(z'01', int8)
    end function kat1_input

    !> Verify the KAT-1 anchor reproduces. Stops with status 1 on drift.
    !>
    !> A regulator with `openssl dgst` and the canonical hex can verify the
    !> property holds WITHOUT any Limitless toolchain. assert_kat1_parity
    !> tells the regulator the local Fortran build agrees.
    subroutine assert_kat1_parity()
        integer(int8) :: key(0)
        integer(int8) :: input(33)
        integer(int8) :: digest(32)
        character(len=64) :: hex_out
        character(len=2) :: hex_byte
        integer :: i

        input = kat1_input()
        call hmac_sha256(key, input, digest)

        hex_out = ''
        do i = 1, 32
            write(hex_byte, '(z2.2)') iand(int(digest(i)), 255)
            ! Lowercase the hex.
            call to_lower(hex_byte)
            hex_out((i - 1) * 2 + 1 : i * 2) = hex_byte
        end do

        if (hex_out /= KAT1_DIGEST_HEX) then
            print *, 'limitless_kat: L43 Mirror-Mark KAT-1 drift detected: got '
            print *, '  ', hex_out
            print *, '  expected ', KAT1_DIGEST_HEX
            print *, 'This breaks cohort parity with pulse / baseline / foundry / oracle / iris.'
            stop 1
        end if
    end subroutine assert_kat1_parity

    !> Lowercase a 2-char hex byte in place.
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

end module limitless_kat
