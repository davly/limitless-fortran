!> limitless_honest -- R143 LOUD-ONCE-WARNING-FLAG primitive (cohort-canonical Fortran SDK).
!>
!> Fortran 2008 port of the R143 LOUD-ONCE-WARNING-FLAG pattern shipped
!> across the Go cohort, every Python flagship, the Erlang
!> `limitless_beam_loud_once`, and the TS / D / Crystal / R cohort siblings.
!>
!> R143 contract:
!>   - First emission for a given code: write the formatted advisory, return .true.
!>   - Subsequent emissions for the same code: silent, return .false.
!>   - loud_once_reset() re-arms emission (test-only).
!>
!> R143.A SEVERITY-LADDER-CONVENTION: closed-set severity vocabulary.
!>
!> R145.B SIBLING-NOT-STACKED: primitive only; no per-flagship advisories.
!>
!> Cohort literal pin: '[LOUD-ONCE-WARNING]' is byte-identical to every adopter.

module limitless_honest
    use iso_fortran_env, only: output_unit, error_unit
    implicit none
    private

    public :: LOUD_ONCE_PREFIX
    public :: SEV_INFO, SEV_WARN, SEV_ERROR, SEV_CRITICAL
    public :: severity_label, severity_rank
    public :: Advisory
    public :: loud_once
    public :: loud_once_reset
    public :: loud_once_has_emitted
    public :: loud_once_cardinality
    public :: loud_once_set_host_prefix

    !> Cohort-canonical line prefix for every emission. Byte-identical to
    !> every cohort adopter (Go LoudOncePrefix, Python LOUD_ONCE_PREFIX,
    !> Erlang loud_once_prefix, ...).
    character(len=*), parameter :: LOUD_ONCE_PREFIX = "[LOUD-ONCE-WARNING]"

    !> R143.A severity ladder. Integer-coded for Fortran.
    integer, parameter :: SEV_INFO     = 0
    integer, parameter :: SEV_WARN     = 1
    integer, parameter :: SEV_ERROR    = 2
    integer, parameter :: SEV_CRITICAL = 3

    !> A single boot-time advisory.
    type, public :: Advisory
        character(len=:), allocatable :: code
        integer :: severity = SEV_WARN
        character(len=:), allocatable :: message
        character(len=:), allocatable :: doc_link
    end type Advisory

    ! Module-level state. Saved across calls; not thread-safe (Fortran has
    ! no module-level synchronization without OpenMP). Cohort discipline:
    ! call loud_once from the host's main boot phase only.
    integer, parameter :: MAX_SEEN_CODES = 256
    character(len=128), save :: seen_codes(MAX_SEEN_CODES) = ' '
    integer, save :: n_seen = 0
    character(len=64), save :: host_prefix = 'limitless'

contains

    function severity_label(sev) result(label)
        integer, intent(in) :: sev
        character(len=:), allocatable :: label
        select case (sev)
        case (SEV_INFO);     label = 'INFO'
        case (SEV_WARN);     label = 'WARN'
        case (SEV_ERROR);    label = 'ERROR'
        case (SEV_CRITICAL); label = 'CRITICAL'
        case default;        label = 'UNKNOWN'
        end select
    end function severity_label

    pure function severity_rank(sev) result(rank)
        integer, intent(in) :: sev
        integer :: rank
        rank = sev
    end function severity_rank

    subroutine loud_once_set_host_prefix(prefix)
        character(len=*), intent(in) :: prefix
        host_prefix = ' '
        host_prefix = prefix
    end subroutine loud_once_set_host_prefix

    !> Emit advisory iff first emission for its code. Returns .true. on first
    !> emission, .false. on subsequent.
    !>
    !> Default sink is error_unit (stderr). Pass an explicit `out_unit` to
    !> redirect (useful in tests).
    function loud_once(adv, out_unit) result(emitted)
        type(Advisory), intent(in) :: adv
        integer, intent(in), optional :: out_unit
        logical :: emitted
        integer :: unit
        integer :: i

        ! Check seen.
        do i = 1, n_seen
            if (trim(seen_codes(i)) == adv%code) then
                emitted = .false.
                return
            end if
        end do

        ! Add to seen (if room).
        if (n_seen < MAX_SEEN_CODES) then
            n_seen = n_seen + 1
            seen_codes(n_seen) = ' '
            seen_codes(n_seen) = adv%code
        end if

        if (present(out_unit)) then
            unit = out_unit
        else
            unit = error_unit
        end if

        write(unit, '(a)') trim(host_prefix) // ' ' // LOUD_ONCE_PREFIX // ' ' // &
                           severity_label(adv%severity) // ' ' // &
                           adv%code // ': ' // adv%message // ' (see ' // adv%doc_link // ')'

        emitted = .true.
    end function loud_once

    !> Test-only: reset the once registry.
    subroutine loud_once_reset()
        seen_codes = ' '
        n_seen = 0
        host_prefix = 'limitless'
    end subroutine loud_once_reset

    function loud_once_has_emitted(code) result(seen)
        character(len=*), intent(in) :: code
        logical :: seen
        integer :: i
        seen = .false.
        do i = 1, n_seen
            if (trim(seen_codes(i)) == code) then
                seen = .true.
                return
            end if
        end do
    end function loud_once_has_emitted

    function loud_once_cardinality() result(count)
        integer :: count
        count = n_seen
    end function loud_once_cardinality

end module limitless_honest
