!> Test suite for limitless-fortran.
!>
!> Run: `fpm test`
!>
!> Minimum 15 test cases per scope requirement.
!>
!> R151 KAT-1 cross-substrate firewall: assert_kat1_parity must reproduce the
!> canonical hex 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca.
!>
!> The fpm test runner expects program units that stop with non-zero status
!> on failure. We use a small assertion harness plus a final summary.

program test_mirrormark
    use iso_fortran_env, only: int8, error_unit
    use limitless_sha256
    use limitless_kat
    use limitless_mirrormark
    use limitless_honest
    use limitless_legal
    implicit none

    integer :: n_tests = 0
    integer :: n_failed = 0

    print *, '== limitless-fortran test suite =='

    ! -----------------------------------------------------------------------
    ! KAT-1 cohort firewall (R151)
    ! -----------------------------------------------------------------------
    call run('KAT-1 hex literal cohort firewall', test_01_kat1_hex_literal())
    call run('KAT-1 mark literal cohort firewall', test_02_kat1_mark_literal())
    call run('assert_kat1_parity reproduces hex', test_03_assert_kat1_parity())
    call run('sign with KAT-1 inputs produces KAT-1 mark', test_04_sign_kat1())
    call run('verify_mark accepts KAT-1 mark', test_05_verify_kat1())
    call run('verify_bool round-trips KAT-1', test_06_verify_bool_kat1())

    ! -----------------------------------------------------------------------
    ! Sign/verify round-trip
    ! -----------------------------------------------------------------------
    call run('Sign/verify round-trip with random-ish inputs', test_07_round_trip())
    call run('Verify rejects tampered payload', test_08_tampered_payload())
    call run('Verify rejects wrong key', test_09_wrong_key())
    call run('Verify rejects wrong corpus', test_10_wrong_corpus())

    ! -----------------------------------------------------------------------
    ! Errors
    ! -----------------------------------------------------------------------
    call run('Sign returns invalid-corpus-len for short corpus', test_11_invalid_corpus_len())
    call run('Verify returns unknown-version for missing prefix', test_12_unknown_version())
    call run('Verify returns malformed for short body', test_13_malformed())

    ! -----------------------------------------------------------------------
    ! Base64url + hex
    ! -----------------------------------------------------------------------
    call run('base64url round-trip', test_14_base64url_round_trip())
    call run('Hex round-trip', test_15_hex_round_trip())

    ! -----------------------------------------------------------------------
    ! Honest (R143)
    ! -----------------------------------------------------------------------
    call run('LOUD_ONCE_PREFIX cohort literal', test_16_loud_once_prefix())
    call run('Severity ladder ordering', test_17_severity_ladder())
    call run('Severity labels SCREAMING form', test_18_severity_labels())

    ! -----------------------------------------------------------------------
    ! Legal (R166 + R150 + R154)
    ! -----------------------------------------------------------------------
    call run('DEFAULT_REVIEWED_BY_COUNSEL honest-default false', test_19_default_reviewed())
    call run('REF_UK_GDPR_ARTICLE_9 cohort literal', test_20_article_9_ref())
    call run('valid_document_id accepts 5 canonical slugs', test_21_document_ids())
    call run('compute_body_hash empty string', test_22_compute_body_hash_empty())
    call run('legal_config_configured rejects empty fields', test_23_config_empty())
    call run('legal_config_configured accepts fully-populated', test_24_config_populated())
    call run('acceptance_key cohort pipe-delimited form', test_25_acceptance_key())
    call run('DEFAULT_PLACEHOLDER_ALERT begins IMPORTANT:', test_26_placeholder_alert())

    ! -----------------------------------------------------------------------
    ! Summary
    ! -----------------------------------------------------------------------
    print *, ''
    write(*, '(a,i0,a,i0,a)') '== Results: ', n_tests - n_failed, ' / ', n_tests, ' passed =='
    if (n_failed > 0) then
        write(error_unit, '(a,i0,a)') 'FAIL: ', n_failed, ' tests failed'
        stop 1
    end if
    print *, 'ALL GREEN'

contains

    subroutine run(name, ok)
        character(len=*), intent(in) :: name
        logical, intent(in) :: ok
        n_tests = n_tests + 1
        if (ok) then
            write(*, '(a,a)') '  PASS  ', name
        else
            n_failed = n_failed + 1
            write(*, '(a,a)') '  FAIL  ', name
        end if
    end subroutine run

    ! ---- tests ----

    function test_01_kat1_hex_literal() result(ok)
        logical :: ok
        ok = (KAT1_DIGEST_HEX == &
              '239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca')
    end function test_01_kat1_hex_literal

    function test_02_kat1_mark_literal() result(ok)
        logical :: ok
        ok = (KAT1_MARK == 'lore@v1:AAAAAAAAAAAjmn0NPxu-Opiu3gHirYGMLbYLcXfALi8BUDWytbfbyg')
    end function test_02_kat1_mark_literal

    function test_03_assert_kat1_parity() result(ok)
        logical :: ok
        ! assert_kat1_parity will stop on drift; if we reach here, it passed.
        call assert_kat1_parity()
        ok = .true.
    end function test_03_assert_kat1_parity

    function test_04_sign_kat1() result(ok)
        logical :: ok
        integer(int8) :: corpus(32), payload(0), key(0)
        character(len=:), allocatable :: mark
        corpus = 0_int8
        mark = sign_mark(corpus, payload, key)
        ok = (mark == KAT1_MARK)
    end function test_04_sign_kat1

    function test_05_verify_kat1() result(ok)
        logical :: ok
        integer(int8) :: corpus(32), payload(0), key(0)
        corpus = 0_int8
        ok = (verify_mark(KAT1_MARK, corpus, payload, key) == ERR_OK)
    end function test_05_verify_kat1

    function test_06_verify_bool_kat1() result(ok)
        logical :: ok
        integer(int8) :: corpus(32), payload(0), key(0)
        corpus = 0_int8
        ok = verify_bool(KAT1_MARK, corpus, payload, key)
    end function test_06_verify_bool_kat1

    function test_07_round_trip() result(ok)
        logical :: ok
        integer(int8) :: corpus(32), payload(11), key(13)
        character(len=:), allocatable :: mark
        integer :: i
        do i = 1, 32; corpus(i) = int(i, int8); end do
        do i = 1, 11; payload(i) = int(64 + i, int8); end do
        do i = 1, 13; key(i) = int(100 + i, int8); end do
        mark = sign_mark(corpus, payload, key)
        ok = (verify_mark(mark, corpus, payload, key) == ERR_OK)
    end function test_07_round_trip

    function test_08_tampered_payload() result(ok)
        logical :: ok
        integer(int8) :: corpus(32), payload(4), payload2(4), key(3)
        character(len=:), allocatable :: mark
        integer :: i
        do i = 1, 32; corpus(i) = int(i, int8); end do
        payload  = [int(z'01',int8), int(z'02',int8), int(z'03',int8), int(z'04',int8)]
        payload2 = [int(z'FF',int8), int(z'02',int8), int(z'03',int8), int(z'04',int8)]
        key = [int(z'AA',int8), int(z'BB',int8), int(z'CC',int8)]
        mark = sign_mark(corpus, payload, key)
        ok = (verify_mark(mark, corpus, payload2, key) == ERR_SIGNATURE_MISMATCH)
    end function test_08_tampered_payload

    function test_09_wrong_key() result(ok)
        logical :: ok
        integer(int8) :: corpus(32), payload(1), key1(1), key2(1)
        character(len=:), allocatable :: mark
        corpus = 0_int8
        payload(1) = int(z'01', int8)
        key1(1) = int(z'AA', int8)
        key2(1) = int(z'BB', int8)
        mark = sign_mark(corpus, payload, key1)
        ok = (verify_mark(mark, corpus, payload, key2) == ERR_SIGNATURE_MISMATCH)
    end function test_09_wrong_key

    function test_10_wrong_corpus() result(ok)
        logical :: ok
        integer(int8) :: corpus1(32), corpus2(32), payload(1), key(1)
        character(len=:), allocatable :: mark
        integer :: i
        do i = 1, 32; corpus1(i) = int(i, int8); end do
        do i = 1, 32; corpus2(i) = int(i + 100, int8); end do
        payload(1) = int(z'78', int8)
        key(1) = int(z'6B', int8)
        mark = sign_mark(corpus1, payload, key)
        ok = (verify_mark(mark, corpus2, payload, key) == ERR_CORPUS_MISMATCH)
    end function test_10_wrong_corpus

    function test_11_invalid_corpus_len() result(ok)
        logical :: ok
        integer(int8) :: short_corpus(20), payload(0), key(0)
        short_corpus = 0_int8
        ok = (verify_mark(KAT1_MARK, short_corpus, payload, key) == ERR_INVALID_CORPUS_LEN)
    end function test_11_invalid_corpus_len

    function test_12_unknown_version() result(ok)
        logical :: ok
        integer(int8) :: corpus(32), payload(0), key(0)
        corpus = 0_int8
        ok = (verify_mark('not-a-mark', corpus, payload, key) == ERR_UNKNOWN_MARK_VERSION)
    end function test_12_unknown_version

    function test_13_malformed() result(ok)
        logical :: ok
        integer(int8) :: corpus(32), payload(0), key(0)
        integer :: status
        corpus = 0_int8
        status = verify_mark('lore@v1:abc', corpus, payload, key)
        ok = (status == ERR_MALFORMED_MARK)
    end function test_13_malformed

    function test_14_base64url_round_trip() result(ok)
        logical :: ok
        integer(int8) :: input(5), back(:)
        allocatable :: back
        character(len=:), allocatable :: encoded
        input = [int(z'48',int8), int(z'65',int8), int(z'6C',int8), int(z'6C',int8), int(z'6F',int8)]
        encoded = base64url_encode(input)
        back = base64url_decode(encoded)
        if (.not. allocated(back)) then
            ok = .false.
            return
        end if
        if (size(back) /= size(input)) then
            ok = .false.
            return
        end if
        ok = all(back == input)
    end function test_14_base64url_round_trip

    function test_15_hex_round_trip() result(ok)
        logical :: ok
        integer(int8) :: data_in(5), back(:)
        allocatable :: back
        character(len=:), allocatable :: hex
        data_in = [int(z'01',int8), int(z'02',int8), int(z'03',int8), &
                   int(z'FF',int8), int(z'AB',int8)]
        hex = bytes_to_hex(data_in)
        if (hex /= '010203ffab') then
            ok = .false.
            return
        end if
        back = hex_to_bytes(hex)
        if (.not. allocated(back)) then
            ok = .false.
            return
        end if
        ok = all(back == data_in)
    end function test_15_hex_round_trip

    function test_16_loud_once_prefix() result(ok)
        logical :: ok
        ok = (LOUD_ONCE_PREFIX == '[LOUD-ONCE-WARNING]')
    end function test_16_loud_once_prefix

    function test_17_severity_ladder() result(ok)
        logical :: ok
        ok = (severity_rank(SEV_INFO) < severity_rank(SEV_WARN)) .and. &
             (severity_rank(SEV_WARN) < severity_rank(SEV_ERROR)) .and. &
             (severity_rank(SEV_ERROR) < severity_rank(SEV_CRITICAL))
    end function test_17_severity_ladder

    function test_18_severity_labels() result(ok)
        logical :: ok
        ok = (severity_label(SEV_INFO) == 'INFO') .and. &
             (severity_label(SEV_WARN) == 'WARN') .and. &
             (severity_label(SEV_ERROR) == 'ERROR') .and. &
             (severity_label(SEV_CRITICAL) == 'CRITICAL')
    end function test_18_severity_labels

    function test_19_default_reviewed() result(ok)
        logical :: ok
        ok = (DEFAULT_REVIEWED_BY_COUNSEL .eqv. .false.)
    end function test_19_default_reviewed

    function test_20_article_9_ref() result(ok)
        logical :: ok
        ok = (REF_UK_GDPR_ARTICLE_9 == 'UK GDPR Article 9')
    end function test_20_article_9_ref

    function test_21_document_ids() result(ok)
        logical :: ok
        ok = valid_document_id('terms') .and. valid_document_id('privacy') .and. &
             valid_document_id('cookies') .and. valid_document_id('gdpr') .and. &
             valid_document_id('community-guidelines') .and. &
             (.not. valid_document_id('invalid'))
    end function test_21_document_ids

    function test_22_compute_body_hash_empty() result(ok)
        logical :: ok
        character(len=:), allocatable :: hex
        hex = compute_body_hash('')
        ! SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        ok = (hex == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    end function test_22_compute_body_hash_empty

    function test_23_config_empty() result(ok)
        logical :: ok
        type(LegalConfig) :: cfg
        cfg%operator_name = ''
        cfg%registered_office_address = 'addr'
        cfg%ico_registration_number = 'ZX0'
        cfg%contact_email = 'a@b.c'
        ok = .not. legal_config_configured(cfg)
    end function test_23_config_empty

    function test_24_config_populated() result(ok)
        logical :: ok
        type(LegalConfig) :: cfg
        cfg = legal_config_placeholder()
        ok = legal_config_configured(cfg)
    end function test_24_config_populated

    function test_25_acceptance_key() result(ok)
        logical :: ok
        ok = (acceptance_key('user1', 'terms', '1.0') == 'user1|terms|1.0')
    end function test_25_acceptance_key

    function test_26_placeholder_alert() result(ok)
        logical :: ok
        ok = (DEFAULT_PLACEHOLDER_ALERT(1:10) == 'IMPORTANT:')
    end function test_26_placeholder_alert

end program test_mirrormark
