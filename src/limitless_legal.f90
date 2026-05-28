!> limitless_legal -- UK GDPR + statutory cross-reference surface (cohort-canonical Fortran SDK).
!>
!> Fortran 2008 port of foundation/legal/{refs.go, types.go, config.go, page.go}
!> (Go canonical) + cohort siblings.
!>
!> R166 LIABILITY-FOOTER-CONST alignment:
!>   - DEFAULT_PLACEHOLDER_ALERT is the cohort-canonical liability-footer.
!>   - DEFAULT_REVIEWED_BY_COUNSEL = .false. is the cohort honest-default.
!>
!> R-rule alignment:
!>   - R166 LIABILITY-FOOTER-CONST
!>   - R154 ARTICLE-9-DSAR-AUDIT-CLASS-COHORT-EXTENSION
!>   - R150 PARALLEL-MAP-R144-REVIEW-METADATA

module limitless_legal
    use iso_fortran_env, only: int8
    use limitless_sha256, only: sha256_digest, SHA256_DIGEST_SIZE
    implicit none
    private

    ! UK GDPR statutory references.
    public :: REF_UK_GDPR_ARTICLE_9, REF_UK_GDPR_ARTICLE_13, REF_UK_GDPR_ARTICLE_14
    public :: REF_UK_GDPR_ARTICLE_15, REF_UK_GDPR_ARTICLE_16, REF_UK_GDPR_ARTICLE_17
    public :: REF_UK_GDPR_ARTICLE_18, REF_UK_GDPR_ARTICLE_20, REF_UK_GDPR_ARTICLE_21
    public :: REF_UK_GDPR_ARTICLE_30, REF_UK_GDPR_ARTICLE_37, REF_UK_GDPR_ARTICLE_46
    public :: REF_DPA_2018_SECTION_17, REF_PECR_REGULATION_6
    public :: REF_UK_LIMITATION_ACT_1980, REF_FSMA_2000_SECTION_19

    ! Cohort-canonical text constants.
    public :: DEFAULT_PLACEHOLDER_ALERT, DEFAULT_REVIEWED_BY_COUNSEL
    public :: ICO_COMPLAINT_NOTICE, FCA_NOT_AUTHORISED_DISCLAIMER

    ! DocumentID closed-set.
    public :: DOCUMENT_ID_TERMS, DOCUMENT_ID_PRIVACY, DOCUMENT_ID_COOKIES
    public :: DOCUMENT_ID_GDPR, DOCUMENT_ID_COMMUNITY_GUIDELINES
    public :: valid_document_id

    ! Helpers.
    public :: LegalConfig
    public :: legal_config_configured
    public :: legal_config_placeholder
    public :: compute_body_hash
    public :: acceptance_key

    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_9  = "UK GDPR Article 9"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_13 = "UK GDPR Article 13"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_14 = "UK GDPR Article 14"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_15 = "UK GDPR Article 15"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_16 = "UK GDPR Article 16"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_17 = "UK GDPR Article 17"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_18 = "UK GDPR Article 18"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_20 = "UK GDPR Article 20"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_21 = "UK GDPR Article 21"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_30 = "UK GDPR Article 30"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_37 = "UK GDPR Article 37"
    character(len=*), parameter :: REF_UK_GDPR_ARTICLE_46 = "UK GDPR Article 46"
    character(len=*), parameter :: REF_DPA_2018_SECTION_17 = "DPA 2018 s17"
    character(len=*), parameter :: REF_PECR_REGULATION_6 = "PECR Regulation 6"
    character(len=*), parameter :: REF_UK_LIMITATION_ACT_1980 = "UK Limitation Act 1980"
    character(len=*), parameter :: REF_FSMA_2000_SECTION_19 = "FSMA 2000 s19"

    !> R166 LIABILITY-FOOTER-CONST.
    character(len=*), parameter :: DEFAULT_PLACEHOLDER_ALERT = &
        "IMPORTANT: This document is structured boilerplate and has not been " // &
        "reviewed by qualified legal counsel. Do not rely on this text as a " // &
        "substitute for a professionally-drafted document before processing " // &
        "customer payments."

    !> R150-aligned honest-default.
    logical, parameter :: DEFAULT_REVIEWED_BY_COUNSEL = .false.

    character(len=*), parameter :: ICO_COMPLAINT_NOTICE = &
        "You have the right to lodge a complaint with the UK Information " // &
        "Commissioner's Office (ICO) at any time. Visit ico.org.uk for contact " // &
        "details."

    character(len=*), parameter :: FCA_NOT_AUTHORISED_DISCLAIMER = &
        "This service provides general personal-finance information only. It is NOT " // &
        "regulated investment, mortgage, insurance, or pensions advice within the " // &
        "meaning of FSMA 2000 s19. The operator is not authorised or regulated by " // &
        "the Financial Conduct Authority. For regulated advice, consult an FCA-" // &
        "authorised independent financial adviser (see fca.org.uk/register)."

    ! DocumentID closed-set.
    character(len=*), parameter :: DOCUMENT_ID_TERMS = "terms"
    character(len=*), parameter :: DOCUMENT_ID_PRIVACY = "privacy"
    character(len=*), parameter :: DOCUMENT_ID_COOKIES = "cookies"
    character(len=*), parameter :: DOCUMENT_ID_GDPR = "gdpr"
    character(len=*), parameter :: DOCUMENT_ID_COMMUNITY_GUIDELINES = "community-guidelines"

    type, public :: LegalConfig
        character(len=:), allocatable :: operator_name
        character(len=:), allocatable :: registered_office_address
        character(len=:), allocatable :: ico_registration_number
        character(len=:), allocatable :: dpo_email
        character(len=:), allocatable :: contact_email
        character(len=:), allocatable :: jurisdiction
        character(len=:), allocatable :: service_name
        character(len=:), allocatable :: vat_number
        character(len=:), allocatable :: company_number
    end type LegalConfig

contains

    function valid_document_id(slug) result(ok)
        character(len=*), intent(in) :: slug
        logical :: ok
        ok = (slug == DOCUMENT_ID_TERMS .or. &
              slug == DOCUMENT_ID_PRIVACY .or. &
              slug == DOCUMENT_ID_COOKIES .or. &
              slug == DOCUMENT_ID_GDPR .or. &
              slug == DOCUMENT_ID_COMMUNITY_GUIDELINES)
    end function valid_document_id

    function legal_config_configured(cfg) result(ok)
        type(LegalConfig), intent(in) :: cfg
        logical :: ok
        ok = allocated(cfg%operator_name) .and. allocated(cfg%registered_office_address) .and. &
             allocated(cfg%ico_registration_number) .and. allocated(cfg%contact_email)
        if (.not. ok) return
        ok = (len(cfg%operator_name) > 0 .and. len(cfg%registered_office_address) > 0 .and. &
              len(cfg%ico_registration_number) > 0 .and. len(cfg%contact_email) > 0)
    end function legal_config_configured

    function legal_config_placeholder() result(cfg)
        type(LegalConfig) :: cfg
        cfg%operator_name = "Operator (REPLACE-IN-PRODUCTION)"
        cfg%registered_office_address = "Address (REPLACE-IN-PRODUCTION)"
        cfg%ico_registration_number = "ZX0000000"
        cfg%dpo_email = "dpo@operator.example"
        cfg%contact_email = "legal@operator.example"
        cfg%jurisdiction = "England and Wales"
        cfg%service_name = "Service (REPLACE-IN-PRODUCTION)"
        cfg%vat_number = ""
        cfg%company_number = ""
    end function legal_config_placeholder

    !> SHA-256 hex digest of a UTF-8-encoded string.
    !> Byte-identical algorithm to foundation/legal/page.ComputeBodyHash.
    function compute_body_hash(body) result(hex_str)
        character(len=*), intent(in) :: body
        character(len=:), allocatable :: hex_str
        integer(int8), allocatable :: body_bytes(:)
        integer(int8) :: digest(SHA256_DIGEST_SIZE)
        character(len=2) :: byte_hex
        integer :: i

        allocate(body_bytes(len(body)))
        do i = 1, len(body)
            body_bytes(i) = int(iachar(body(i:i)), int8)
        end do

        call sha256_digest(body_bytes, digest)
        deallocate(body_bytes)

        allocate(character(len=SHA256_DIGEST_SIZE * 2) :: hex_str)
        do i = 1, SHA256_DIGEST_SIZE
            write(byte_hex, '(z2.2)') iand(int(digest(i)), 255)
            ! Lowercase.
            if (byte_hex(1:1) >= 'A' .and. byte_hex(1:1) <= 'Z') &
                byte_hex(1:1) = achar(iachar(byte_hex(1:1)) + 32)
            if (byte_hex(2:2) >= 'A' .and. byte_hex(2:2) <= 'Z') &
                byte_hex(2:2) = achar(iachar(byte_hex(2:2)) + 32)
            hex_str((i - 1) * 2 + 1 : i * 2) = byte_hex
        end do
    end function compute_body_hash

    !> Cohort-aligned canonical lookup key. Format: "user_id|document_id|version".
    function acceptance_key(user_id, document_id, version_) result(key)
        character(len=*), intent(in) :: user_id, document_id, version_
        character(len=:), allocatable :: key
        key = user_id // '|' // document_id // '|' // version_
    end function acceptance_key

end module limitless_legal
