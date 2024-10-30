from pyasn1_alt_modules import rfc5280

from pkilint import validation
from pkilint.etsi import etsi_shared
from pkilint.itu import x520_name

_LEGAL_PERSON_REQUIRED_ATTRIBUTES = {
    rfc5280.id_at_countryName,
    rfc5280.id_at_organizationName,
    x520_name.id_at_organizationIdentifier,
    rfc5280.id_at_commonName,
}


class LegalPersonSubjectAttributeAllowanceValidator(
    etsi_shared.LegalPersonAttributeAllowanceValidator
):
    """
    LEG-4.2.1-2: The subject field shall include at least the following attributes as specified in Recommendation
    ITU-T X.520
    """

    _CODE_CLASSIFIER = "etsi.en_319_412_3.leg-4.2.1-2"

    def __init__(self):
        super().__init__(
            self._CODE_CLASSIFIER,
            _LEGAL_PERSON_REQUIRED_ATTRIBUTES,
            "certificate.tbsCertificate.subject.rdnSequence",
        )


class LegalPersonDuplicateAttributeAllowanceValidator(
    etsi_shared.LegalPersonDuplicateAttributeAllowanceValidator
):
    """
    LEG-4.2.1-3: Only one instance of each of these attributes shall be present.
    """

    VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_3.leg-4.2.1-3.prohibited_duplicate_attribute_present",
    )

    def __init__(self):
        super().__init__(
            self.VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT,
            _LEGAL_PERSON_REQUIRED_ATTRIBUTES,
        )


class LegalPersonOrganizationAttributesEqualityValidator(
    etsi_shared.LegalPersonOrganizationAttributesEqualityValidator
):
    """
    LEG-4.2.1-6: The organizationIdentifier attribute shall contain an identification of the subject organization
    different from the organization name.
    """

    VALIDATION_ORGID_ORGNAME_ATTRIBUTE_VALUES_EQUAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_3.leg-4.2.1-6.organization_id_and_organization_name_attribute_values_equal",
    )

    def __init__(self):
        super().__init__(self.VALIDATION_ORGID_ORGNAME_ATTRIBUTE_VALUES_EQUAL)


class LegalPersonKeyUsageValidator(etsi_shared.KeyUsageValidator):
    """
    LEG-4.3.1-3: Certificates used to validate commitment to signed content (e.g. documents, agreements and/or
    transactions) shall be limited to type A, B or F.
    """

    VALIDATION_INVALID_CONTENT_COMMITMENT_SETTING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_3.leg-4.3.1-3.invalid_content_commitment_setting",
    )

    """
    LEG-4.3.1-4: Of these alternatives, type A should be used (see the security note 2 below).
    """
    VALIDATION_NON_PREFERRED_CONTENT_COMMITMENT_SETTING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "etsi.en_319_412_3.leg-4.3.1-4.non_preferred_content_commitment_setting",
    )

    def __init__(self, is_content_commitment_type):
        super().__init__(
            is_content_commitment_type,
            self.VALIDATION_INVALID_CONTENT_COMMITMENT_SETTING,
            self.VALIDATION_NON_PREFERRED_CONTENT_COMMITMENT_SETTING,
        )


class LegalPersonCountryCodeValidator(etsi_shared.LegalPersonCountryCodeValidator):
    """
    LEG-4.2.1-4: The countryName attribute shall specify the country in which the subject (legal person) is established.
    """

    VALIDATION_UNKNOWN_COUNTRY_CODE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "etsi.en_319_412_3.leg-4.2.1-4.unknown_country_code",
    )

    def __init__(self):
        super().__init__(self.VALIDATION_UNKNOWN_COUNTRY_CODE)
