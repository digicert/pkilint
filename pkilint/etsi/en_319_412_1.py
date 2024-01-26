from iso3166 import countries_by_alpha2

from pkilint import validation, document
from pkilint.common import organization_id
from pkilint.common.organization_id import ParsedOrganizationIdentifier
from pkilint.itu import x520_name
from pkilint.pkix import Rfc2119Word


class LegalPersonOrganizationIdentifierValidator(organization_id.OrganizationIdentifierValidatorBase):
    VALIDATION_INVALID_ORGANIZATION_ID_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.leg-5.1.4-02.invalid_format'
    )

    VALIDATION_INVALID_ORGANIZATION_ID_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.leg-5.1.4-03.invalid_scheme'
    )

    VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.leg-5.1.4-03.invalid_country'
    )

    VALIDATION_ORGANIZATION_NATIONAL_SCHEME_DETECTED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'etsi.en_319_412_1.leg-5.1.4-03.national_scheme_detected'
    )

    _STATE_PROVINCE_PROHIBITED = (Rfc2119Word.MUST_NOT, VALIDATION_INVALID_ORGANIZATION_ID_FORMAT.code)
    _REFERENCE_REQUIRED = (Rfc2119Word.MUST, VALIDATION_INVALID_ORGANIZATION_ID_FORMAT.code)

    _NTR_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(organization_id.ISO3166_1_COUNTRY_CODES,
                       VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY),
        state_province=_STATE_PROVINCE_PROHIBITED,
        reference=_REFERENCE_REQUIRED
    )

    _VAT_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(organization_id.ISO3166_1_COUNTRY_CODES | {organization_id.COUNTRY_CODE_GREECE_TRADITIONAL,
                                                                  organization_id.COUNTRY_CODE_NORTHERN_IRELAND},
                       VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY),
        state_province=_STATE_PROVINCE_PROHIBITED,
        reference=_REFERENCE_REQUIRED
    )

    _PSD_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(organization_id.ISO3166_1_COUNTRY_CODES,
                       VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY),
        state_province=_STATE_PROVINCE_PROHIBITED,
        reference=_REFERENCE_REQUIRED
    )

    _LEI_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=({organization_id.COUNTRY_CODE_GLOBAL_SCHEME},
                       VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY),
        state_province=_STATE_PROVINCE_PROHIBITED,
        reference=_REFERENCE_REQUIRED
    )

    _ELEMENT_ALLOWANCES = {
        'NTR': _NTR_SCHEME,
        'VAT': _VAT_SCHEME,
        'PSD': _PSD_SCHEME,
        'LEI': _LEI_SCHEME,
    }

    def __init__(self):
        super().__init__(element_allowances=self._ELEMENT_ALLOWANCES,
                         invalid_format_validation=self.VALIDATION_INVALID_ORGANIZATION_ID_FORMAT,
                         additional_validations=[
                             self.VALIDATION_INVALID_ORGANIZATION_ID_SCHEME,
                             self.VALIDATION_ORGANIZATION_NATIONAL_SCHEME_DETECTED
                         ],
                         pdu_class=x520_name.X520OrganizationIdentifier,
                         predicate=lambda n: any(n.children))

    @classmethod
    def handle_unknown_scheme(cls, node: document.PDUNode, parsed: organization_id.ParsedOrganizationIdentifier):
        is_valid_national_scheme = (
            parsed.is_national_scheme and
            parsed.country in countries_by_alpha2 and
            parsed.state_province is None and
            parsed.reference
        )

        value_str = str(node.child[1].pdu)

        if is_valid_national_scheme:
            raise validation.ValidationFindingEncountered(
                cls.VALIDATION_ORGANIZATION_NATIONAL_SCHEME_DETECTED,
                f'National registration scheme "{parsed.scheme}" in organization identifier: "{value_str}"'
            )
        else:
            raise validation.ValidationFindingEncountered(
                cls.VALIDATION_INVALID_ORGANIZATION_ID_SCHEME,
                f'Invalid registration scheme "{parsed.scheme}" in organization identifier: "{value_str}"'
            )

    @classmethod
    def parse_organization_id_node(cls, node: document.PDUNode) -> ParsedOrganizationIdentifier:
        value = str(node.child[1].pdu)

        return organization_id.parse_organization_identifier(value)
