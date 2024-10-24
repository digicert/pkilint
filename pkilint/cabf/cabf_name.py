import typing

import unicodedata
import html
from iso3166 import countries_by_alpha2
from pyasn1_alt_modules import rfc5280

from pkilint import validation, document
from pkilint.common import organization_id
from pkilint.common.organization_id import ParsedOrganizationIdentifier
from pkilint.itu import x520_name, asn1_util
from pkilint.pkix import Rfc2119Word


class ValidCountryCodeValidatorBase(validation.TypeMatchingValidator):
    def __init__(self, type_oid, value_path, checked_validation):
        super().__init__(
            type_path="type",
            type_oid=type_oid,
            value_path=value_path,
            pdu_class=rfc5280.AttributeTypeAndValue,
            validations=[checked_validation],
        )

    def validate_with_value(self, node, value_node):
        country_code = str(value_node.pdu)

        if country_code == "XX":
            return
        elif country_code not in countries_by_alpha2:
            raise validation.ValidationFindingEncountered(
                self.validations[0], f'Invalid country code: "{country_code}"'
            )


class ValidCountryValidator(ValidCountryCodeValidatorBase):
    VALIDATION_INVALID_COUNTRY_CODE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.invalid_country_code"
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc5280.id_at_countryName,
            value_path="value.x520countryName",
            checked_validation=self.VALIDATION_INVALID_COUNTRY_CODE,
        )


class CabfOrganizationIdentifierValidatorBase(
    organization_id.OrganizationIdentifierValidatorBase
):
    VALIDATION_ORGANIZATION_ID_INVALID_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.invalid_organization_identifier_registration_scheme",
    )

    VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.invalid_organization_identifier_country",
    )

    # the attribute name for this finding is prefixed with an underscore, so it's not flagged by the "validation report"
    # test
    _VALIDATION_ORGANIZATION_ID_INVALID_SP_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.invalid_organization_identifier_state_province_format",
    )

    REFERENCE_REQUIRED = (
        Rfc2119Word.MUST,
        "cabf.organization_identifier_reference_missing_for_scheme",
    )

    STATE_PROVINCE_PROHIBITED = (
        Rfc2119Word.MUST_NOT,
        "cabf.invalid_subject_organization_identifier_state_province_for_scheme",
    )

    _NTR_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(
            organization_id.ISO3166_1_COUNTRY_CODES,
            VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY,
        ),
        state_province=(Rfc2119Word.MAY, None),
        reference=REFERENCE_REQUIRED,
    )

    _VAT_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(
            organization_id.ISO3166_1_COUNTRY_CODES
            | {
                organization_id.COUNTRY_CODE_GREECE_TRADITIONAL,
                organization_id.COUNTRY_CODE_NORTHERN_IRELAND,
            },
            VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY,
        ),
        state_province=STATE_PROVINCE_PROHIBITED,
        reference=REFERENCE_REQUIRED,
    )

    _PSD_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(
            organization_id.ISO3166_1_COUNTRY_CODES,
            VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY,
        ),
        state_province=STATE_PROVINCE_PROHIBITED,
        reference=REFERENCE_REQUIRED,
    )

    _ALLOWED_SCHEME_MAPPINGS = {
        "NTR": _NTR_SCHEME,
        "VAT": _VAT_SCHEME,
        "PSD": _PSD_SCHEME,
    }

    def __init__(
        self,
        invalid_format_validation: typing.Optional[validation.ValidationFinding],
        additional_schemes: typing.Optional[
            typing.Mapping[str, organization_id.OrganizationIdentifierElementAllowance]
        ] = None,
        enforce_strict_state_province_format=True,
        additional_validations=None,
        **kwargs,
    ):
        self._allowed_schemes = self._ALLOWED_SCHEME_MAPPINGS.copy()

        if additional_schemes:
            self._allowed_schemes.update(additional_schemes)

        self._enforce_strict_state_province_format = (
            enforce_strict_state_province_format
        )

        additional_validations = (
            [] if additional_validations is None else additional_validations.copy()
        )
        additional_validations.append(self.VALIDATION_ORGANIZATION_ID_INVALID_SCHEME)

        if self._enforce_strict_state_province_format:
            additional_validations.append(
                self._VALIDATION_ORGANIZATION_ID_INVALID_SP_FORMAT
            )

        super().__init__(
            self._allowed_schemes,
            invalid_format_validation,
            additional_validations=additional_validations,
            **kwargs,
        )

    @classmethod
    def handle_unknown_scheme(
        cls, node: document.PDUNode, parsed: ParsedOrganizationIdentifier
    ):
        raise validation.ValidationFindingEncountered(
            cls.VALIDATION_ORGANIZATION_ID_INVALID_SCHEME,
            f'Invalid registration scheme: "{parsed.scheme}"',
        )

    def validate_with_parsed_value(self, node, parsed):
        if (
            self._enforce_strict_state_province_format
            and parsed.state_province is not None
        ):
            if len(parsed.state_province) != 2 or not parsed.state_province.isalpha():
                raise validation.ValidationFindingEncountered(
                    self._VALIDATION_ORGANIZATION_ID_INVALID_SP_FORMAT,
                    f'State/province "{parsed.state_province}" is not two letters (will be fixed in erratum ballot)',
                )

        return super().validate_with_parsed_value(node, parsed)


class CabfOrganizationIdentifierAttributeValidator(
    CabfOrganizationIdentifierValidatorBase
):
    VALIDATION_ORGANIZATION_ID_INVALID_ENCODING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.invalid_subject_organization_identifier_encoding",
    )

    VALIDATION_ORGANIZATION_ID_INVALID_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.invalid_subject_organization_identifier_format",
    )

    def __init__(
        self,
        additional_schemes: typing.Optional[
            typing.Mapping[str, organization_id.OrganizationIdentifierElementAllowance]
        ] = None,
        enforce_strict_state_province_format=True,
        additional_validations: typing.Optional[
            typing.List[validation.ValidationFinding]
        ] = None,
    ):
        if additional_validations is None:
            additional_validations = []

        super().__init__(
            self.VALIDATION_ORGANIZATION_ID_INVALID_FORMAT,
            additional_schemes,
            enforce_strict_state_province_format,
            [self.VALIDATION_ORGANIZATION_ID_INVALID_ENCODING] + additional_validations,
            pdu_class=x520_name.X520OrganizationIdentifier,
        )

    @classmethod
    def parse_organization_id_node(
        cls, node
    ) -> organization_id.ParsedOrganizationIdentifier:
        name, value_node = node.child

        if name not in {"utf8String", "printableString"}:
            raise validation.ValidationFindingEncountered(
                cls.VALIDATION_ORGANIZATION_ID_INVALID_ENCODING,
                f"Invalid ASN.1 encoding: {name}",
            )

        return organization_id.parse_organization_identifier(str(value_node.pdu))


class RelativeDistinguishedNameContainsOneElementValidator(validation.Validator):
    VALIDATION_RDN_CONTAINS_MULTIPLE_ATVS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE, "cabf.rdn_contains_multiple_atvs"
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_RDN_CONTAINS_MULTIPLE_ATVS],
            pdu_class=rfc5280.RelativeDistinguishedName,
        )

    def validate(self, node):
        child_count = len(node.children)

        if child_count > 1:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_RDN_CONTAINS_MULTIPLE_ATVS
            )


VALIDATION_INTERNAL_IP_ADDRESS = validation.ValidationFinding(
    validation.ValidationFindingSeverity.ERROR, "cabf.internal_ip_address"
)

VALIDATION_INTERNAL_DOMAIN_NAME = validation.ValidationFinding(
    validation.ValidationFindingSeverity.ERROR, "cabf.internal_domain_name"
)


class SignificantAttributeValueValidator(validation.Validator):
    VALIDATION_INSIGNIFICANT_ATTRIUBTE_VALUE_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.insignificant_attribute_value_present",
    )

    # https://www.unicode.org/reports/tr44/#General_Category_Values
    # TODO: any letter, number, or symbol is significant. revisit this to restrict S to only Sc (currency symbol)?
    _SIGNIFICANT_MAJOR_CLASSES = {
        "L",
        "N",
        "S",
    }

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_INSIGNIFICANT_ATTRIUBTE_VALUE_PRESENT],
            pdu_class=rfc5280.AttributeTypeAndValue,
        )

    def validate(self, node):
        value = asn1_util.get_string_value_from_attribute_node(node)

        if value is None:
            return

        if not any(
            unicodedata.category(c)[0] in self._SIGNIFICANT_MAJOR_CLASSES for c in value
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INSIGNIFICANT_ATTRIUBTE_VALUE_PRESENT,
                f'Insignificant attribute value: "{value}"',
            )


class HTMLEntitiesValidator(validation.Validator):
    """Validates that attribute values do not contain HTML entities using html.unescape."""

    VALIDATION_ATTRIBUTE_VALUE_CONTAINS_HTML_ENTITY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.name.attribute_value_contains_html_entity",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_ATTRIBUTE_VALUE_CONTAINS_HTML_ENTITY],
            pdu_class=rfc5280.AttributeTypeAndValue,
        )

    def validate(self, node):
        value_str = asn1_util.get_string_value_from_attribute_node(node)

        if not value_str:
            return

        unescaped_value = html.unescape(value_str)

        if value_str != unescaped_value:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ATTRIBUTE_VALUE_CONTAINS_HTML_ENTITY,
                f'Attribute value contains HTML entity: "{value_str}"',
            )
