import re
from typing import NamedTuple, Optional, Set, Tuple, Dict, List

from iso3166 import countries_by_alpha2

from pkilint import validation, document
from pkilint.iso import lei
from pkilint.itu import x520_name
from pkilint.pkix import Rfc2119Word

_ORG_ID_REGEX = re.compile(
    r"^(?P<scheme>[A-Z]{2}[A-Z:])(?P<country>[a-zA-Z]{2})(\+(?P<sp>[a-zA-Z0-9]{1,3}))?"
    r"(-(?P<reference>.+))?$"
)

# alternative country codes
COUNTRY_CODE_GREECE_TRADITIONAL = "EL"
COUNTRY_CODE_NORTHERN_IRELAND = "XI"

# multi-national codes
COUNTRY_CODE_GLOBAL_SCHEME = "XG"
COUNTRY_CODE_EUROPEAN_UNION = "EU"
COUNTRY_CODE_EUROZONE = "EZ"
COUNTRY_CODE_USSR = "SU"
COUNTRY_CODE_UNITED_NATIONS = "UN"

TRANSNATIONAL_COUNTRY_CODES = {
    COUNTRY_CODE_EUROPEAN_UNION,
    COUNTRY_CODE_EUROZONE,
    COUNTRY_CODE_USSR,
    COUNTRY_CODE_UNITED_NATIONS,
}

ISO3166_1_COUNTRY_CODES = set(countries_by_alpha2.keys())
ISO3166_1_WITH_TRANSNATIONAL_COUNTRY_CODES = (
    ISO3166_1_COUNTRY_CODES | TRANSNATIONAL_COUNTRY_CODES
)


LEI_PREFIX = "LEIXG-"


class ParsedOrganizationIdentifier(NamedTuple):
    raw: Optional[str]
    scheme: str
    is_national_scheme: bool
    country: str
    state_province: Optional[str]
    reference: Optional[str]


def parse_organization_identifier(value: str) -> ParsedOrganizationIdentifier:
    m = _ORG_ID_REGEX.match(value)

    if m is None:
        raise ValueError(f'Invalid organization identifier syntax: "{value}"')

    is_national_scheme = m["scheme"].endswith(":")

    scheme = m["scheme"][:2] if is_national_scheme else m["scheme"]

    return ParsedOrganizationIdentifier(
        value,
        scheme,
        is_national_scheme,
        m.group("country"),
        m.group("sp"),
        m.group("reference"),
    )


def assert_parsed_organization_identifier_equal(
    org1: ParsedOrganizationIdentifier,
    org1_source: str,
    org2: ParsedOrganizationIdentifier,
    org2_source: str,
):
    if org1.scheme != org2.scheme:
        raise ValueError(
            f'Mismatched scheme: {org1_source}: "{org1.scheme}", {org2_source}: "{org2.scheme}"'
        )

    if org1.country.casefold() != org2.country.casefold():
        raise ValueError(
            f'Mismatched country: {org1_source}: "{org1.country}", {org2_source}: "{org2.country}"'
        )

    if org1.state_province != org2.state_province:
        org1_state_province = "" if org1.state_province is None else org1.state_province
        org2_state_province = "" if org2.state_province is None else org2.state_province

        raise ValueError(
            f'Mismatched state/province: {org1_source}: "{org1_state_province}", '
            f'{org2_source}: "{org2_state_province}"'
        )

    if org1.reference != org2.reference:
        org1_reference = "" if org1.reference is None else org1.reference
        org2_reference = "" if org2.reference is None else org2.reference

        raise ValueError(
            f'Mismatched registration reference: {org1_source}: "{org1_reference}", '
            f'{org2_source}: "{org2_reference}"'
        )


class OrganizationIdentifierLeiValidator(validation.Validator):
    def __init__(self):
        super().__init__(
            validations=[
                lei.VALIDATION_INVALID_LEI_CHECKSUM,
                lei.VALIDATION_INVALID_LEI_FORMAT,
            ],
            pdu_class=x520_name.X520OrganizationIdentifier,
            predicate=lambda n: any(n.children)
            and str(n.child[1].pdu).startswith("LEI"),
        )

    def validate(self, node):
        value = str(node.child[1].pdu)

        if not value.startswith(LEI_PREFIX):
            # let the syntax validator report this problem
            return

        lei_value = value[len(LEI_PREFIX) :]

        lei.validate_lei(lei_value)


class OrganizationIdentifierElementAllowance(NamedTuple):
    country_codes: Tuple[Set[str], validation.ValidationFinding]
    state_province: Tuple[Rfc2119Word, Optional[str]]
    reference: Tuple[Rfc2119Word, Optional[str]]


class OrganizationIdentifierValidatorBase(validation.Validator):
    def __init__(
        self,
        element_allowances: Dict[str, OrganizationIdentifierElementAllowance],
        invalid_format_validation: Optional[validation.ValidationFinding],
        additional_validations: Optional[List[validation.ValidationFinding]] = None,
        **kwargs,
    ):
        if additional_validations is None:
            additional_validations = []

        self._element_allowances = element_allowances.copy()

        self._invalid_format_validation = invalid_format_validation

        validations = [] + additional_validations

        if self._invalid_format_validation is not None:
            validations.append(self._invalid_format_validation)

        for allowance in element_allowances.values():
            validations.append(allowance.country_codes[1])

            OrganizationIdentifierValidatorBase._create_and_append_validation_finding(
                validations, *allowance.state_province
            )
            OrganizationIdentifierValidatorBase._create_and_append_validation_finding(
                validations, *allowance.reference
            )

        super().__init__(validations=validations, **kwargs)

    @staticmethod
    def _create_and_append_validation_finding(validations, presence_word, finding_code):
        if presence_word != Rfc2119Word.MAY:
            validations.append(
                validation.ValidationFinding(presence_word.to_severity, finding_code)
            )

    @classmethod
    def parse_organization_id_node(
        cls, node: document.PDUNode
    ) -> ParsedOrganizationIdentifier:
        pass

    @classmethod
    def handle_unknown_scheme(
        cls, node: document.PDUNode, parsed: ParsedOrganizationIdentifier
    ):
        pass

    def validate_with_parsed_value(
        self, node: document.PDUNode, parsed: ParsedOrganizationIdentifier
    ):
        scheme_allowance = self._element_allowances.get(parsed.scheme)

        if scheme_allowance is None:
            return self.handle_unknown_scheme(node, parsed)

        allowed_country_codes, finding = scheme_allowance.country_codes

        findings = []
        if parsed.country not in allowed_country_codes:
            findings.append(
                validation.ValidationFindingDescription(
                    finding,
                    f'Invalid country code for registration scheme "{parsed.scheme}": "{parsed.country}"',
                )
            )

        allowance, finding_code = scheme_allowance.state_province

        if parsed.state_province is None and allowance in {
            Rfc2119Word.SHOULD,
            Rfc2119Word.MUST,
        }:
            findings.append(
                validation.ValidationFindingDescription(
                    validation.ValidationFinding(allowance.to_severity, finding_code),
                    f'State/province missing for registration scheme "{parsed.scheme}"',
                )
            )
        elif parsed.state_province is not None and allowance in {
            Rfc2119Word.SHOULD_NOT,
            Rfc2119Word.MUST_NOT,
        }:
            findings.append(
                validation.ValidationFindingDescription(
                    validation.ValidationFinding(allowance.to_severity, finding_code),
                    f'State/province value present for scheme "{parsed.scheme}": "{parsed.state_province}"',
                )
            )

        allowance, finding_code = scheme_allowance.reference

        if parsed.reference is None and allowance in {
            Rfc2119Word.SHOULD,
            Rfc2119Word.MUST,
        }:
            findings.append(
                validation.ValidationFindingDescription(
                    validation.ValidationFinding(allowance.to_severity, finding_code),
                    f'Registration reference missing for scheme "{parsed.scheme}"',
                )
            )
        elif parsed.reference is not None and allowance in {
            Rfc2119Word.SHOULD_NOT,
            Rfc2119Word.MUST_NOT,
        }:
            findings.append(
                validation.ValidationFindingDescription(
                    validation.ValidationFinding(allowance.to_severity, finding_code),
                    f'Registration reference present for scheme "{parsed.scheme}": "{parsed.reference}"',
                )
            )

        return validation.ValidationResult(self, node, findings)

    def validate(self, node):
        try:
            parsed = self.parse_organization_id_node(node)
        except ValueError as e:
            raise validation.ValidationFindingEncountered(
                self._invalid_format_validation, str(e)
            )

        return self.validate_with_parsed_value(node, parsed)
