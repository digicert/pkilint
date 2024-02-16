import re
import typing
from typing import List

from iso3166 import countries_by_alpha2
from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc3739

from pkilint import validation, document
from pkilint.common import organization_id
from pkilint.common.organization_id import ParsedOrganizationIdentifier
from pkilint.etsi.asn1 import en_319_412_1
from pkilint.itu import x520_name
from pkilint.pkix import Rfc2119Word, certificate


def _get_semantics_info_nodes(cert: certificate.RFC5280Certificate) -> List[document.PDUNode]:
    ext_and_idx = cert.get_extension_by_oid(rfc3739.id_pe_qcStatements)

    if ext_and_idx is None:
        return []

    ext, _ = ext_and_idx

    try:
        _, ext_decoded_value_node = ext.children['extnValue'].child
    except ValueError:
        return []

    nodes = []
    for statement_node in ext_decoded_value_node.children.values():
        if statement_node.children['statementId'].pdu == rfc3739.id_qcs_pkixQCSyntax_v2:
            info_node = statement_node.children.get('statementInfo')

            if info_node is not None:
                info_node_decoded = info_node.children.get('semanticsInformation')

                if info_node_decoded is not None:
                    nodes.append(info_node_decoded)

    return nodes


def _cert_has_semantics_id(semantics_id: univ.ObjectIdentifier, cert: certificate.RFC5280Certificate) -> bool:
    # noinspection PyTypeChecker
    semantics_info_nodes = _get_semantics_info_nodes(cert)

    for semantics_info_node in semantics_info_nodes:
        id_oid_node = semantics_info_node.children.get('semanticsIdentifier')

        if id_oid_node is not None and id_oid_node.pdu == semantics_id:
            return True

    return False


class LegalPersonOrganizationIdentifierValidator(organization_id.OrganizationIdentifierValidatorBase):
    VALIDATION_INVALID_ORGANIZATION_ID_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.leg-5.1.4-02.invalid_format'
    )

    VALIDATION_INVALID_ORGANIZATION_ID_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.leg-5.1.4-03.invalid_scheme'
    )

    VALIDATION_INVALID_ORGANIZATION_ID_COUNTRY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.leg-5.1.4-03.invalid_country'
    )

    VALIDATION_ORGANIZATION_NATIONAL_SCHEME_DETECTED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'etsi.en_319_412_1.leg-5.1.4-03.national_identifier_scheme_detected'
    )

    _STATE_PROVINCE_PROHIBITED = (Rfc2119Word.MUST_NOT, VALIDATION_INVALID_ORGANIZATION_ID_FORMAT.code)
    _REFERENCE_REQUIRED = (Rfc2119Word.MUST, VALIDATION_INVALID_ORGANIZATION_ID_FORMAT.code)

    _NTR_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(organization_id.ISO3166_1_COUNTRY_CODES,
                       VALIDATION_INVALID_ORGANIZATION_ID_COUNTRY),
        state_province=_STATE_PROVINCE_PROHIBITED,
        reference=_REFERENCE_REQUIRED
    )

    _VAT_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(organization_id.ISO3166_1_COUNTRY_CODES | {organization_id.COUNTRY_CODE_GREECE_TRADITIONAL,
                                                                  organization_id.COUNTRY_CODE_NORTHERN_IRELAND},
                       VALIDATION_INVALID_ORGANIZATION_ID_COUNTRY),
        state_province=_STATE_PROVINCE_PROHIBITED,
        reference=_REFERENCE_REQUIRED
    )

    _PSD_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(organization_id.ISO3166_1_COUNTRY_CODES,
                       VALIDATION_INVALID_ORGANIZATION_ID_COUNTRY),
        state_province=_STATE_PROVINCE_PROHIBITED,
        reference=_REFERENCE_REQUIRED
    )

    _LEI_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=({organization_id.COUNTRY_CODE_GLOBAL_SCHEME},
                       VALIDATION_INVALID_ORGANIZATION_ID_COUNTRY),
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
                         pdu_class=x520_name.X520OrganizationIdentifier)

    def match(self, node):
        if not super().match(node):
            return False

        # skip nodes that haven't been decoded
        if not any(node.children):
            return False

        # noinspection PyTypeChecker
        return _cert_has_semantics_id(en_319_412_1.id_etsi_qcs_SemanticsId_Legal, node.document)

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


_NATURAL_PERSON_ID_REGEX = re.compile(
    r'^(?P<scheme>[A-Z]{2}[A-Z:])(?P<country>[a-zA-Z]{2})-(?P<reference>.+)$'
)


class ParsedNaturalPersonIdentifier(typing.NamedTuple):
    raw: typing.Optional[str]
    scheme: str
    is_national_scheme: bool
    country: str
    reference: str


def parse_natural_person_identifier(value: str) -> ParsedNaturalPersonIdentifier:
    m = _NATURAL_PERSON_ID_REGEX.match(value)

    if m is None:
        raise ValueError(f'Invalid natural person identifier syntax: "{value}"')

    is_national_scheme = m['scheme'].endswith(':')

    scheme = m['scheme'][:2] if is_national_scheme else m['scheme']

    return ParsedNaturalPersonIdentifier(value, scheme, is_national_scheme, m['country'], m['reference'])


class NaturalPersonIdentifierValidator(validation.Validator):
    VALIDATION_INVALID_NATURAL_PERSON_ID_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.nat-5.1.3.invalid_identifier_format'
    )

    VALIDATION_NATURAL_PERSON_ID_NATIONAL_SCHEME_DETECTED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'etsi.en_319_412_1.nat-5.1.3.national_identifier_scheme_detected'
    )

    VALIDATION_INVALID_NATURAL_PERSON_ID_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-5.1.3.invalid_identifier_scheme'
    )

    VALIDATION_DEPRECATED_NATURAL_PERSON_ID_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'etsi.en_319_412_3.nat-5.1.3.deprecated_identifier_scheme'
    )

    VALIDATION_INVALID_NATURAL_PERSON_ID_COUNTRY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_419_412_4.nat-5.1.3.invalid_identifier_country'
    )

    _KNOWN_SCHEMES = {
        'PAS',
        'IDC',
        'PNO',
        'TAX',
        'TIN',
    }

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_INVALID_NATURAL_PERSON_ID_FORMAT,
                self.VALIDATION_NATURAL_PERSON_ID_NATIONAL_SCHEME_DETECTED,
                self.VALIDATION_INVALID_NATURAL_PERSON_ID_SCHEME,
                self.VALIDATION_DEPRECATED_NATURAL_PERSON_ID_SCHEME,
                self.VALIDATION_INVALID_NATURAL_PERSON_ID_COUNTRY,
            ],
            pdu_class=rfc5280.X520SerialNumber
        )

    def match(self, node):
        if not super().match(node):
            return False

        # noinspection PyTypeChecker
        return _cert_has_semantics_id(en_319_412_1.id_etsi_qcs_semanticsId_Natural, node.document)

    def validate(self, node):
        value = str(node.pdu)

        try:
            parsed = parse_natural_person_identifier(value)
        except ValueError as e:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_NATURAL_PERSON_ID_FORMAT,
                str(e)
            )

        findings = []
        if parsed.scheme in self._KNOWN_SCHEMES:
            if parsed.scheme == 'TAX':
                findings.append(validation.ValidationFindingDescription(
                    self.VALIDATION_DEPRECATED_NATURAL_PERSON_ID_SCHEME,
                    f'Deprecated natural person identifier scheme: "{parsed.scheme}"'
                ))
        else:
            if parsed.is_national_scheme:
                findings.append(validation.ValidationFindingDescription(
                    self.VALIDATION_NATURAL_PERSON_ID_NATIONAL_SCHEME_DETECTED,
                    f'National registration scheme "{parsed.scheme}" in natural person identifier: "{value}"'
                ))
            else:
                findings.append(validation.ValidationFindingDescription(
                    self.VALIDATION_INVALID_NATURAL_PERSON_ID_SCHEME,
                    f'Invalid natural person identifier scheme: "{parsed.scheme}"'
                ))

        if parsed.country not in countries_by_alpha2:
            findings.append(validation.ValidationFindingDescription(
                self.VALIDATION_INVALID_NATURAL_PERSON_ID_COUNTRY,
                f'Invalid natural person identifier country code: "{parsed.country}"'
            ))

        return validation.ValidationResult(self, node, findings)


class NameRegistrationAuthoritiesValidatorBase(validation.Validator):
    def __init__(
            self,
            name_registration_authorities_missing_validation: validation.ValidationFinding,
            name_registration_authorities_uri_missing_validation: validation.ValidationFinding,
            attribute_type_id: univ.ObjectIdentifier,
            semantics_id: univ.ObjectIdentifier
    ):
        self._name_registration_authorities_missing_validation = name_registration_authorities_missing_validation
        self._name_registration_authorities_uri_missing_validation = (
            name_registration_authorities_uri_missing_validation
        )

        self._attribute_type_id = attribute_type_id
        self._semantics_id = semantics_id

        validations = [
            name_registration_authorities_missing_validation,
            name_registration_authorities_uri_missing_validation,
        ]

        super().__init__(validations=validations, pdu_class=rfc3739.SemanticsInformation)

    @classmethod
    def is_attribute_value_national_id_scheme(cls, atv_node: document.PDUNode) -> bool:
        pass

    def match(self, node):
        if not super().match(node):
            return False

        semantics_id_node = node.children.get('semanticsIdentifier')

        if semantics_id_node is None or semantics_id_node.pdu != self._semantics_id:
            return False

        atvs_and_idxs = node.document.get_subject_attributes_by_type(self._attribute_type_id)

        return any(self.is_attribute_value_national_id_scheme(a) for a, _ in atvs_and_idxs)

    def validate(self, node):
        nra_node = node.children.get('nameRegistrationAuthorities')

        if nra_node is None:
            raise validation.ValidationFindingEncountered(self._name_registration_authorities_missing_validation)

        if not any(g.child[0] == 'uniformResourceIdentifier' for g in nra_node.children.values()):
            raise validation.ValidationFindingEncountered(self._name_registration_authorities_uri_missing_validation)


class NaturalPersonIdentifierNameRegistrationAuthoritiesValidator(NameRegistrationAuthoritiesValidatorBase):
    """
    NAT-5.1.3-05: When a locally defined identity type reference is provided (two characters followed by ":"), the
    nameRegistrationAuthorities element of SemanticsInformation (IETF RFC 3739 [1]) shall be present.
    """
    VALIDATION_NAME_REGISTRATION_AUTHORITIES_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.nat-5.1.3-05.national_id_scheme_name_registration_authorities_missing'
    )

    """
    NAT-5.1.3-06: The nameRegistrationAuthorities element of SemanticsInformation (IETF RFC 3739 [1]) shall
    contain at least a uniformResourceIdentifier generalName.
    """
    VALIDATION_NAME_REGISTRATION_AUTHORITIES_URI_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.nat-5.1.3-05.national_id_scheme_name_registration_authorities_uri_missing'
    )

    def __init__(self):
        super().__init__(
            self.VALIDATION_NAME_REGISTRATION_AUTHORITIES_MISSING,
            self.VALIDATION_NAME_REGISTRATION_AUTHORITIES_URI_MISSING,
            rfc5280.id_at_serialNumber,
            en_319_412_1.id_etsi_qcs_semanticsId_Natural
        )

    @classmethod
    def is_attribute_value_national_id_scheme(cls, atv_node: document.PDUNode) -> bool:
        value_node = atv_node.children['value']

        try:
            _, decoded_value_node = value_node.child

            value_str = str(decoded_value_node.pdu)

            parsed = parse_natural_person_identifier(value_str)
        except ValueError:
            return False

        return parsed.is_national_scheme


class LegalPersonIdentifierNameRegistrationAuthoritiesValidator(NameRegistrationAuthoritiesValidatorBase):
    """
    LEG-5.1.4-05: When a locally defined identity type reference is provided (two characters followed by ":"), the
    nameRegistrationAuthorities element of SemanticsInformation (IETF RFC 3739 [1]) shall be present and
    shall contain at least a uniformResourceIdentifier generalName.
    """
    VALIDATION_NAME_REGISTRATION_AUTHORITIES_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.leg-5.1.4-05.national_id_scheme_name_registration_authorities_missing'
    )

    VALIDATION_NAME_REGISTRATION_AUTHORITIES_URI_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_1.leg-5.1.4-05.national_id_scheme_name_registration_authorities_uri_missing'
    )

    def __init__(self):
        super().__init__(
            self.VALIDATION_NAME_REGISTRATION_AUTHORITIES_MISSING,
            self.VALIDATION_NAME_REGISTRATION_AUTHORITIES_URI_MISSING,
            x520_name.id_at_organizationIdentifier,
            en_319_412_1.id_etsi_qcs_SemanticsId_Legal
        )

    @classmethod
    def is_attribute_value_national_id_scheme(cls, atv_node: document.PDUNode) -> bool:
        value_node = atv_node.children['value']

        try:
            _, decoded_dirstring_node = value_node.child

            _, decoded_value_node = decoded_dirstring_node.child

            value_str = str(decoded_value_node.pdu)

            parsed = organization_id.parse_organization_identifier(value_str)
        except ValueError:
            return False

        return parsed.is_national_scheme
