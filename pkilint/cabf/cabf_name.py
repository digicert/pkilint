import ipaddress
import typing
from urllib.parse import urlparse

import publicsuffixlist
import unicodedata
from iso3166 import countries_by_alpha2
from pyasn1_alt_modules import rfc5280, rfc8398

from pkilint import validation, document
from pkilint.common import organization_id
from pkilint.common.organization_id import ParsedOrganizationIdentifier
from pkilint.itu import x520_name
from pkilint.pkix import general_name, Rfc2119Word


class ValidCountryCodeValidatorBase(validation.TypeMatchingValidator):
    def __init__(self, type_oid, value_path, checked_validation):
        super().__init__(type_path='type', type_oid=type_oid,
                         value_path=value_path,
                         pdu_class=rfc5280.AttributeTypeAndValue,
                         validations=[checked_validation]
                         )

    def validate_with_value(self, node, value_node):
        country_code = str(value_node.pdu).upper()

        if country_code == 'XX':
            return
        elif country_code not in countries_by_alpha2:
            raise validation.ValidationFindingEncountered(
                self.validations[0],
                f'Invalid country code: "{country_code}"'
            )


class ValidCountryValidator(ValidCountryCodeValidatorBase):
    VALIDATION_INVALID_COUNTRY_CODE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_country_code'
    )

    def __init__(self):
        super().__init__(type_oid=rfc5280.id_at_countryName,
                         value_path='value.x520countryName',
                         checked_validation=self.VALIDATION_INVALID_COUNTRY_CODE
                         )


class CabfOrganizationIdentifierValidatorBase(organization_id.OrganizationIdentifierValidatorBase):
    VALIDATION_ORGANIZATION_ID_INVALID_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_organization_identifier_registration_scheme'
    )

    VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_organization_identifier_country'
    )

    # the attribute name for this finding is prefixed with an underscore so it's not flagged by the "validation report"
    # test
    _VALIDATION_ORGANIZATION_ID_INVALID_SP_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_organization_identifier_state_province_format'
    )

    REFERENCE_REQUIRED = (Rfc2119Word.MUST, 'cabf.organization_identifier_reference_missing_for_scheme')

    STATE_PROVINCE_PROHIBITED = (Rfc2119Word.MUST_NOT,
                                 'cabf.invalid_subject_organization_identifier_state_province_for_scheme')

    _NTR_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(organization_id.ISO3166_1_COUNTRY_CODES,
                       VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY),
        state_province=(Rfc2119Word.MAY, None),
        reference=REFERENCE_REQUIRED
    )

    _VAT_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(organization_id.ISO3166_1_COUNTRY_CODES | {organization_id.COUNTRY_CODE_GREECE_TRADITIONAL,
                                                                  organization_id.COUNTRY_CODE_NORTHERN_IRELAND},
                       VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY),
        state_province=STATE_PROVINCE_PROHIBITED,
        reference=REFERENCE_REQUIRED
    )

    _PSD_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(organization_id.ISO3166_1_COUNTRY_CODES,
                       VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY),
        state_province=STATE_PROVINCE_PROHIBITED,
        reference=REFERENCE_REQUIRED
    )

    _ALLOWED_SCHEME_MAPPINGS = {
        'NTR': _NTR_SCHEME,
        'VAT': _VAT_SCHEME,
        'PSD': _PSD_SCHEME,
    }

    def __init__(self,
                 invalid_format_validation: typing.Optional[validation.ValidationFinding],
                 additional_schemes: typing.Optional[
                     typing.Mapping[str, organization_id.OrganizationIdentifierElementAllowance]
                 ] = None,
                 enforce_strict_state_province_format=True,
                 additional_validations=None,
                 **kwargs):
        self._allowed_schemes = self._ALLOWED_SCHEME_MAPPINGS.copy()

        if additional_schemes:
            self._allowed_schemes.update(additional_schemes)

        self._enforce_strict_state_province_format = enforce_strict_state_province_format

        additional_validations = [] if additional_validations is None else additional_validations.copy()
        additional_validations.append(self.VALIDATION_ORGANIZATION_ID_INVALID_SCHEME)

        if self._enforce_strict_state_province_format:
            additional_validations.append(self._VALIDATION_ORGANIZATION_ID_INVALID_SP_FORMAT)

        super().__init__(self._allowed_schemes,
                         invalid_format_validation,
                         additional_validations=additional_validations,
                         **kwargs
                         )

    @classmethod
    def handle_unknown_scheme(cls, node: document.PDUNode, parsed: ParsedOrganizationIdentifier):
        raise validation.ValidationFindingEncountered(
            cls.VALIDATION_ORGANIZATION_ID_INVALID_SCHEME,
            f'Invalid registration scheme: "{parsed.scheme}"'
        )

    def validate_with_parsed_value(self, node, parsed):
        if self._enforce_strict_state_province_format and parsed.state_province is not None:
            if len(parsed.state_province) != 2 or not parsed.state_province.isalpha():
                raise validation.ValidationFindingEncountered(
                    self._VALIDATION_ORGANIZATION_ID_INVALID_SP_FORMAT,
                    f'State/province "{parsed.state_province}" is not two letters (will be fixed in erratum ballot)'
                )

        return super().validate_with_parsed_value(node, parsed)


class CabfOrganizationIdentifierAttributeValidator(CabfOrganizationIdentifierValidatorBase):
    VALIDATION_ORGANIZATION_ID_INVALID_ENCODING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_subject_organization_identifier_encoding'
    )

    VALIDATION_ORGANIZATION_ID_INVALID_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_subject_organization_identifier_format'
    )

    def __init__(self,
                 additional_schemes: typing.Optional[
                     typing.Mapping[str, organization_id.OrganizationIdentifierElementAllowance]
                 ] = None,
                 enforce_strict_state_province_format=True):
        super().__init__(self.VALIDATION_ORGANIZATION_ID_INVALID_FORMAT,
                         additional_schemes,
                         enforce_strict_state_province_format,
                         [self.VALIDATION_ORGANIZATION_ID_INVALID_ENCODING],
                         pdu_class=x520_name.X520OrganizationIdentifier)

    @classmethod
    def parse_organization_id_node(cls, node) -> organization_id.ParsedOrganizationIdentifier:
        name, value_node = node.child

        if name not in {'utf8String', 'printableString'}:
            raise validation.ValidationFindingEncountered(
                cls.VALIDATION_ORGANIZATION_ID_INVALID_ENCODING,
                f'Invalid ASN.1 encoding: {name}'
            )

        return organization_id.parse_organization_identifier(str(value_node.pdu))


class RelativeDistinguishedNameContainsOneElementValidator(validation.Validator):
    VALIDATION_RDN_CONTAINS_MULTIPLE_ATVS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'cabf.rdn_contains_multiple_atvs'
    )

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_RDN_CONTAINS_MULTIPLE_ATVS],
                         pdu_class=rfc5280.RelativeDistinguishedName)

    def validate(self, node):
        child_count = len(node.children)

        if child_count > 1:
            raise validation.ValidationFindingEncountered(self.VALIDATION_RDN_CONTAINS_MULTIPLE_ATVS)


class InternalDomainNameValidator(validation.Validator):
    VALIDATION_INTERNAL_DOMAIN_NAME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.internal_domain_name'
    )

    def __init__(self, *args, **kwargs):
        self._psl = publicsuffixlist.PublicSuffixList(accept_unknown=False)

        super().__init__(validations=[self.VALIDATION_INTERNAL_DOMAIN_NAME], **kwargs)

    def extract_domain_name(self, node):
        return str(node.pdu)

    def validate_with_value(self, node, value):
        if self._psl.publicsuffix(value) is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INTERNAL_DOMAIN_NAME,
                f'Internal domain name: "{value}"'
            )

    def validate(self, node):
        domain_name = self.extract_domain_name(node)

        return self.validate_with_value(node, domain_name)


class GeneralNameDnsNameInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(self, allow_onion_tld=False):
        self._allow_onion_tld = allow_onion_tld

        super().__init__(predicate=general_name.create_generalname_type_predicate('dNSName'))

    def validate_with_value(self, node, value):
        if len(value) == 0 and general_name.is_nameconstraints_child_node(node):
            return
        else:
            if self._allow_onion_tld and value.lower().endswith('.onion'):
                return
            else:
                return super().validate_with_value(node, value)


class UriInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def extract_domain_name(self, node):
        return urlparse(str(node.pdu)).hostname or ''


class GeneralNameUriInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(self):
        super().__init__(predicate=general_name.create_generalname_type_predicate('uniformResourceIdentifier'))

    def extract_domain_name(self, node):
        if general_name.is_nameconstraints_child_node(node):
            return str(node.pdu).lstrip('.')
        else:
            return urlparse(str(node.pdu)).hostname or ''

    def validate_with_value(self, node, value):
        if len(value) == 0 and general_name.is_nameconstraints_child_node(node):
            return
        else:
            return super().validate_with_value(node, value)


class EmailAddressInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def extract_domain_name(self, node):
        parts = str(node.pdu).split('@', maxsplit=1)

        return parts[1] if len(parts) == 2 else ''


class GeneralNameRfc822NameInternalDomainNameValidator(EmailAddressInternalDomainNameValidator):
    def __init__(self):
        super().__init__(predicate=general_name.create_generalname_type_predicate('rfc822Name'))

    def extract_domain_name(self, node):
        if general_name.is_nameconstraints_child_node(node):
            return str(node.pdu).lstrip('.')
        else:
            return super().extract_domain_name(node)

    def validate_with_value(self, node, value):
        if len(value) == 0 and general_name.is_nameconstraints_child_node(node):
            return
        else:
            super().validate_with_value(node, value)


class SmtpUtf8MailboxInternalDomainNameValidator(EmailAddressInternalDomainNameValidator):
    def __init__(self):
        super().__init__(pdu_class=rfc8398.SmtpUTF8Mailbox)

    def extract_domain_name(self, node):
        domain_part = super().extract_domain_name(node)

        return domain_part.encode('idna').decode()


class InternalIpAddressValidator(validation.Validator):
    VALIDATION_INTERNAL_IP_ADDRESS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.internal_ip_address'
    )

    def __init__(self, *args, **kwargs):
        super().__init__(validations=self.VALIDATION_INTERNAL_IP_ADDRESS, **kwargs)

    @staticmethod
    def _extract_ip_address(node):
        octets = node.pdu.asOctets()

        if len(octets) == 4:
            return ipaddress.IPv4Address(octets)
        else:
            return ipaddress.IPv6Address(octets)

    def validate(self, node):
        ip_addr = InternalIpAddressValidator._extract_ip_address(node)

        if not ip_addr.is_global:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INTERNAL_IP_ADDRESS,
                f'Internal IP address: "{ip_addr}"'
            )


class GeneralNameInternalIpAddressValidator(InternalIpAddressValidator):
    def __init__(self):
        super().__init__(predicate=general_name.create_generalname_type_predicate('iPAddress'))

    def validate(self, node):
        if general_name.is_nameconstraints_child_node(node):
            return

        super().validate(node)


class OrganizationNameTruncatedLegalNameValidator(validation.Validator):
    VALIDATION_ORGANIZATION_NAME_TRUNCATED_LEGAL_NAME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.organization_name_no_closing_parenthesis'
    )

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_ORGANIZATION_NAME_TRUNCATED_LEGAL_NAME],
                         pdu_class=rfc5280.X520OrganizationName)

    def validate(self, node):
        _, value_node = node.child

        value = unicodedata.normalize('NFC', str(value_node.pdu))

        open_paren_idx = value.find('(')
        if open_paren_idx < 0:
            return

        close_paren_idx = value.find(')', open_paren_idx)

        if close_paren_idx < 0:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ORGANIZATION_NAME_TRUNCATED_LEGAL_NAME,
                f'Organization name attribute with truncated legal name: "{value}"'
            )
