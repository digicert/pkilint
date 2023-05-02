import re
import typing
import unicodedata
from urllib.parse import urlparse

import publicsuffixlist
from iso3166 import countries_by_alpha2
from pyasn1_alt_modules import rfc5280, rfc8398

from pkilint import validation
from pkilint.cabf import cabf_constants
from pkilint.cabf.cabf_constants import REGISTRATION_SCHEMES
from pkilint.itu import x520_name
from pkilint.pkix import general_name


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


_ORG_ID_REGEX = re.compile(
    r'^(?P<scheme>[A-Z]{3})(?P<country>[a-zA-Z]{2})?(\+(?P<sp>[a-zA-Z0-9]{1,3}))?'
    r'-(?P<reference>.+)$'
)


class OrganizationIdentifierAttributeValidator(validation.TypeMatchingValidator):
    VALIDATION_ORGANIZATION_ID_INVALID_ENCODING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_subject_organization_identifier_encoding'
    )

    VALIDATION_ORGANIZATION_ID_INVALID_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_subject_organization_identifier_format'
    )

    VALIDATION_ORGANIZATION_ID_INVALID_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_subject_organization_identifier_registration_scheme'
    )

    VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_subject_organization_identifier_country'
    )

    VALIDATION_ORGANIZATION_ID_INVALID_SP = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_subject_organization_identifier_state_province_for_scheme'
    )

    VALIDATION_ORGANIZATION_ID_INVALID_SP_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_subject_organization_identifier_state_province_format'
    )

    def __init__(self, additional_schemes: typing.Optional[
            typing.Mapping[str, cabf_constants.RegistrationSchemeNamingConvention]]=None):
        super().__init__(type_oid=x520_name.id_at_organizationIdentifier,
                         type_path='type', value_path='value.x520OrganizationIdentifier',
                         pdu_class=rfc5280.AttributeTypeAndValue,
                         validations=[
                             self.VALIDATION_ORGANIZATION_ID_INVALID_ENCODING,
                             self.VALIDATION_ORGANIZATION_ID_INVALID_FORMAT,
                             self.VALIDATION_ORGANIZATION_ID_INVALID_SCHEME,
                             self.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY,
                             self.VALIDATION_ORGANIZATION_ID_INVALID_SP,
                             self.VALIDATION_ORGANIZATION_ID_INVALID_SP_FORMAT,
                         ]
                         )

        if additional_schemes is None:
            additional_schemes = {}
        self._allowed_schemes = {**REGISTRATION_SCHEMES, **additional_schemes}

    def validate_with_value(self, node, choice_node):
        name, value_node = choice_node.child

        if name not in {'utf8String', 'printableString'}:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ORGANIZATION_ID_INVALID_ENCODING,
                f'Invalid ASN.1 encoding: {name}'
            )

        m = _ORG_ID_REGEX.match(str(value_node.pdu))

        if m is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ORGANIZATION_ID_INVALID_FORMAT,
                f'Invalid format: {value_node.pdu}'
            )

        scheme_info = self._allowed_schemes.get(m['scheme'])

        if scheme_info is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ORGANIZATION_ID_INVALID_SCHEME,
                f'Invalid registration scheme: {m["scheme"]}'
            )

        country_code = '' if m['country'] is None else m['country'].upper()

        if scheme_info.country_identifier_type == cabf_constants.RegistrationSchemeCountryIdentifierType.NONE:
            valid_country_code = (country_code == '')
        elif scheme_info.country_identifier_type == cabf_constants.RegistrationSchemeCountryIdentifierType.XG:
            valid_country_code = (country_code == 'XG')
        elif scheme_info.country_identifier_type == cabf_constants.RegistrationSchemeCountryIdentifierType.ISO3166:
            valid_country_code = (country_code in countries_by_alpha2)
        else:
            raise ValueError(f'Unknown country identifier type for scheme "{m["scheme"]}": '
                             f'{scheme_info.country_identifier_type}')

        if not valid_country_code:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY,
                f'Invalid country code for scheme "{m["scheme"]}": {country_code}'
            )

        if m['sp'] is not None and not scheme_info.allow_state_province:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ORGANIZATION_ID_INVALID_SP,
                f'Scheme "{m["scheme"]}" does not allow state/province values'
            )

        if m['sp'] is not None and not (len(m['sp']) == 2 and m['sp'].isalpha()):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ORGANIZATION_ID_INVALID_SP_FORMAT,
                f'State/province "{m["sp"]}" is not two letters (will be fixed in erratum ballot)'
            )


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
    def __init__(self):
        super().__init__(predicate=general_name.create_generalname_type_predicate('dNSName'))
        
    def validate_with_value(self, node, value):
        if len(value) == 0 and general_name.is_nameconstraints_child_node(node):
            return
        else:
            return super().validate_with_value(node, value)


class UriInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def extract_domain_name(self, node):
        return urlparse(str(node.pdu)).netloc


class GeneralNameUriInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(self):
        super().__init__(predicate=general_name.create_generalname_type_predicate('uniformResourceIdentifier'))

    def extract_domain_name(self, node):
        if general_name.is_nameconstraints_child_node(node):
            return str(node.pdu).lstrip('.')
        else:
            return urlparse(str(node.pdu)).netloc

    def validate_with_value(self, node, value):
        if len(value) == 0 and general_name.is_nameconstraints_child_node(node):
                return
        else:
            return super().validate_with_value(node, value)


class EmailAddressInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def extract_domain_name(self, node):
        _, domain_part = str(node.pdu).split('@', maxsplit=1)

        return domain_part


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
