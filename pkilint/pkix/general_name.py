import codecs
import ipaddress
import math

import validators
from pyasn1_alt_modules import rfc5280, rfc8398

from pkilint import validation

_GENERALNAME_INSTANCE = rfc5280.GeneralName()
_GENERALNAME_TYPES = [str(n) for n in _GENERALNAME_INSTANCE.componentType]

OTHER_NAME_MAPPINGS = rfc5280.anotherNameMap.copy()


def validators_predicate(func, value):
    ret = func(value)

    return isinstance(ret, bool) and ret


def is_nameconstraints_child_node(node):
    return any((isinstance(n.pdu, rfc5280.NameConstraints) for n in node.parents))


def create_generalname_type_predicate(generalname_type):
    if generalname_type in _GENERALNAME_TYPES:
        return lambda n: (
                n.name == generalname_type and
                n.parent is not None and
                isinstance(n.parent.pdu, rfc5280.GeneralName)
        )
    else:
        raise ValueError(f'Invalid type specified: {generalname_type}')


class UriSyntaxValidator(validation.Validator):
    VALIDATION_INVALID_URI_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.invalid_uri_syntax'
    )

    VALIDATION_LDAP_URI_NOT_VALIDATED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'pkix.ldap_uri_not_validated'
    )

    def __init__(self, **kwargs):
        super().__init__(validations=[self.VALIDATION_INVALID_URI_SYNTAX, self.VALIDATION_LDAP_URI_NOT_VALIDATED],
                         **kwargs
                         )

    def validate_value(self, node):
        value = str(node.pdu)

        if value.casefold().startswith('ldap://'.casefold()):
            raise validation.ValidationFindingEncountered(self.VALIDATION_LDAP_URI_NOT_VALIDATED, value)

        return validators_predicate(validators.url, value)

    def validate(self, node):
        if not self.validate_value(node):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_URI_SYNTAX,
                f'Invalid URI syntax: "{str(node.pdu)}"'
            )


class DomainNameSyntaxValidator(validation.Validator):
    VALIDATION_NOT_PREFERRED_NAME_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.invalid_domain_name_syntax'
    )

    def __init__(self, **kwargs):
        super().__init__(validations=[
            self.VALIDATION_NOT_PREFERRED_NAME_SYNTAX
        ],
            **kwargs
        )

    def validate_value(self, node):
        value = str(node.pdu)

        return validators_predicate(validators.domain, value)

    def validate(self, node):
        if not self.validate_value(node):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NOT_PREFERRED_NAME_SYNTAX,
                f'Invalid domain name syntax: "{str(node.pdu)}"'
            )


class MailboxAddressSyntaxValidator(validation.Validator):
    VALIDATION_INVALID_EMAIL_ADDRESS_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.invalid_email_address_syntax'
    )

    def __init__(self, **kwargs):
        super().__init__(validations=[
            self.VALIDATION_INVALID_EMAIL_ADDRESS_SYNTAX
        ],
            **kwargs
        )

    def validate_value(self, node):
        value = str(node.pdu)

        return validators_predicate(validators.email, value)

    def validate(self, node):
        if not self.validate_value(node):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_EMAIL_ADDRESS_SYNTAX,
                f'Invalid e-mail address syntax: "{str(node.pdu)}"'
            )


class GeneralNameUriSyntaxValidator(UriSyntaxValidator):
    def __init__(self):
        super().__init__(
            predicate=create_generalname_type_predicate(
                'uniformResourceIdentifier'
            ),
        )

    def validate_value(self, node):
        is_nc_child = is_nameconstraints_child_node(node)

        value = str(node.pdu)

        if is_nc_child:
            if value == '.':
                return True

            if value.startswith('.'):
                value = value[1:]

            return validators_predicate(validators.domain, value)
        else:
            return super().validate_value(node)


class GeneralNameDnsNameSyntaxValidator(DomainNameSyntaxValidator):
    def __init__(self):
        super().__init__(
            predicate=create_generalname_type_predicate('dNSName')
        )

    def validate_value(self, node):
        value = str(node.pdu)

        if len(value) == 0 and is_nameconstraints_child_node(node):
            return True
        else:
            return super().validate_value(node)


class GeneralNameMailboxAddressSyntaxValidator(MailboxAddressSyntaxValidator):
    def __init__(self):
        super().__init__(
            predicate=create_generalname_type_predicate('rfc822Name'),
        )

    def validate_value(self, node):
        value = str(node.pdu)

        if '@' in value:
            return super().validate_value(node)

        if is_nameconstraints_child_node(node):
            if value == '.':
                return True

            if value.startswith('.'):
                value = value[1:]

            return validators_predicate(validators.domain, value)
        else:
            return super().validate_value(node)


def _get_cidr_prefix(address_octets):
    address_bitlen = len(address_octets) * 8

    address = int.from_bytes(address_octets, 'big')

    if address == 0:
        return 0

    lsb = int(math.log2(address & -address))

    for i in range(address_bitlen - 1, lsb, -1):
        if address & (1 << i) == 0:
            raise ValueError(f'Netmask bit index {i} is not asserted')

    return address_bitlen - lsb


class GeneralNameIpAddressSyntaxValidator(validation.Validator):
    VALIDATION_IP_ADDRESS_NC_WRONG_LENGTH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.ip_address_name_constraint_wrong_length'
    )

    VALIDATION_IP_ADDRESS_WRONG_LENGTH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.ip_address_wrong_length'
    )

    VALIDATION_IP_ADDRESS_CONSTRAINT_NOT_CIDR = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.ip_address_name_constraint_invalid_cidr'
    )

    def __init__(self):
        super().__init__(
            predicate=create_generalname_type_predicate('iPAddress'),
            validations=[
                self.VALIDATION_IP_ADDRESS_NC_WRONG_LENGTH,
                self.VALIDATION_IP_ADDRESS_WRONG_LENGTH,
                self.VALIDATION_IP_ADDRESS_CONSTRAINT_NOT_CIDR,
            ]
        )

    def validate(self, node):
        is_nc_child = is_nameconstraints_child_node(node)

        length_multiplier = 2 if is_nc_child else 1

        allowed_lengths = [address_lengths * length_multiplier for address_lengths in [4, 16]]

        value = node.pdu.asOctets()

        actual_length = len(value)

        if actual_length not in allowed_lengths:
            if is_nc_child:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_IP_ADDRESS_NC_WRONG_LENGTH,
                    f'Invalid IP address contraint length: {actual_length}'
                )
            else:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_IP_ADDRESS_WRONG_LENGTH,
                    f'Invalid IP address length: {actual_length}'
                )

        if is_nc_child:
            midpoint = int(actual_length / 2)

            network = value[0:midpoint]
            mask = value[midpoint:]

            try:
                cidr = _get_cidr_prefix(mask)

                if actual_length == (4 * 2):
                    network_obj = ipaddress.IPv4Address(network)

                    ipaddress.IPv4Network(f'{network_obj}/{cidr}')
                else:
                    network_obj = ipaddress.IPv6Address(network)

                    ipaddress.IPv6Network(f'{network_obj}/{cidr}')
            except ValueError as e:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_IP_ADDRESS_CONSTRAINT_NOT_CIDR,
                    str(e)
                )


class SmtpUTF8MailboxValidator(validation.Validator):
    VALIDATION_NOT_MAILBOX_ADDRESS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.smtp_utf8_mailbox_invalid_syntax'
    )

    VALIDATION_ASCII_ONLY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.smtp_utf8_mailbox_is_ascii_only'
    )

    VALIDATION_HAS_BOM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.smtp_utf8_mailbox_has_bom'
    )

    VALIDATION_DOMAIN_PART_NOT_LOWERCASE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.smtp_utf8_mailbox_has_uppercase'
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_NOT_MAILBOX_ADDRESS,
                self.VALIDATION_ASCII_ONLY,
                self.VALIDATION_HAS_BOM,
                self.VALIDATION_DOMAIN_PART_NOT_LOWERCASE,
            ],
            pdu_class=rfc8398.SmtpUTF8Mailbox
        )

    def validate(self, node):
        value = str(node.pdu)

        if '@' not in value:
            raise validation.ValidationFindingEncountered(self.VALIDATION_NOT_MAILBOX_ADDRESS)

        local_part, domain_part = value.split('@', maxsplit=1)

        if local_part.isascii():
            raise validation.ValidationFindingEncountered(self.VALIDATION_ASCII_ONLY)

        encoded = local_part.encode('utf-8')
        if encoded.startswith(codecs.BOM_UTF8):
            raise validation.ValidationFindingEncountered(self.VALIDATION_HAS_BOM)

        if domain_part != domain_part.lower():
            raise validation.ValidationFindingEncountered(self.VALIDATION_DOMAIN_PART_NOT_LOWERCASE)
