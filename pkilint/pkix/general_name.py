import codecs
import ipaddress
import math
from urllib.parse import urlparse

import validators
from pyasn1_alt_modules import rfc5280, rfc8398

from pkilint import validation

_GENERALNAME_INSTANCE = rfc5280.GeneralName()
_GENERALNAME_TYPES = [str(n) for n in _GENERALNAME_INSTANCE.componentType]

OTHER_NAME_MAPPINGS = rfc5280.anotherNameMap.copy()


# TODO: consider subclassing from StrEnum when minimum supported Python version is 3.11
class GeneralNameTypeName:
    OTHER_NAME = "otherName"
    RFC822_NAME = "rfc822Name"
    DNS_NAME = "dNSName"
    X400_ADDRESS = "x400Address"
    DIRECTORY_NAME = "directoryName"
    EDI_PARTY_NAME = "ediPartyName"
    UNIFORM_RESOURCE_IDENTIFIER = "uniformResourceIdentifier"
    IP_ADDRESS = "iPAddress"
    REGISTERED_ID = "registeredID"


def validators_predicate(func, value):
    ret = func(value)

    return isinstance(ret, bool) and ret


def is_nameconstraints_child_node(node):
    return any((isinstance(n.pdu, rfc5280.NameConstraints) for n in node.parents))


def create_generalname_type_predicate(generalname_type):
    if generalname_type in _GENERALNAME_TYPES:
        return lambda n: (
            n.name == generalname_type
            and n.parent is not None
            and isinstance(n.parent.pdu, rfc5280.GeneralName)
        )
    else:
        raise ValueError(f"Invalid type specified: {generalname_type}")


class GeneralNameValidatorContainer(validation.ValidatorContainer):
    def __init__(self):
        super().__init__(
            validators=[
                GeneralNameUriSyntaxValidator(),
                GeneralNameDnsNameSyntaxValidator(),
                GeneralNameIpAddressSyntaxValidator(),
                GeneralNameMailboxAddressSyntaxValidator(),
                SmtpUTF8MailboxValidator(),
                GeneralNameDnsNameDomainNameLengthValidator(),
                GeneralNameUriDomainNameLengthValidator(),
                GeneralNameRfc822NameDomainNameLengthValidator(),
                SmtpUTF8MailboxDomainNameLengthValidator(),
            ],
            pdu_class=rfc5280.GeneralName,
        )


class UriSyntaxValidator(validation.Validator):
    VALIDATION_INVALID_URI_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.invalid_uri_syntax"
    )

    VALIDATION_LDAP_URI_NOT_VALIDATED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE, "pkix.ldap_uri_not_validated"
    )

    def __init__(self, **kwargs):
        super().__init__(
            validations=[
                self.VALIDATION_INVALID_URI_SYNTAX,
                self.VALIDATION_LDAP_URI_NOT_VALIDATED,
            ],
            **kwargs,
        )

    def validate_value(self, node):
        value = str(node.pdu)

        if value.casefold().startswith("ldap://".casefold()):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_LDAP_URI_NOT_VALIDATED, value
            )

        return validators_predicate(validators.url, value)

    def validate(self, node):
        if not self.validate_value(node):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_URI_SYNTAX,
                f'Invalid URI syntax: "{str(node.pdu)}"',
            )


class DomainNameSyntaxValidator(validation.Validator):
    VALIDATION_NOT_PREFERRED_NAME_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.invalid_domain_name_syntax"
    )

    def __init__(self, **kwargs):
        super().__init__(
            validations=[self.VALIDATION_NOT_PREFERRED_NAME_SYNTAX], **kwargs
        )

    def validate_value(self, node):
        value = str(node.pdu)

        return validators_predicate(validators.domain, value)

    def validate(self, node):
        if not self.validate_value(node):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NOT_PREFERRED_NAME_SYNTAX,
                f'Invalid domain name syntax: "{str(node.pdu)}"',
            )


class MailboxAddressSyntaxValidator(validation.Validator):
    VALIDATION_INVALID_EMAIL_ADDRESS_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.invalid_email_address_syntax"
    )

    def __init__(self, **kwargs):
        super().__init__(
            validations=[self.VALIDATION_INVALID_EMAIL_ADDRESS_SYNTAX], **kwargs
        )

    def validate_value(self, node):
        value = str(node.pdu)

        return validators_predicate(validators.email, value)

    def validate(self, node):
        if not self.validate_value(node):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_EMAIL_ADDRESS_SYNTAX,
                f'Invalid e-mail address syntax: "{str(node.pdu)}"',
            )


class GeneralNameUriSyntaxValidator(UriSyntaxValidator):
    def __init__(self):
        super().__init__(
            predicate=create_generalname_type_predicate("uniformResourceIdentifier"),
        )

    def validate_value(self, node):
        is_nc_child = is_nameconstraints_child_node(node)

        value = str(node.pdu)

        if is_nc_child:
            if value == ".":
                return True

            if value.startswith("."):
                value = value[1:]

            return validators_predicate(validators.domain, value)
        else:
            return super().validate_value(node)


class GeneralNameDnsNameSyntaxValidator(DomainNameSyntaxValidator):
    def __init__(self):
        super().__init__(predicate=create_generalname_type_predicate("dNSName"))

    def validate_value(self, node):
        value = str(node.pdu)

        if len(value) == 0 and is_nameconstraints_child_node(node):
            return True
        else:
            return super().validate_value(node)


class GeneralNameMailboxAddressSyntaxValidator(MailboxAddressSyntaxValidator):
    def __init__(self):
        super().__init__(
            predicate=create_generalname_type_predicate("rfc822Name"),
        )

    def validate_value(self, node):
        value = str(node.pdu)

        if "@" in value:
            return super().validate_value(node)

        if is_nameconstraints_child_node(node):
            if value == ".":
                return True

            if value.startswith("."):
                value = value[1:]

            return validators_predicate(validators.domain, value)
        else:
            return super().validate_value(node)


def _get_cidr_prefix(address_octets):
    address_bitlen = len(address_octets) * 8

    address = int.from_bytes(address_octets, "big")

    if address == 0:
        return 0

    lsb = int(math.log2(address & -address))

    for i in range(address_bitlen - 1, lsb, -1):
        if address & (1 << i) == 0:
            raise ValueError(f"Netmask bit index {i} is not asserted")

    return address_bitlen - lsb


class GeneralNameIpAddressSyntaxValidator(validation.Validator):
    VALIDATION_IP_ADDRESS_NC_WRONG_LENGTH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.ip_address_name_constraint_wrong_length",
    )

    VALIDATION_IP_ADDRESS_WRONG_LENGTH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.ip_address_wrong_length"
    )

    VALIDATION_IP_ADDRESS_CONSTRAINT_NOT_CIDR = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.ip_address_name_constraint_invalid_cidr",
    )

    def __init__(self):
        super().__init__(
            predicate=create_generalname_type_predicate("iPAddress"),
            validations=[
                self.VALIDATION_IP_ADDRESS_NC_WRONG_LENGTH,
                self.VALIDATION_IP_ADDRESS_WRONG_LENGTH,
                self.VALIDATION_IP_ADDRESS_CONSTRAINT_NOT_CIDR,
            ],
        )

    def validate(self, node):
        is_nc_child = is_nameconstraints_child_node(node)

        length_multiplier = 2 if is_nc_child else 1

        allowed_lengths = [
            address_lengths * length_multiplier for address_lengths in [4, 16]
        ]

        value = node.pdu.asOctets()

        actual_length = len(value)

        if actual_length not in allowed_lengths:
            if is_nc_child:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_IP_ADDRESS_NC_WRONG_LENGTH,
                    f"Invalid IP address contraint length: {actual_length}",
                )
            else:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_IP_ADDRESS_WRONG_LENGTH,
                    f"Invalid IP address length: {actual_length}",
                )

        if is_nc_child:
            midpoint = int(actual_length / 2)

            network = value[0:midpoint]
            mask = value[midpoint:]

            try:
                cidr = _get_cidr_prefix(mask)

                if actual_length == (4 * 2):
                    network_obj = ipaddress.IPv4Address(network)

                    ipaddress.IPv4Network(f"{network_obj}/{cidr}")
                else:
                    network_obj = ipaddress.IPv6Address(network)

                    ipaddress.IPv6Network(f"{network_obj}/{cidr}")
            except ValueError as e:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_IP_ADDRESS_CONSTRAINT_NOT_CIDR, str(e)
                )


class SmtpUTF8MailboxValidator(validation.Validator):
    VALIDATION_NOT_MAILBOX_ADDRESS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.smtp_utf8_mailbox_invalid_syntax",
    )

    VALIDATION_ASCII_ONLY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.smtp_utf8_mailbox_is_ascii_only",
    )

    VALIDATION_HAS_BOM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.smtp_utf8_mailbox_has_bom"
    )

    VALIDATION_DOMAIN_PART_NOT_LOWERCASE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.smtp_utf8_mailbox_has_uppercase",
    )

    """
    RFC 9598, section 3:
     In SmtpUTF8Mailbox, labels that include non-ASCII characters MUST be stored in A-label (rather than U-label)
     form [RFC5890].
    """
    VALIDATION_DOMAIN_PART_INVALID_DOMAIN_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.smtp_utf8_mailbox_domain_part_invalid_syntax",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_NOT_MAILBOX_ADDRESS,
                self.VALIDATION_ASCII_ONLY,
                self.VALIDATION_HAS_BOM,
                self.VALIDATION_DOMAIN_PART_NOT_LOWERCASE,
                self.VALIDATION_DOMAIN_PART_INVALID_DOMAIN_SYNTAX,
            ],
            pdu_class=rfc8398.SmtpUTF8Mailbox,
        )

    def validate(self, node):
        value = str(node.pdu)

        if "@" not in value:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NOT_MAILBOX_ADDRESS
            )

        local_part, domain_part = value.split("@", maxsplit=1)

        if local_part.isascii():
            raise validation.ValidationFindingEncountered(self.VALIDATION_ASCII_ONLY)

        encoded = local_part.encode("utf-8")
        if encoded.startswith(codecs.BOM_UTF8):
            raise validation.ValidationFindingEncountered(self.VALIDATION_HAS_BOM)

        if domain_part != domain_part.lower():
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_DOMAIN_PART_NOT_LOWERCASE
            )

        if not domain_part.isascii() or not validators_predicate(
            validators.domain, domain_part
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_DOMAIN_PART_INVALID_DOMAIN_SYNTAX
            )


class DomainNameLengthValidator(validation.Validator):
    # https://devblogs.microsoft.com/oldnewthing/20120412-00/?p=7873
    _MAX_DOMAIN_NAME_ASCII_LENGTH = 253

    def __init__(self, validation_domain_name_too_long, **kwargs):
        super().__init__(validations=[validation_domain_name_too_long], **kwargs)

        self._validation_domain_name_too_long = validation_domain_name_too_long

    @classmethod
    def extract_value(cls, node):
        pass

    def validate(self, node):
        value = self.extract_value(node)

        value_len = len(value)

        if value_len > self._MAX_DOMAIN_NAME_ASCII_LENGTH:
            raise validation.ValidationFindingEncountered(
                self._validation_domain_name_too_long,
                f'Domain name too long: "{value}" ({value_len} characters) exceeds maximum length of '
                f"{self._MAX_DOMAIN_NAME_ASCII_LENGTH} characters",
            )


class GeneralNameDnsNameDomainNameLengthValidator(DomainNameLengthValidator):
    VALIDATION_DOMAIN_NAME_TOO_LONG = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.dnsname_domain_name_too_long"
    )

    def __init__(self):
        super().__init__(
            self.VALIDATION_DOMAIN_NAME_TOO_LONG,
            predicate=create_generalname_type_predicate("dNSName"),
        )

    @classmethod
    def extract_value(cls, node):
        return str(node.pdu)


class GeneralNameUriDomainNameLengthValidator(DomainNameLengthValidator):
    VALIDATION_DOMAIN_NAME_TOO_LONG = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.uri_domain_name_too_long"
    )

    def __init__(self):
        super().__init__(
            self.VALIDATION_DOMAIN_NAME_TOO_LONG,
            predicate=create_generalname_type_predicate("uniformResourceIdentifier"),
        )

    @classmethod
    def extract_value(cls, node):
        uri_str = str(node.pdu)

        return urlparse(uri_str).hostname or ""


class GeneralNameEmailAddressDomainNameLengthValidator(DomainNameLengthValidator):
    def __init__(self, validation_domain_name_too_long, **kwargs):
        super().__init__(validation_domain_name_too_long, **kwargs)

    @classmethod
    def extract_value(cls, node):
        email_address = str(node.pdu)

        parts = email_address.split("@", maxsplit=1)

        return parts[1] if len(parts) == 2 else ""


class GeneralNameRfc822NameDomainNameLengthValidator(
    GeneralNameEmailAddressDomainNameLengthValidator
):
    VALIDATION_DOMAIN_NAME_TOO_LONG = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.rfc822name_domain_part_too_long",
    )

    def __init__(self):
        super().__init__(
            self.VALIDATION_DOMAIN_NAME_TOO_LONG,
            predicate=create_generalname_type_predicate("rfc822Name"),
        )


class SmtpUTF8MailboxDomainNameLengthValidator(
    GeneralNameEmailAddressDomainNameLengthValidator
):
    VALIDATION_DOMAIN_NAME_TOO_LONG = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.smtputf8mailbox_domain_part_too_long",
    )

    def __init__(self):
        super().__init__(
            self.VALIDATION_DOMAIN_NAME_TOO_LONG, pdu_class=rfc8398.SmtpUTF8Mailbox
        )
