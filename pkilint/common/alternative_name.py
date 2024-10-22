import ipaddress
from urllib.parse import urlparse

import publicsuffixlist
from pyasn1_alt_modules import rfc8398, rfc5280

from pkilint import validation
from pkilint.pkix import general_name


class InternalDomainNameValidator(validation.Validator):
    def __init__(
        self,
        validation_internal_domain_name_present: validation.ValidationFinding,
        *args,
        **kwargs,
    ):
        self._psl = publicsuffixlist.PublicSuffixList(accept_unknown=False)

        super().__init__(
            validations=[validation_internal_domain_name_present], **kwargs
        )

        self._validation_internal_domain_name_present = (
            validation_internal_domain_name_present
        )

    @classmethod
    def extract_domain_name(cls, node):
        return str(node.pdu)

    def validate_with_value(self, node, value):
        if self._psl.publicsuffix(value) is None:
            raise validation.ValidationFindingEncountered(
                self._validation_internal_domain_name_present,
                f'Internal domain name: "{value}"',
            )

    def validate(self, node):
        domain_name = self.extract_domain_name(node)

        return self.validate_with_value(node, domain_name)


class GeneralNameDnsNameInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(
        self,
        validation_internal_domain_name_present: validation.ValidationFinding,
        allow_onion_tld=False,
    ):
        self._allow_onion_tld = allow_onion_tld

        super().__init__(
            validation_internal_domain_name_present,
            predicate=general_name.create_generalname_type_predicate(
                general_name.GeneralNameTypeName.DNS_NAME
            ),
        )

    def validate_with_value(self, node, value):
        if len(value) == 0 and general_name.is_nameconstraints_child_node(node):
            return
        else:
            if self._allow_onion_tld and value.lower().endswith(".onion"):
                return
            else:
                return super().validate_with_value(node, value)


class UriInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(
        self,
        validation_internal_domain_name_present: validation.ValidationFinding,
        *args,
        **kwargs,
    ):
        super().__init__(validation_internal_domain_name_present, *args, **kwargs)

    def extract_domain_name(self, node):
        return urlparse(str(node.pdu)).hostname or ""


class GeneralNameUriInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(
        self, validation_internal_domain_name_present: validation.ValidationFinding
    ):
        super().__init__(
            validation_internal_domain_name_present,
            predicate=general_name.create_generalname_type_predicate(
                general_name.GeneralNameTypeName.UNIFORM_RESOURCE_IDENTIFIER
            ),
        )

    def extract_domain_name(self, node):
        if general_name.is_nameconstraints_child_node(node):
            return str(node.pdu).lstrip(".")
        else:
            return urlparse(str(node.pdu)).hostname or ""

    def validate_with_value(self, node, value):
        if len(value) == 0 and general_name.is_nameconstraints_child_node(node):
            return
        else:
            return super().validate_with_value(node, value)


class EmailAddressInternalDomainNameValidator(InternalDomainNameValidator):
    def __init__(
        self,
        validation_internal_domain_name_present: validation.ValidationFinding,
        *args,
        **kwargs,
    ):
        super().__init__(validation_internal_domain_name_present, *args, **kwargs)

    def extract_domain_name(self, node):
        parts = str(node.pdu).split("@", maxsplit=1)

        return parts[1] if len(parts) == 2 else ""


class GeneralNameRfc822NameInternalDomainNameValidator(
    EmailAddressInternalDomainNameValidator
):
    def __init__(
        self, validation_internal_domain_name_present: validation.ValidationFinding
    ):
        super().__init__(
            validation_internal_domain_name_present,
            predicate=general_name.create_generalname_type_predicate(
                general_name.GeneralNameTypeName.RFC822_NAME
            ),
        )

    def extract_domain_name(self, node):
        if general_name.is_nameconstraints_child_node(node):
            return str(node.pdu).lstrip(".")
        else:
            return super().extract_domain_name(node)

    def validate_with_value(self, node, value):
        if len(value) == 0 and general_name.is_nameconstraints_child_node(node):
            return
        else:
            super().validate_with_value(node, value)


class SmtpUtf8MailboxInternalDomainNameValidator(
    EmailAddressInternalDomainNameValidator
):
    def __init__(
        self, validation_internal_domain_name_present: validation.ValidationFinding
    ):
        super().__init__(
            validation_internal_domain_name_present, pdu_class=rfc8398.SmtpUTF8Mailbox
        )

    def extract_domain_name(self, node):
        domain_part = super().extract_domain_name(node)

        # remove ToASCII once RFC 9598 is published
        return domain_part.encode("idna").decode()


class InternalIpAddressValidator(validation.Validator):
    def __init__(
        self,
        validation_internal_ip_address_present: validation.ValidationFinding,
        *args,
        **kwargs,
    ):
        super().__init__(validations=[validation_internal_ip_address_present], **kwargs)

        self._validation_internal_ip_address_present = (
            validation_internal_ip_address_present
        )

    @classmethod
    def _extract_ip_address(cls, node):
        octets = node.pdu.asOctets()

        if len(octets) == 4:
            return ipaddress.IPv4Address(octets)
        else:
            return ipaddress.IPv6Address(octets)

    def validate(self, node):
        ip_addr = self._extract_ip_address(node)

        if not ip_addr.is_global:
            raise validation.ValidationFindingEncountered(
                self._validation_internal_ip_address_present,
                f'Internal IP address: "{ip_addr}"',
            )


class GeneralNameInternalIpAddressValidator(InternalIpAddressValidator):
    def __init__(
        self, validation_internal_ip_address_present: validation.ValidationFinding
    ):
        super().__init__(
            validation_internal_ip_address_present,
            predicate=general_name.create_generalname_type_predicate(
                general_name.GeneralNameTypeName.IP_ADDRESS
            ),
        )

    def validate(self, node):
        if general_name.is_nameconstraints_child_node(node):
            return

        super().validate(node)


def create_internal_name_validator_container(
    validation_internal_domain_name_present: validation.ValidationFinding,
    validation_internal_ip_address_present: validation.ValidationFinding,
    allow_onion_tld: bool = False,
):
    validators = [
        GeneralNameDnsNameInternalDomainNameValidator(
            validation_internal_domain_name_present, allow_onion_tld
        ),
        GeneralNameUriInternalDomainNameValidator(
            validation_internal_domain_name_present
        ),
        GeneralNameRfc822NameInternalDomainNameValidator(
            validation_internal_domain_name_present
        ),
        SmtpUtf8MailboxInternalDomainNameValidator(
            validation_internal_domain_name_present
        ),
        GeneralNameInternalIpAddressValidator(validation_internal_ip_address_present),
    ]

    return validation.ValidatorContainer(
        validators=validators, pdu_class=rfc5280.GeneralName
    )


def create_cpsuri_internal_domain_name_validator(
    validation_internal_domain_name_present: validation.ValidationFinding,
):
    return UriInternalDomainNameValidator(
        validation_internal_domain_name_present, pdu_class=rfc5280.CPSuri
    )
