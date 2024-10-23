import base64
import binascii
import re

from cryptography.hazmat.primitives import hashes
from pyasn1_alt_modules import rfc5280

from pkilint import validation
from pkilint.cabf.asn1 import ev_guidelines
from pkilint.cabf.cabf_name import ValidCountryCodeValidatorBase
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.itu import x520_name
from pkilint.pkix import name, general_name


class ValidJurisdictionCountryValidator(ValidCountryCodeValidatorBase):
    """Validates that the jurisdictionCountryName value conforms to EVG 9.2.4."""

    VALIDATION_INVALID_COUNTRY_CODE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.invalid_jurisdiction_country_code",
    )

    def __init__(self):
        super().__init__(
            type_oid=ev_guidelines.id_evat_jurisdiction_countryName,
            value_path="value.eVGJurisdictionCountryName",
            checked_validation=self.VALIDATION_INVALID_COUNTRY_CODE,
        )


class ValidBusinessCategoryValidator(validation.Validator):
    """Validates that the businessCategory value conforms to EVG 9.2.3."""

    VALIDATION_INVALID_BUSINESS_CATEGORY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.ev_guidelines.invalid_business_category",
    )

    _ALLOWED_VALUES = {
        "Private Organization",
        "Government Entity",
        "Business Entity",
        "Non-Commercial Entity",
    }

    def __init__(self):
        super().__init__(
            pdu_class=x520_name.X520BusinessCategory,
            validations=[self.VALIDATION_INVALID_BUSINESS_CATEGORY],
        )

    def validate(self, node):
        # BusinessCategory is a CHOICE so retrieve the child node value
        business_category = str(node.child[1].pdu)

        if business_category not in self._ALLOWED_VALUES:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_BUSINESS_CATEGORY,
                f'Invalid business category: "{business_category}"',
            )


class X520NameAttributeValueLengthValidator(validation.Validator):
    """Validates that the length of X520Name values does not exceed the limit stated in BR 7.1.4.2."""

    VALIDATION_NAME_VALUE_TOO_LONG = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.name_attribute_value_too_long",
    )

    _MAX_NAME_LENGTH_CHARS = 64

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_NAME_VALUE_TOO_LONG, pdu_class=rfc5280.X520name
        )

    def validate(self, node):
        _, value_node = node.child

        value = str(value_node.pdu)

        if len(value) > self._MAX_NAME_LENGTH_CHARS:
            raise validation.ValidationFindingEncountered(
                self._validations[0],
                f'Attribute value exceeds maximum length of {self._MAX_NAME_LENGTH_CHARS}: "{value}"',
            )


class DomainComponentAttributeValueLengthValidator(validation.Validator):
    """Validates that the length of domainComponent values does not exceed the limit stated in BR 7.1.4.2."""

    VALIDATION_DC_ATTRIBUTE_VALUE_TOO_LONG = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.domain_component_attribute_value_length_too_long",
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_DC_ATTRIBUTE_VALUE_TOO_LONG,
            pdu_class=rfc5280.DomainComponent,
        )

    def validate(self, node):
        value_str = str(node.pdu)

        if len(value_str) > 63:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_DC_ATTRIBUTE_VALUE_TOO_LONG
            )


class AttributeValueDirectoryStringValidator(validation.Validator):
    """Validates that DirectoryString attributes are encoded as per 7.1.4.2."""

    VALIDATION_ATTRIBUTE_VALUE_INVALID_ENCODING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.attribute_value_invalid_encoding_type",
    )

    _ENFORCED_ATTRIBUTE_TYPE_OIDS = {
        rfc5280.id_at_stateOrProvinceName,
        rfc5280.id_at_localityName,
        x520_name.id_at_postalCode,
        x520_name.id_at_streetAddress,
        rfc5280.id_at_organizationName,
        rfc5280.id_at_surname,
        rfc5280.id_at_givenName,
        rfc5280.id_at_organizationalUnitName,
        rfc5280.id_at_commonName,
        x520_name.id_at_businessCategory,
        ev_guidelines.id_evat_jurisdiction_stateOrProvinceName,
        ev_guidelines.id_evat_jurisdiction_localityName,
        x520_name.id_at_organizationIdentifier,
    }

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_ATTRIBUTE_VALUE_INVALID_ENCODING,
            pdu_class=rfc5280.AttributeTypeAndValue,
            predicate=lambda n: n.navigate("type").pdu
            in self._ENFORCED_ATTRIBUTE_TYPE_OIDS,
        )

    def validate(self, node):
        value_node = node.navigate("value")

        if not any(value_node.children):
            # unparsed attribute
            return

        _, parsed_attr = value_node.child
        directory_string_choice_name, _ = parsed_attr.child

        if directory_string_choice_name not in {"utf8String", "printableString"}:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ATTRIBUTE_VALUE_INVALID_ENCODING,
                f"Invalid attribute value encoding: {directory_string_choice_name}",
            )


class AttributeOrderEncodingValidator(validation.Validator):
    """Validates that the encoded order of subject attributes conforms to the list in BR 7.1.4.2."""

    VALIDATION_INVALID_RDN_ORDER = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.serverauth.invalid_rdn_order"
    )

    _ENFORCED_ATTRIBUTE_TYPE_OIDS = [
        rfc5280.id_domainComponent,
        rfc5280.id_at_countryName,
        rfc5280.id_at_stateOrProvinceName,
        rfc5280.id_at_localityName,
        x520_name.id_at_postalCode,
        x520_name.id_at_streetAddress,
        rfc5280.id_at_organizationName,
        rfc5280.id_at_surname,
        rfc5280.id_at_givenName,
        rfc5280.id_at_organizationalUnitName,
        rfc5280.id_at_commonName,
    ]

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_INVALID_RDN_ORDER,
            path="certificate.tbsCertificate.subject.rdnSequence",
        )

    def validate(self, node):
        enforced_order_cursor_idx = None

        # assume each RDN has one ATV
        for rdn in node.children.values():
            attr_oid = rdn.children["0"].children["type"].pdu

            try:
                idx = self._ENFORCED_ATTRIBUTE_TYPE_OIDS.index(attr_oid)
            except ValueError:
                continue

            if enforced_order_cursor_idx is None:
                enforced_order_cursor_idx = idx
            elif idx < enforced_order_cursor_idx:
                current_rdn_oid = str(attr_oid)
                enforced_order_oid = str(
                    self._ENFORCED_ATTRIBUTE_TYPE_OIDS[enforced_order_cursor_idx]
                )

                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_INVALID_RDN_ORDER,
                    f"Invalid RDN order: {current_rdn_oid} follows {enforced_order_oid}",
                )
            else:
                enforced_order_cursor_idx = idx


class ServerauthRelativeDistinguishedNameContainsOneElementValidator(
    validation.Validator
):
    """Validates that each RelativeDistguishedName contains exactly one AttributeTypeAndValue, as per BR 7.1.4.2."""

    VALIDATION_RDN_CONTAINS_MULTIPLE_ATVS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.rdn_contains_multiple_atvs",
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


class ServerauthDuplicateAttributeTypeValidator(name.DuplicateAttributeTypeValidator):
    """Validates that only specified attributes may appear multiple times as per BR 7.1.2.3 and 7.1.2.7.4."""

    VALIDATION_DUPLICATE_ATTRIBUTE_TYPES = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.prohibited_duplicate_attribute_type",
    )

    def __init__(self, certificate_type):
        allowed_oids = set()

        if certificate_type in {
            serverauth_constants.CertificateType.OV_FINAL_CERTIFICATE,
            serverauth_constants.CertificateType.OV_PRE_CERTIFICATE,
        }:
            allowed_oids.add(rfc5280.id_domainComponent)

        if certificate_type not in {
            serverauth_constants.CertificateType.DV_FINAL_CERTIFICATE,
            serverauth_constants.CertificateType.DV_PRE_CERTIFICATE,
        }:
            allowed_oids.add(x520_name.id_at_streetAddress)

        super().__init__(
            allowed_duplicate_oid_set=allowed_oids,
            validation=self.VALIDATION_DUPLICATE_ATTRIBUTE_TYPES,
        )


# BR 7.1.2.7.12
class DnsNameLdhLabelSyntaxValidator(validation.Validator):
    """Validates that each dNSName conforms to the syntax in BR 7.1.2.7.12."""

    VALIDATION_INVALID_DNSNAME_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.invalid_dnsname_syntax",
    )

    VALIDATION_PROHIBITED_RESERVED_LABEL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.dnsname_contains_prohibited_reserved_label",
    )

    VALIDATION_INVALID_PLABEL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.invalid_plabel_encoding",
    )

    _ACE_REGEX = re.compile(r"^(?P<tag>.{2})--(?P<ace>.+)$", re.RegexFlag.IGNORECASE)
    _NON_LDH_CHAR_REGEX = re.compile(r"[^a-zA-Z0-9-]")

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_INVALID_DNSNAME_SYNTAX,
                self.VALIDATION_PROHIBITED_RESERVED_LABEL,
                self.VALIDATION_INVALID_PLABEL,
            ],
            predicate=general_name.create_generalname_type_predicate("dNSName"),
        )

    def _is_valid_ldh_syntax(self, label):
        label_len = len(label)

        return (
            0 < label_len <= 63
            and self._NON_LDH_CHAR_REGEX.search(label) is None
            and not label.startswith("-")
            and not label.endswith("-")
        )

    def validate(self, node):
        value = str(node.pdu)

        in_nc = any((isinstance(n.pdu, rfc5280.NameConstraints) for n in node.parents))

        if in_nc and len(value) == 0:
            return

        fqdn = value[2:] if not in_nc and value.startswith("*.") else value

        labels = fqdn.split(".")

        for label in labels:
            if not self._is_valid_ldh_syntax(label):
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_INVALID_DNSNAME_SYNTAX,
                    f'Non-LDH domain label "{label}" in domain name "{value}"',
                )

            m = self._ACE_REGEX.search(label)

            if m is None:
                continue

            tag = m.group("tag")

            if tag.casefold() != "xn".casefold():
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_PROHIBITED_RESERVED_LABEL,
                    f'Invalid reserved label "{label}" with tag "{tag}" in domain name "{value}"',
                )

            try:
                _ = m.group("ace").encode().decode("punycode")
            except UnicodeError:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_INVALID_PLABEL,
                    f'Invalid P-Label "{label}" in domain name "{value}"',
                )


class TorVersion3DomainNameValidator(validation.Validator):
    """Validates that each Onion Domain Name conforms to the Tor v3 specification."""

    VALIDATION_INVALID_TOR_V3_NAME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.invalid_tor_v3_domain_name",
    )

    VALIDATION_INVALID_TOR_VERSION = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.invalid_tor_version",
    )

    VALIDATION_INVALID_TOR_CHECKSUM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.invalid_tor_checksum",
    )

    _CHECKSUM = b".onion checksum"
    _VERSION = 0x03

    _ONION_V3_DOMAIN_NAME_REGEX = re.compile(
        r"^([^.]+\.)*(?P<descriptor>[a-z2-7]{56})(\.onion)?$", re.IGNORECASE
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_INVALID_TOR_V3_NAME,
                self.VALIDATION_INVALID_TOR_VERSION,
                self.VALIDATION_INVALID_TOR_CHECKSUM,
            ],
            predicate=general_name.create_generalname_type_predicate("dNSName"),
        )

    @staticmethod
    def _calculate_checksum(pubkey_octets):
        s = bytearray()
        s.extend(TorVersion3DomainNameValidator._CHECKSUM)
        s.extend(pubkey_octets)
        s.append(TorVersion3DomainNameValidator._VERSION)

        h = hashes.Hash(hashes.SHA3_256())
        h.update(s)
        digest = h.finalize()

        return digest[:2]

    def validate(self, node):
        value = str(node.pdu)

        if not value.lower().endswith(".onion"):
            return

        m = self._ONION_V3_DOMAIN_NAME_REGEX.match(value)

        if m is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_TOR_V3_NAME,
                f'Invalid Tor v3 domain name: "{value}"',
            )

        try:
            decoded = base64.b32decode(m.group("descriptor").upper())
        except binascii.Error:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_TOR_V3_NAME,
                f'Invalid Base-32 encoding for descriptor: "{value}"',
            )

        version = decoded[-1]

        if version != self._VERSION:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_TOR_VERSION,
                f'Invalid Tor version {version} in domain name: "{value}"',
            )

        actual_checksum = decoded[-3:-1]
        pubkey_octets = decoded[0:32]

        expected_checksum = TorVersion3DomainNameValidator._calculate_checksum(
            pubkey_octets
        )

        if actual_checksum != expected_checksum:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_TOR_CHECKSUM,
                f"Invalid Tor v3 checksum. Expected: {expected_checksum.hex()}, actual: {actual_checksum.hex()}",
            )
