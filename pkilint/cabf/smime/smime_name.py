import re

import validators
from pyasn1_alt_modules import rfc5280, rfc8398

from pkilint import validation, pkix, oid
from pkilint.cabf import cabf_name
from pkilint.cabf.cabf_name import CabfOrganizationIdentifierAttributeValidator
from pkilint.cabf.smime.smime_constants import Generation, ValidationLevel
from pkilint.common import organization_id
from pkilint.common.organization_id import OrganizationIdentifierLeiValidator
from pkilint.itu import x520_name, asn1_util
from pkilint.pkix import certificate, name, Rfc2119Word, general_name

SHALL = pkix.Rfc2119Word.SHALL
SHALL_NOT = pkix.Rfc2119Word.SHALL_NOT
MAY = pkix.Rfc2119Word.MAY

_MV_ATTRIBUTES = {
    rfc5280.id_at_commonName: (MAY, MAY, MAY),
    rfc5280.id_at_organizationName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_organizationalUnitName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    x520_name.id_at_organizationIdentifier: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_givenName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_surname: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_pseudonym: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_serialNumber: (MAY, MAY, MAY),
    rfc5280.id_emailAddress: (MAY, MAY, MAY),
    rfc5280.id_at_title: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    x520_name.id_at_streetAddress: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_localityName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_stateOrProvinceName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    x520_name.id_at_postalCode: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_countryName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
}

_OV_ATTRIBUTES = {
    rfc5280.id_at_commonName: (MAY, MAY, MAY),
    rfc5280.id_at_organizationName: (SHALL, SHALL, SHALL),
    rfc5280.id_at_organizationalUnitName: (MAY, MAY, MAY),
    x520_name.id_at_organizationIdentifier: (SHALL, SHALL, SHALL),
    rfc5280.id_at_givenName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_surname: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_pseudonym: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_serialNumber: (MAY, MAY, MAY),
    rfc5280.id_emailAddress: (MAY, MAY, MAY),
    rfc5280.id_at_title: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    x520_name.id_at_streetAddress: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_localityName: (MAY, MAY, MAY),
    rfc5280.id_at_stateOrProvinceName: (MAY, MAY, MAY),
    x520_name.id_at_postalCode: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_countryName: (MAY, MAY, MAY),
}

_SV_ATTRIBUTES = {
    rfc5280.id_at_commonName: (MAY, MAY, MAY),
    rfc5280.id_at_organizationName: (SHALL, SHALL, SHALL),
    rfc5280.id_at_organizationalUnitName: (MAY, MAY, MAY),
    x520_name.id_at_organizationIdentifier: (SHALL, SHALL, SHALL),
    rfc5280.id_at_givenName: (MAY, MAY, MAY),
    rfc5280.id_at_surname: (MAY, MAY, MAY),
    rfc5280.id_at_pseudonym: (MAY, MAY, MAY),
    rfc5280.id_at_serialNumber: (MAY, MAY, MAY),
    rfc5280.id_emailAddress: (MAY, MAY, MAY),
    rfc5280.id_at_title: (MAY, MAY, MAY),
    x520_name.id_at_streetAddress: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_localityName: (MAY, MAY, MAY),
    rfc5280.id_at_stateOrProvinceName: (MAY, MAY, MAY),
    x520_name.id_at_postalCode: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_countryName: (MAY, MAY, MAY),
}

_IV_ATTRIBUTES = {
    rfc5280.id_at_commonName: (MAY, MAY, MAY),
    rfc5280.id_at_organizationName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_organizationalUnitName: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    x520_name.id_at_organizationIdentifier: (SHALL_NOT, SHALL_NOT, SHALL_NOT),
    rfc5280.id_at_givenName: (MAY, MAY, MAY),
    rfc5280.id_at_surname: (MAY, MAY, MAY),
    rfc5280.id_at_pseudonym: (MAY, MAY, MAY),
    rfc5280.id_at_serialNumber: (MAY, MAY, MAY),
    rfc5280.id_emailAddress: (MAY, MAY, MAY),
    rfc5280.id_at_title: (MAY, MAY, MAY),
    x520_name.id_at_streetAddress: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_localityName: (MAY, MAY, MAY),
    rfc5280.id_at_stateOrProvinceName: (MAY, MAY, MAY),
    x520_name.id_at_postalCode: (MAY, MAY, SHALL_NOT),
    rfc5280.id_at_countryName: (MAY, MAY, MAY),
}

_GENERATION_INDEXES = {
    Generation.LEGACY: 0,
    Generation.MULTIPURPOSE: 1,
    Generation.STRICT: 2,
}

_VALIDATION_LEVEL_TO_TABLE = {
    ValidationLevel.MAILBOX: _MV_ATTRIBUTES,
    ValidationLevel.ORGANIZATION: _OV_ATTRIBUTES,
    ValidationLevel.SPONSORED: _SV_ATTRIBUTES,
    ValidationLevel.INDIVIDUAL: _IV_ATTRIBUTES,
}

_VALIDATION_LEVEL_TO_OTHER_ATTRIBUTE_ALLOWANCE = {
    ValidationLevel.MAILBOX: (False, False, False),
    ValidationLevel.ORGANIZATION: (True, False, False),
    ValidationLevel.SPONSORED: (True, False, False),
    ValidationLevel.INDIVIDUAL: (True, False, False),
}

_REQUIRED_ONE_OF_N = {
    (ValidationLevel.SPONSORED, Generation.LEGACY): {
        rfc5280.id_at_givenName,
        rfc5280.id_at_surname,
        rfc5280.id_at_pseudonym,
        rfc5280.id_at_commonName,
    },
    (ValidationLevel.INDIVIDUAL, Generation.LEGACY): {
        rfc5280.id_at_givenName,
        rfc5280.id_at_surname,
        rfc5280.id_at_pseudonym,
        rfc5280.id_at_commonName,
    },
    (ValidationLevel.SPONSORED, Generation.MULTIPURPOSE): {
        rfc5280.id_at_givenName,
        rfc5280.id_at_surname,
        rfc5280.id_at_pseudonym,
    },
    (ValidationLevel.INDIVIDUAL, Generation.MULTIPURPOSE): {
        rfc5280.id_at_givenName,
        rfc5280.id_at_surname,
        rfc5280.id_at_pseudonym,
    },
    (ValidationLevel.SPONSORED, Generation.STRICT): {
        rfc5280.id_at_givenName,
        rfc5280.id_at_surname,
        rfc5280.id_at_pseudonym,
    },
    (ValidationLevel.INDIVIDUAL, Generation.STRICT): {
        rfc5280.id_at_givenName,
        rfc5280.id_at_surname,
        rfc5280.id_at_pseudonym,
    },
}


class SubscriberSubjectValidator(validation.Validator):
    VALIDATION_MISSING_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.missing_required_attribute",
    )

    VALIDATION_PROHIBITED_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.smime.prohibited_attribute"
    )

    VALIDATION_MIXED_NAME_AND_PSEUDONYM_ATTRIBUTES = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.mixed_name_and_pseudonym_attributes",
    )

    def __init__(self, validation_level, generation):
        super().__init__(
            validations=[
                self.VALIDATION_PROHIBITED_ATTRIBUTE,
                self.VALIDATION_MISSING_ATTRIBUTE,
                self.VALIDATION_MIXED_NAME_AND_PSEUDONYM_ATTRIBUTES,
            ],
            pdu_class=rfc5280.RDNSequence,
            predicate=lambda n: n.path
            != "certificate.tbsCertificate.issuer.rdnSequence",
        )

        self._attribute_table = {
            k: v[_GENERATION_INDEXES[generation]]
            for k, v in _VALIDATION_LEVEL_TO_TABLE[validation_level].items()
        }

        self._required_attributes = {
            k for k, v in self._attribute_table.items() if v == SHALL
        }
        self._prohibited_attributes = {
            k for k, v, in self._attribute_table.items() if v == SHALL_NOT
        }
        self._required_one_of_n_attributes = _REQUIRED_ONE_OF_N.get(
            (validation_level, generation)
        )

        self._allow_other_oids = _VALIDATION_LEVEL_TO_OTHER_ATTRIBUTE_ALLOWANCE[
            validation_level
        ][_GENERATION_INDEXES[generation]]

    def validate(self, node):
        findings = []

        attributes = set()
        for rdn in node.children.values():
            attributes.update(
                (atv.children["type"].pdu for atv in rdn.children.values())
            )

        findings.extend(
            (
                validation.ValidationFindingDescription(
                    self.VALIDATION_MISSING_ATTRIBUTE,
                    f"Missing required attribute: {a}",
                )
                for a in self._required_attributes - attributes
            )
        )

        if (
            self._required_one_of_n_attributes
            and len(self._required_one_of_n_attributes.intersection(attributes)) == 0
        ):
            oids = oid.format_oids(self._required_one_of_n_attributes)

            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_MISSING_ATTRIBUTE,
                    f"Missing one of these required attributes: {oids}",
                )
            )

        findings.extend(
            (
                validation.ValidationFindingDescription(
                    self.VALIDATION_PROHIBITED_ATTRIBUTE, f"Prohibited attribute: {a}"
                )
                for a in self._prohibited_attributes.intersection(attributes)
            )
        )

        if rfc5280.id_at_pseudonym in attributes and (
            any(
                {rfc5280.id_at_givenName, rfc5280.id_at_surname}.intersection(
                    attributes
                )
            )
        ):
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_MIXED_NAME_AND_PSEUDONYM_ATTRIBUTES, None
                )
            )

        if not self._allow_other_oids:
            findings.extend(
                (
                    validation.ValidationFindingDescription(
                        self.VALIDATION_PROHIBITED_ATTRIBUTE,
                        f"Prohibited other attribute: {a}",
                    )
                    for a in attributes - set(self._attribute_table.keys())
                )
            )

        return validation.ValidationResult(self, node, findings)


class CabfSmimeOrganizationIdentifierAttributeValidator(
    CabfOrganizationIdentifierAttributeValidator
):
    _REFERENCE_PROHIBITED = (
        Rfc2119Word.MUST_NOT,
        "cabf.smime.prohibited_organization_identifier_reference_present_for_scheme",
    )

    """
    From SMBR 7.1.4.2.2 (d):
   
    When the Organization or Legal Entity is registered in Germany, the Registration Reference SHOULD use the EUID
    identifier.
    """
    VALIDATION_GERMAN_NTR_REFERENCE_NOT_EUID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.smime.german_ntr_registration_reference_not_euid",
    )

    _LEI_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(
            {organization_id.COUNTRY_CODE_GLOBAL_SCHEME},
            CabfOrganizationIdentifierAttributeValidator.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY,
        ),
        state_province=CabfOrganizationIdentifierAttributeValidator.STATE_PROVINCE_PROHIBITED,
        reference=CabfOrganizationIdentifierAttributeValidator.REFERENCE_REQUIRED,
    )
    _GOV_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(
            organization_id.ISO3166_1_COUNTRY_CODES,
            CabfOrganizationIdentifierAttributeValidator.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY,
        ),
        state_province=(Rfc2119Word.MAY, None),
        reference=_REFERENCE_PROHIBITED,
    )
    _INT_SCHEME = organization_id.OrganizationIdentifierElementAllowance(
        country_codes=(
            {organization_id.COUNTRY_CODE_GLOBAL_SCHEME},
            CabfOrganizationIdentifierAttributeValidator.VALIDATION_ORGANIZATION_ID_INVALID_COUNTRY,
        ),
        state_province=CabfOrganizationIdentifierAttributeValidator.STATE_PROVINCE_PROHIBITED,
        reference=_REFERENCE_PROHIBITED,
    )

    _EUID_SYNTAX = re.compile(
        r"^(?P<country>[A-Z]{2})(?P<register>.+)\.(?P<reference>.+)$"
    )

    def __init__(self):
        super().__init__(
            {
                "LEI": self._LEI_SCHEME,
                "GOV": self._GOV_SCHEME,
                "INT": self._INT_SCHEME,
            },
            enforce_strict_state_province_format=False,
            additional_validations=[self.VALIDATION_GERMAN_NTR_REFERENCE_NOT_EUID],
        )

    def validate_with_parsed_value(self, node, parsed):
        result = super().validate_with_parsed_value(node, parsed)

        if any(result.finding_descriptions):
            return validation.ValidationResult(self, node, result.finding_descriptions)

        if parsed.scheme == "NTR" and parsed.country == "DE":
            if parsed.state_province is not None:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_GERMAN_NTR_REFERENCE_NOT_EUID,
                    f'Organization identifier contains state/province: "{parsed.raw}"',
                )

            m = self._EUID_SYNTAX.match(parsed.reference)

            if m is None:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_GERMAN_NTR_REFERENCE_NOT_EUID,
                    f'Registration Reference is not in EUID format: "{parsed.reference}"',
                )

            if m["country"] != parsed.country:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_GERMAN_NTR_REFERENCE_NOT_EUID,
                    f'EUID Registration Reference has mismatched country code: "{parsed.raw}"',
                )


class SubscriberAttributeDependencyValidator(validation.Validator):
    VALIDATION_MISSING_REQUIRED_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.required_attribute_missing_for_dependent_attribute",
    )

    _ATTRIBUTE_DEPENDENCIES = [
        (
            x520_name.id_at_streetAddress,
            {rfc5280.id_at_localityName, rfc5280.id_at_stateOrProvinceName},
        ),
        (rfc5280.id_at_stateOrProvinceName, {rfc5280.id_at_countryName}),
        (rfc5280.id_at_localityName, {rfc5280.id_at_countryName}),
        (x520_name.id_at_postalCode, {rfc5280.id_at_countryName}),
    ]

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_MISSING_REQUIRED_ATTRIBUTE],
            pdu_class=rfc5280.RDNSequence,
            predicate=lambda n: n.path
            != "certificate.tbsCertificate.issuer.rdnSequence",
        )

    def validate(self, node):
        attributes = set()
        for rdn in node.children.values():
            attributes.update(
                (atv.children["type"].pdu for atv in rdn.children.values())
            )

        for dependent_attribute, required_attributes in self._ATTRIBUTE_DEPENDENCIES:
            if dependent_attribute in attributes:
                if not attributes & required_attributes:
                    oids = oid.format_oids(required_attributes)

                    if len(required_attributes) > 1:
                        message = f"one of {oids} is not present"
                    else:
                        message = f"{oids} is not present"

                    raise validation.ValidationFindingEncountered(
                        self.VALIDATION_MISSING_REQUIRED_ATTRIBUTE,
                        f"{dependent_attribute} is present but {message}",
                    )


def create_subscriber_certificate_subject_validator_container(
    validation_level, generation
):
    dn_validators = [
        SubscriberSubjectValidator(validation_level, generation),
        SubscriberAttributeDependencyValidator(),
        SubjectAlternativeNameContainsSubjectEmailAddressesValidator(),
        cabf_name.ValidCountryValidator(),
        CommonNameValidator(validation_level, generation),
        CabfSmimeOrganizationIdentifierAttributeValidator(),
        OrganizationIdentifierLeiValidator(),
        OrganizationIdentifierCountryNameConsistentValidator(),
        cabf_name.RelativeDistinguishedNameContainsOneElementValidator(),
        cabf_name.SignificantAttributeValueValidator(),
        cabf_name.HTMLEntitiesValidator(),
    ]

    return certificate.create_subject_validator_container(
        dn_validators,
        pdu_class=rfc5280.Name,
        predicate=lambda n: n.path != "certificate.tbsCertificate.issuer",
    )


class SubjectAlternativeNameContainsSubjectEmailAddressesValidator(
    validation.Validator
):
    VALIDATION_EMAIL_ADDRESS_IN_ATTRIBUTE_MISSING_FROM_SAN = (
        validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            "cabf.smime.email_address_in_attribute_not_in_san",
        )
    )

    VALIDATION_UNPARSED_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "cabf.smime.unparsed_attribute_value_encountered",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_EMAIL_ADDRESS_IN_ATTRIBUTE_MISSING_FROM_SAN,
                self.VALIDATION_UNPARSED_ATTRIBUTE,
            ],
            pdu_class=rfc5280.AttributeTypeAndValue,
            # emailAddress presence in SAN is checked by PKIX lint
            predicate=lambda n: n.children["type"].pdu != rfc5280.id_emailAddress,
        )

    def validate(self, node):
        oid = node.children["type"].pdu

        value_str = asn1_util.get_string_value_from_attribute_node(node)

        if value_str is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNPARSED_ATTRIBUTE,
                f"Unparsed attribute {str(oid)} encountered",
            )

        if bool(validators.email(value_str)):
            san_email_addresses = get_email_addresses_from_san(node.document)

            if value_str not in san_email_addresses:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_EMAIL_ADDRESS_IN_ATTRIBUTE_MISSING_FROM_SAN,
                    f'Attribute {str(oid)} with value "{value_str}" not found in SAN',
                )


class CommonNameValidator(validation.Validator):
    VALIDATION_COMMON_NAME_UNKNOWN_VALUE_SOURCE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.common_name_value_unknown_source",
    )

    VALIDATION_UNPARSED_COMMON_NAME_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "cabf.smime.unparsed_common_name_value",
    )

    def __init__(self, validation_level, generation):
        super().__init__(
            validations=[
                self.VALIDATION_COMMON_NAME_UNKNOWN_VALUE_SOURCE,
                self.VALIDATION_UNPARSED_COMMON_NAME_VALUE,
            ],
            pdu_class=rfc5280.X520CommonName,
        )

        self._validation_level = validation_level
        self._generation = generation

    @staticmethod
    def _is_value_in_dirstring_atvs(atvs, expected_value_node):
        expected_value_str = str(expected_value_node.pdu)

        return any(
            expected_value_str == asn1_util.get_string_value_from_attribute_node(a)
            for a in atvs
        )

    def validate(self, node):
        try:
            _, cn_value_node = node.child
        except ValueError:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNPARSED_COMMON_NAME_VALUE
            )

        parent_name_node = next(
            (n for n in node.parents if isinstance(n.pdu, rfc5280.Name))
        )

        if self._validation_level in {
            ValidationLevel.SPONSORED,
            ValidationLevel.INDIVIDUAL,
        }:
            # we don't need the index
            pseudonym_nodes = [
                t[0]
                for t in name.get_name_attributes_by_type(
                    parent_name_node, rfc5280.id_at_pseudonym
                )
            ]

            # Legacy sponsored and individual profiles allow the Personal Name in CN without being in other
            # subject attributes. However, if any pseudonym attributes are present, the CN must not contain a Personal
            # Name.
            if self._generation == Generation.LEGACY and not pseudonym_nodes:
                return

            if CommonNameValidator._is_value_in_dirstring_atvs(
                pseudonym_nodes, cn_value_node
            ):
                return

            # if there's a GN or SN, assume it's in the CN
            if any(
                name.get_name_attributes_by_type(
                    parent_name_node, rfc5280.id_at_givenName
                )
            ) or any(
                name.get_name_attributes_by_type(
                    parent_name_node, rfc5280.id_at_surname
                )
            ):
                return
        elif self._validation_level == ValidationLevel.ORGANIZATION:
            orgname_nodes = [
                t[0]
                for t in name.get_name_attributes_by_type(
                    parent_name_node, rfc5280.id_at_organizationName
                )
            ]

            if CommonNameValidator._is_value_in_dirstring_atvs(
                orgname_nodes, cn_value_node
            ):
                return

        email_addresses = get_email_addresses_from_san(node.document)

        if str(cn_value_node.pdu) not in email_addresses:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_COMMON_NAME_UNKNOWN_VALUE_SOURCE,
                f'Unknown CN value source: "{str(cn_value_node.pdu)}"',
            )


class OrganizationIdentifierCountryNameConsistentValidator(validation.Validator):
    VALIDATION_ORGID_COUNTRYNAME_INCONSISTENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.org_identifier_and_country_name_attribute_inconsistent",
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_ORGID_COUNTRYNAME_INCONSISTENT,
            pdu_class=rfc5280.X520countryName,
        )

    def validate(self, node):
        country_name_value = str(node.pdu)

        for atv, _ in node.document.get_subject_attributes_by_type(
            x520_name.id_at_organizationIdentifier
        ):
            x520_value_str = asn1_util.get_string_value_from_attribute_node(atv)

            if x520_value_str is None:
                continue

            try:
                parsed_org_id = organization_id.parse_organization_identifier(
                    x520_value_str
                )
            except ValueError:
                continue

            orgid_country_name = parsed_org_id.country

            # skip this orgId attribute if it contains the global scheme identifier
            if orgid_country_name == organization_id.COUNTRY_CODE_GLOBAL_SCHEME:
                continue

            if orgid_country_name != country_name_value:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_ORGID_COUNTRYNAME_INCONSISTENT,
                    f'CountryName attribute value: "{country_name_value}", '
                    f'OrganizationIdentifier attribute country name value: "{orgid_country_name}"',
                )


def get_email_addresses_from_san(cert_document):
    san_ext_and_idx = cert_document.get_extension_by_oid(rfc5280.id_ce_subjectAltName)

    if san_ext_and_idx is None:
        return []

    san_ext, _ = san_ext_and_idx

    email_addresses = []
    for gn in san_ext.navigate("extnValue.subjectAltName").children.values():
        name, value = gn.child

        if name == general_name.GeneralNameTypeName.RFC822_NAME:
            email_addresses.append(value.pdu)
        elif (
            name == general_name.GeneralNameTypeName.OTHER_NAME
            and value.navigate("type-id").pdu == rfc8398.id_on_SmtpUTF8Mailbox
        ):
            email_addresses.append(value.navigate("value").child[1].pdu)

    return email_addresses
