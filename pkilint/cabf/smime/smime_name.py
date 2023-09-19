import validators
from pyasn1.type import char
from pyasn1_alt_modules import rfc5280, rfc8398

from pkilint import validation, pkix, oid
from pkilint.cabf import cabf_name, cabf_constants
from pkilint.cabf.cabf_name import OrganizationIdentifierAttributeValidator
from pkilint.cabf.smime.smime_constants import Generation, ValidationLevel
from pkilint.iso import lei
from pkilint.itu import x520_name
from pkilint.pkix import certificate, name

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
    (ValidationLevel.SPONSORED, Generation.LEGACY): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                     rfc5280.id_at_pseudonym, rfc5280.id_at_commonName},
    (ValidationLevel.INDIVIDUAL, Generation.LEGACY): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                      rfc5280.id_at_pseudonym, rfc5280.id_at_commonName},
    (ValidationLevel.SPONSORED, Generation.MULTIPURPOSE): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                           rfc5280.id_at_pseudonym},
    (ValidationLevel.INDIVIDUAL, Generation.MULTIPURPOSE): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                            rfc5280.id_at_pseudonym},
    (ValidationLevel.SPONSORED, Generation.STRICT): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                     rfc5280.id_at_pseudonym},
    (ValidationLevel.INDIVIDUAL, Generation.STRICT): {rfc5280.id_at_givenName, rfc5280.id_at_surname,
                                                      rfc5280.id_at_pseudonym},
}


class SubscriberSubjectValidator(validation.Validator):
    VALIDATION_MISSING_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.missing_required_attribute'
    )

    VALIDATION_PROHIBITED_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.prohibited_attribute'
    )

    VALIDATION_MIXED_NAME_AND_PSEUDONYM_ATTRIBUTES = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.mixed_name_and_pseudonym_attributes'
    )

    def __init__(self, validation_level, generation):
        super().__init__(validations=[
            self.VALIDATION_PROHIBITED_ATTRIBUTE,
            self.VALIDATION_MISSING_ATTRIBUTE,
            self.VALIDATION_MIXED_NAME_AND_PSEUDONYM_ATTRIBUTES,
        ],
            pdu_class=rfc5280.RDNSequence,
            predicate=lambda n: n.path != 'certificate.tbsCertificate.issuer.rdnSequence')

        self._attribute_table = {
            k: v[_GENERATION_INDEXES[generation]] for k, v in _VALIDATION_LEVEL_TO_TABLE[validation_level].items()
        }

        self._required_attributes = {k for k, v in self._attribute_table.items() if v == SHALL}
        self._prohibited_attributes = {k for k, v, in self._attribute_table.items() if v == SHALL_NOT}
        self._required_one_of_n_attributes = _REQUIRED_ONE_OF_N.get((validation_level, generation))

        self._allow_other_oids = _VALIDATION_LEVEL_TO_OTHER_ATTRIBUTE_ALLOWANCE[validation_level][
            _GENERATION_INDEXES[generation]]

    def validate(self, node):
        findings = []

        attributes = set()
        for rdn in node.children.values():
            attributes.update((atv.children['type'].pdu for atv in rdn.children.values()))

        findings.extend((
            validation.ValidationFindingDescription(self.VALIDATION_MISSING_ATTRIBUTE,
                                                    f'Missing required attribute: {a}')
            for a in self._required_attributes - attributes
        ))

        if self._required_one_of_n_attributes and len(self._required_one_of_n_attributes.intersection(attributes)) == 0:
            oids = oid.format_oids(self._required_one_of_n_attributes)

            findings.append(validation.ValidationFindingDescription(self.VALIDATION_MISSING_ATTRIBUTE,
                                                                    f'Missing one of these required attributes: {oids}'))

        findings.extend((
            validation.ValidationFindingDescription(self.VALIDATION_PROHIBITED_ATTRIBUTE,
                                                    f'Prohibited attribute: {a}')
            for a in self._prohibited_attributes.intersection(attributes)
        ))

        if rfc5280.id_at_pseudonym in attributes and (
                any({rfc5280.id_at_givenName, rfc5280.id_at_surname}.intersection(attributes))):
            findings.append(
                validation.ValidationFindingDescription(self.VALIDATION_MIXED_NAME_AND_PSEUDONYM_ATTRIBUTES, None))

        if not self._allow_other_oids:
            findings.extend((
                validation.ValidationFindingDescription(self.VALIDATION_PROHIBITED_ATTRIBUTE,
                                                        f'Prohibited other attribute: {a}')
                for a in attributes - set(self._attribute_table.keys())
            ))

        return validation.ValidationResult(self, node, findings)


def create_subscriber_certificate_subject_validator_container(
        validation_level, generation
):
    dn_validators = [
        SubscriberSubjectValidator(validation_level, generation),
        SubjectAlternativeNameContainsSubjectEmailAddressesValidator(),
        cabf_name.ValidCountryValidator(),
        CommonNameValidator(validation_level, generation),
        OrganizationIdentifierAttributeValidator(relax_stateprovince_syntax=True, additional_schemes={
            'LEI': cabf_constants.RegistrationSchemeNamingConvention(
                cabf_constants.RegistrationSchemeCountryIdentifierType.XG,
                False, True
            ),
            'GOV': cabf_constants.RegistrationSchemeNamingConvention(
                cabf_constants.RegistrationSchemeCountryIdentifierType.ISO3166,
                True, False
            ),
            'INT': cabf_constants.RegistrationSchemeNamingConvention(
                cabf_constants.RegistrationSchemeCountryIdentifierType.XG,
                False, False
            )
        }),
        OrganizationIdentifierLeiValidator(),
        OrganizationIdentifierCountryNameConsistentValidator(),
        cabf_name.RelativeDistinguishedNameContainsOneElementValidator(),
    ]

    return certificate.create_subject_validator_container(
        dn_validators, pdu_class=rfc5280.Name,
        predicate=lambda n: n.path != 'certificate.tbsCertificate.issuer'
    )


class SubjectAlternativeNameContainsSubjectEmailAddressesValidator(
    validation.Validator
):
    VALIDATION_EMAIL_ADDRESS_IN_ATTRIBUTE_MISSING_FROM_SAN = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.email_address_in_attribute_not_in_san'
    )

    VALIDATION_UNPARSED_ATTRIBUTE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'cabf.smime.unparsed_attribute_value_encountered'
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_EMAIL_ADDRESS_IN_ATTRIBUTE_MISSING_FROM_SAN,
                self.VALIDATION_UNPARSED_ATTRIBUTE,
            ],
            pdu_class=rfc5280.AttributeTypeAndValue,
            # emailAddress presence in SAN is checked by PKIX lint
            predicate=lambda n: n.children['type'].pdu != rfc5280.id_emailAddress
        )

    def validate(self, node):
        oid = node.children['type'].pdu
        value = node.children['value']

        while True:
            if len(value.children) != 1:
                value = None
                break
            else:
                _, value = value.child

                if len(value.children) == 0:
                    if isinstance(value.pdu, char.AbstractCharacterString):
                        break

        if value is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNPARSED_ATTRIBUTE,
                f'Unparsed attribute {str(oid)} encountered'
            )

        value_str = str(value.pdu)

        if bool(validators.email(value_str)):
            san_email_addresses = get_email_addresses_from_san(node.document)

            if value_str not in san_email_addresses:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_EMAIL_ADDRESS_IN_ATTRIBUTE_MISSING_FROM_SAN,
                    f'Attribute {str(oid)} with value "{value_str}" not found in SAN'
                )


class CommonNameValidator(validation.Validator):
    VALIDATION_COMMON_NAME_UNKNOWN_VALUE_SOURCE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.common_name_value_unknown_source'
    )

    VALIDATION_UNPARSED_COMMON_NAME_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'cabf.smime.unparsed_common_name_value'
    )

    def __init__(self, validation_level, generation):
        super().__init__(
            validations=[self.VALIDATION_COMMON_NAME_UNKNOWN_VALUE_SOURCE, self.VALIDATION_UNPARSED_COMMON_NAME_VALUE],
            pdu_class=rfc5280.X520CommonName
        )

        self._validation_level = validation_level
        self._generation = generation

    @staticmethod
    def _is_value_in_dirstring_atvs(atvs, expected_value_node):
        for atv in atvs:
            try:
                # get the value contained within the DirectoryString-encoded ATV value
                _, atv_dirstring_value_node = atv.children['value'].child
                _, value = atv_dirstring_value_node.child
            except ValueError:
                # skip unparsed field

                continue

            if str(value.pdu) == str(expected_value_node.pdu):
                return True

        return False

    def validate(self, node):
        try:
            _, cn_value_node = node.child
        except ValueError:
            raise validation.ValidationFindingEncountered(self.VALIDATION_UNPARSED_COMMON_NAME_VALUE)

        parent_name_node = next((n for n in node.parents if isinstance(n.pdu, rfc5280.Name)))

        if self._validation_level in {ValidationLevel.SPONSORED, ValidationLevel.INDIVIDUAL}:
            # legacy sponsored and individual profiles allow the Personal Name in CN without being in other
            # subject attributes
            if self._generation == Generation.LEGACY:
                return

            # we don't need the index
            pseudonym_nodes = [t[0] for t in
                               name.get_name_attributes_by_type(parent_name_node, rfc5280.id_at_pseudonym)]

            if CommonNameValidator._is_value_in_dirstring_atvs(pseudonym_nodes, cn_value_node):
                return

            # if there's a GN or SN, assume it's in the CN
            if (
                    any(name.get_name_attributes_by_type(parent_name_node, rfc5280.id_at_givenName)) or
                    any(name.get_name_attributes_by_type(parent_name_node, rfc5280.id_at_surname))):
                return
        elif self._validation_level == ValidationLevel.ORGANIZATION:
            orgname_nodes = [t[0] for t in
                             name.get_name_attributes_by_type(parent_name_node, rfc5280.id_at_organizationName)]

            if CommonNameValidator._is_value_in_dirstring_atvs(orgname_nodes, cn_value_node):
                return

        email_addresses = get_email_addresses_from_san(node.document)

        if str(cn_value_node.pdu) not in email_addresses:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_COMMON_NAME_UNKNOWN_VALUE_SOURCE,
                f'Unknown CN value source: "{str(cn_value_node.pdu)}"'
            )


class OrganizationIdentifierLeiValidator(validation.Validator):
    VALIDATION_INVALID_ORGID_LEI_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, 'cabf.smime.invalid_lei_scheme_format'
    )

    _LEI_PREFIX = 'LEIXG-'

    def __init__(self):
        super().__init__(validations=[
            lei.VALIDATION_INVALID_LEI_CHECKSUM, lei.VALIDATION_INVALID_LEI_FORMAT,
            self.VALIDATION_INVALID_ORGID_LEI_FORMAT
        ],
            pdu_class=x520_name.X520OrganizationIdentifier,
            predicate=lambda n: any(n.children) and str(n.child[1].pdu).startswith('LEI')
        )

    def validate(self, node):
        value = str(node.child[1].pdu)

        if not value.startswith(self._LEI_PREFIX):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_ORGID_LEI_FORMAT,
                f'Invalid Organization Identifier format: {value}'
            )

        lei_value = value[len(self._LEI_PREFIX):]

        lei.validate_lei(lei_value)


class OrganizationIdentifierCountryNameConsistentValidator(validation.Validator):
    VALIDATION_ORGID_COUNTRYNAME_INCONSISTENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.smime.org_identifier_and_country_name_attribute_inconsistent'
    )

    def __init__(self):
        super().__init__(validations=self.VALIDATION_ORGID_COUNTRYNAME_INCONSISTENT,
                         pdu_class=rfc5280.X520countryName)

    def validate(self, node):
        country_name_value = str(node.pdu)

        for atv, _ in node.document.get_subject_attributes_by_type(x520_name.id_at_organizationIdentifier):
            attr_value_node = atv.navigate('value')

            try:
                _, x520_dirstring_value_node = attr_value_node.child
            except ValueError:
                continue

            _, x520_value_node = x520_dirstring_value_node.child

            x520_value_str = str(x520_value_node.pdu)

            m = cabf_name.ORG_ID_REGEX.match(x520_value_str)

            if m is None:
                continue

            orgid_country_name = m['country']

            # skip this orgId attribute if it doesn't contain a countryName or contains XG
            if not orgid_country_name or orgid_country_name.upper() == 'XG':
                continue

            if orgid_country_name.casefold() != country_name_value.casefold():
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_ORGID_COUNTRYNAME_INCONSISTENT,
                    f'CountryName attribute value: "{country_name_value}", '
                    f'OrganizationIdentifier attribute country name value: "{orgid_country_name}"'
                )


def get_email_addresses_from_san(cert_document):
    san_ext_and_idx = cert_document.get_extension_by_oid(rfc5280.id_ce_subjectAltName)

    if san_ext_and_idx is None:
        return []

    san_ext, _ = san_ext_and_idx

    email_addresses = []
    for gn in san_ext.navigate('extnValue.subjectAltName').children.values():
        name, value = gn.child

        if name == 'rfc822Name':
            email_addresses.append(value.pdu)
        elif name == 'otherName' and value.navigate('type-id').pdu == rfc8398.id_on_SmtpUTF8Mailbox:
            email_addresses.append(value.navigate('value').pdu)

    return email_addresses
