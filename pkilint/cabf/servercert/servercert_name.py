from pyasn1_alt_modules import rfc5280

from pkilint import validation, document
from pkilint.cabf.cabf_name import ValidCountryCodeValidatorBase, _ORG_ID_REGEX
from pkilint.cabf.servercert.asn1 import ev_guidelines
from pkilint.itu import x520_name
from pkilint.pkix import name


class ValidJurisdictionCountryValidator(ValidCountryCodeValidatorBase):
    VALIDATION_INVALID_COUNTRY_CODE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_jurisdiction_country_code'
    )

    def __init__(self):
        super().__init__(
            type_oid=ev_guidelines.id_evat_jurisdiction_countryName,
            value_path='value.eVGJurisdictionCountryName',
            checked_validation=self.VALIDATION_INVALID_COUNTRY_CODE
        )


class ValidBusinessCategoryValidator(validation.Validator):
    VALIDATION_INVALID_BUSINESS_CATEGORY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.invalid_business_category'
    )

    _ALLOWED_VALUES = {
        'Private Organization',
        'Government Entity',
        'Business Entity',
        'Non-Commercial Entity'
    }

    def __init__(self):
        super().__init__(
            pdu_class=x520_name.X520BusinessCategory,
            validations=[self.VALIDATION_INVALID_BUSINESS_CATEGORY]
        )

    def validate(self, node):
        # BusinessCategory is a CHOICE so retrieve the child node value
        business_category = str(node.child[1].pdu)

        if business_category not in self._ALLOWED_VALUES:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_BUSINESS_CATEGORY,
                f'Invalid business category: {business_category}'
            )


class OrganizationIdentifierConsistentSubjectAndExtensionValidator(validation.Validator):
    VALIDATION_CABF_ORG_ID_NO_EXT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.organization_identifier_extension_absent'
    )

    VALIDATION_CABF_ORG_ID_INVALID_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.FATAL,
        'cabf.organization_identifier_invalid_syntax'
    )

    VALIDATION_CABF_ORG_ID_MISMATCHED_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.organization_identifier_mismatched_scheme'
    )

    VALIDATION_CABF_ORG_ID_MISMATCHED_COUNTRY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.organization_identifier_mismatched_country_code'
    )

    VALIDATION_CABF_ORG_ID_MISMATCHED_SP = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.organization_identifier_mismatched_state_province'
    )

    VALIDATION_CABF_ORG_ID_MISMATCHED_REFERENCE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.organization_identifier_mismatched_registration_reference'
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_CABF_ORG_ID_NO_EXT,
                self.VALIDATION_CABF_ORG_ID_INVALID_SYNTAX,
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_SCHEME,
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_COUNTRY,
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_SP,
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_REFERENCE,
            ],
            pdu_class=x520_name.X520OrganizationIdentifier,
            predicate=lambda n: any(n.children)
        )

    def validate(self, node):
        ext_and_idx = node.document.get_extension_by_oid(
            ev_guidelines.id_CABFOrganizationIdentifier
        )

        if ext_and_idx is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CABF_ORG_ID_NO_EXT
            )

        ext, _ = ext_and_idx
        try:
            ext = ext.navigate('extnValue.cABFOrganizationIdentifier')
        except document.PDUNavigationFailedError:
            return

        attr_value = str(node.child[1].pdu)

        m = _ORG_ID_REGEX.match(attr_value)
        if m is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CABF_ORG_ID_INVALID_SYNTAX,
                f'Invalid syntax: {attr_value}'
            )

        findings = []
        ext_scheme = str(ext.children['registrationSchemeIdentifier'].pdu)
        if m['scheme'] != ext_scheme:
            findings.append(validation.ValidationFindingDescription(
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_SCHEME,
                f'Mismatched scheme: subject: {m["scheme"]}, extension: '
                f'{ext_scheme}'
            ))

        ext_country = str(ext.children['registrationCountry'].pdu)
        if m['country'] != ext_country:
            findings.append(validation.ValidationFindingDescription(
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_COUNTRY,
                f'Mismatched country: subject: {m["country"]}, extension: '
                f'{ext_country}'
            ))

        ext_sp_node = ext.children.get('registrationStateOrProvince')
        ext_sp = None if ext_sp_node is None else str(ext_sp_node.pdu)
        if m['sp'] is None and ext_sp is not None:
            findings.append(validation.ValidationFindingDescription(
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_SP,
                'Extension has state/province value but subject does not'
            ))
        elif m['sp'] is not None and ext_sp is None:
            findings.append(validation.ValidationFindingDescription(
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_SP,
                'Extension does not have state/province value but subject does'
            ))
        elif m['sp'] is not None and ext_sp is not None:
            if ext_sp != m['sp']:
                findings.append(validation.ValidationFindingDescription(
                    self.VALIDATION_CABF_ORG_ID_MISMATCHED_SP,
                    f'Mismatched state/province value: subject: {m["sp"]}, '
                    f'extension: {ext_sp}'
                ))

        ext_reg_ref = str(ext.children['registrationReference'].pdu)
        if m['reference'] != ext_reg_ref:
            findings.append(validation.ValidationFindingDescription(
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_REFERENCE,
                f'Mismatched registration reference: subject: {m["reference"]}'
                f', extension: {ext_reg_ref}'
            ))

        return validation.ValidationResult(self, node, findings)


class EvSubscriberCertificateAllowedAttributesValidator(
    name.PermittedAttributeTypeValidator
):
    VALIDATION_PROHIBITED_SUBJECT_FIELD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.ev_subscriber_certificate_prohibited_subject_field'
    )

    def __init__(self):
        super().__init__(
            allowed_oid_set={rfc5280.id_at_commonName, rfc5280.id_at_countryName, rfc5280.id_at_localityName,
                             rfc5280.id_at_organizationName, rfc5280.id_at_organizationalUnitName,
                             rfc5280.id_at_stateOrProvinceName, rfc5280.id_at_serialNumber,
                             ev_guidelines.id_evat_jurisdiction_countryName,
                             ev_guidelines.id_evat_jurisdiction_localityName,
                             ev_guidelines.id_evat_jurisdiction_stateOrProvinceName,
                             ev_guidelines.id_CABFOrganizationIdentifier, x520_name.id_at_businessCategory,
                             x520_name.id_at_postalCode, x520_name.id_at_streetAddress,
                             x520_name.id_at_businessCategory},
            validation=self.VALIDATION_PROHIBITED_SUBJECT_FIELD
        )


class DvSubscriberCertificatedAllowedAttributesValidator(
    name.PermittedAttributeTypeValidator
):
    VALIDATION_PROHIBITED_SUBJECT_FIELD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.dv_subscriber_certificate_prohibited_subject_field'
    )

    def __init__(self):
        super().__init__(allowed_oid_set={rfc5280.id_at_commonName, rfc5280.id_at_countryName},
                         validation=self.VALIDATION_PROHIBITED_SUBJECT_FIELD
                         )
