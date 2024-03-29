from pyasn1_alt_modules import rfc5280

from pkilint import validation, oid
from pkilint.pkix import extension, name


class CertificatePoliciesCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_CERTIFICATE_POLICIES_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'etsi.en_319_412_2.gen-4.3.3-1.critical_certificate_policies_extension'
    )

    def __init__(self):
        super().__init__(validation=self.VALIDATION_CERTIFICATE_POLICIES_CRITICAL,
                         type_oid=rfc5280.id_ce_certificatePolicies,
                         is_critical=False)


class SubjectAlternativeNameCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_SAN_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.gen-4.3.5-1.san_extension_is_critical'
    )

    def __init__(self):
        super().__init__(validation=self.VALIDATION_SAN_CRITICAL,
                         type_oid=rfc5280.id_ce_subjectAltName,
                         is_critical=False)


class IssuerAlternativeNameCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_ISSUER_ALTERNATIVE_NAME_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.gen-4.3.6-1.ian_extension_is_critical'
    )

    def __init__(self):
        super().__init__(validation=self.VALIDATION_ISSUER_ALTERNATIVE_NAME_CRITICAL,
                         type_oid=rfc5280.id_ce_issuerAltName,
                         is_critical=False)


class ExtendedKeyUsageCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_EXTENDED_KEY_USAGE_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.gen-4.3.10-1.eku_extension_is_critical'
    )

    def __init__(self):
        super().__init__(validation=self.VALIDATION_EXTENDED_KEY_USAGE_CRITICAL,
                         type_oid=rfc5280.id_ce_extKeyUsage,
                         is_critical=False)


class CRLDistributionPointsCriticalityValidator(extension.ExtensionCriticalityValidator):
    CRL_DISTRIBUTION_POINTS_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.gen-4.3.11-5.crl_extension_is_critical'
    )

    def __init__(self):
        super().__init__(validation=self.CRL_DISTRIBUTION_POINTS_CRITICAL,
                         type_oid=rfc5280.id_ce_cRLDistributionPoints,
                         is_critical=False)


class NaturalPersonSubjectAttributeAllowanceValidator(validation.Validator):
    """
    NAT-4.2.4-1: The subject field shall include the following attributes as specified in Recommendation ITU-T X.520:
    • countryName;
    • choice of (givenName and/or surname) or pseudonym; and
    • commonName.
    """
    VALIDATION_NATURAL_PERSON_NAME_ATTRIBUTE_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-4.2.4-1.required_attribute_missing'
    )

    """
    NAT-4.2.4-4 The pseudonym attribute shall not be present if the givenName
    and surname attribute are present.
    """
    VALIDATION_MIXED_PSEUDONYM_AND_NAME_ATTRIBUTES_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-4.2.4-4.mixed_pseudonym_and_name_attributes_present'
    )

    """
    NAT 4.2.4-3 The subject field shall not contain more than one instance of commonName and countryName
    """
    VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-4.2.4-3.prohibited_duplicate_attribute_present'
    )

    _REQUIRED_ATTRIBUTES = {
        rfc5280.id_at_countryName,
        rfc5280.id_at_commonName,
    }

    _PSEUDONYM_AND_NAME_ATTRIBUTES = {
        rfc5280.id_at_givenName,
        rfc5280.id_at_surname,
        rfc5280.id_at_pseudonym,
    }

    _PROHIBITED_DUPLICATE_ATTRIBUTES = {
        rfc5280.id_at_countryName,
        rfc5280.id_at_commonName,
    }

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_NATURAL_PERSON_NAME_ATTRIBUTE_MISSING,
                self.VALIDATION_MIXED_PSEUDONYM_AND_NAME_ATTRIBUTES_PRESENT,
                self.VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT
            ],
            pdu_class=rfc5280.Name
        )

    def validate(self, node):
        attr_counts = name.get_name_attribute_counts(node)

        attrs_present = set(attr_counts.keys())

        missing_attrs = None

        if not attrs_present.issuperset(self._REQUIRED_ATTRIBUTES):
            missing_attrs = self._REQUIRED_ATTRIBUTES - attrs_present
        elif attrs_present.isdisjoint(self._PSEUDONYM_AND_NAME_ATTRIBUTES):
            missing_attrs = self._PSEUDONYM_AND_NAME_ATTRIBUTES - attrs_present

        if missing_attrs:
            oid_str = oid.format_oids(missing_attrs)

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NATURAL_PERSON_NAME_ATTRIBUTE_MISSING,
                f'Required attributes missing: {oid_str}'
            )

        if all((a in attrs_present for a in self._PSEUDONYM_AND_NAME_ATTRIBUTES)):
            raise validation.ValidationFindingEncountered(self.VALIDATION_MIXED_PSEUDONYM_AND_NAME_ATTRIBUTES_PRESENT)

        for a in self._PROHIBITED_DUPLICATE_ATTRIBUTES:
            if attr_counts[a] > 1:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT,
                    f'Prohibited duplicate attribute present: {a}'
                )
