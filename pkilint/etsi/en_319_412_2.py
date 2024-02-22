from pkilint import validation, document
from pyasn1_alt_modules import rfc5280
from pkilint.pkix.certificate import RFC5280Certificate
from pkilint.pkix.crl import RFC5280CertificateList
from pkilint.pkix import extension


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


class SubjectCNCountryNameSingularValidator(validation.Validator):
    """NAT 4.2.4-3 The subject field shall not contain more than one instance of commonName and countryName"""
    VALIDATION_COMMON_NAME_MULTIPLE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-4.2.4-3.multiple_common_name'
    )
    VALIDATION_COUNTRY_NAME_MULTIPLE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_5.nat-4.2.4-3.multiple_country_name'
    )

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_COMMON_NAME_MULTIPLE, self.VALIDATION_COUNTRY_NAME_MULTIPLE],
                         pdu_class=rfc5280.RDNSequence)

    def validate(self, node):
        if len(node.document.get_subject_attributes_by_type(oid=rfc5280.id_at_countryName)) > 1:
            raise validation.ValidationFindingEncountered(self.VALIDATION_COUNTRY_NAME_MULTIPLE)
        if len(node.document.get_subject_attributes_by_type(oid=rfc5280.id_at_commonName)) > 1:
            raise validation.ValidationFindingEncountered(self.VALIDATION_COMMON_NAME_MULTIPLE)


class CRLDistributionPointsCriticalityValidator(extension.ExtensionCriticalityValidator):
    CRL_DISTRIBUTION_POINTS_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.gen-4.3.11-5.crl_extension_is_critical'
    )

    def __init__(self):
        super().__init__(validation=self.CRL_DISTRIBUTION_POINTS_CRITICAL,
                         type_oid=rfc5280.id_ce_cRLDistributionPoints,
                         is_critical=False)

class PseudonymPresentValidator(validation.Validator):
    """NAT-4.2.4-4 The pseudonym attribute shall not be present if the givenName
    and surname attribute are present."""
    VALIDATION_PSEUDONYM_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-4.2.4-4.pseudonym_is_present'
    )

    def __init__(self):
        super().__init__(validations=self.VALIDATION_PSEUDONYM_PRESENT,
        pdu_class=rfc5280.RDNSequence)

    def validate(self, node):
        if (node.document.get_subject_attributes_by_type(oid=rfc5280.id_at_givenName)
           and node.document.get_subject_attributes_by_type(oid=rfc5280.id_at_surname)
           and node.document.get_subject_attributes_by_type(oid=rfc5280.id_at_pseudonym)):
           raise validation.ValidationFindingEncountered(self.VALIDATION_PSEUDONYM_PRESENT)
