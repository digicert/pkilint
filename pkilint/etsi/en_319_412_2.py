from pkilint import validation, document
from pyasn1_alt_modules import rfc5280
from pkilint.pkix.certificate import RFC5280Certificate
from pkilint.pkix.crl import RFC5280CertificateList

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
          