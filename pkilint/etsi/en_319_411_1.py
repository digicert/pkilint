from pyasn1_alt_modules import rfc5280

from pkilint import validation, oid
from pkilint.etsi import etsi_constants
from pkilint.etsi.asn1 import en_319_411_1


class CertificatePoliciesValidator(validation.Validator):
    """
    GEN-6.3.3-12: The CP identifier shall be [CHOICE]:
    ...
    """

    VALIDATION_MULTIPLE_RESERVED_POLICY_OIDS_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_411_1.gen-6.3.3-12.multiple_reserved_policy_oids_present",
    )

    VALIDATION_PROHIBITED_RESERVED_POLICY_OID_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_411_1.gen-6.3.3-12.prohibited_reserved_policy_oid_present",
    )

    # mapping of certificate types to ETSI policy OIDs
    _CERTIFICATE_TYPE_SET_TO_POLICY_OID_MAPPINGS = [
        (etsi_constants.CABF_EV_CERTIFICATE_TYPES, en_319_411_1.id_evcp),
        (etsi_constants.CABF_DV_CERTIFICATE_TYPES, en_319_411_1.id_dvcp),
        (etsi_constants.CABF_OV_CERTIFICATE_TYPES, en_319_411_1.id_ovcp),
        (etsi_constants.CABF_IV_CERTIFICATE_TYPES, en_319_411_1.id_ivcp),
    ]

    def __init__(self, certificate_type):
        super().__init__(
            validations=[
                self.VALIDATION_MULTIPLE_RESERVED_POLICY_OIDS_PRESENT,
                self.VALIDATION_PROHIBITED_RESERVED_POLICY_OID_PRESENT,
            ],
            pdu_class=rfc5280.CertificatePolicies,
        )

        self._expected_policy_oid = next(
            p
            for t, p in self._CERTIFICATE_TYPE_SET_TO_POLICY_OID_MAPPINGS
            if certificate_type in t
        )

    def validate(self, node):
        # extract ETSI reserved policy OIDs from certificate policy OIDs
        etsi_policy_oids = en_319_411_1.POLICY_OIDS & node.document.policy_oids

        # if multiple ETSI policy OIDs are present, then report
        if len(etsi_policy_oids) > 1:
            oids = oid.format_oids(etsi_policy_oids)

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_MULTIPLE_RESERVED_POLICY_OIDS_PRESENT,
                f"Multiple reserved certificate policy OIDs present: {oids}",
            )

        # if there is a mismatch between the certificate type and reserved ETSI policy OID, then report
        if etsi_policy_oids and self._expected_policy_oid not in etsi_policy_oids:
            prohibited_oid = next(iter(etsi_policy_oids))

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_RESERVED_POLICY_OID_PRESENT,
                f"Prohibited reserved certificate policy OID present: {prohibited_oid}",
            )
