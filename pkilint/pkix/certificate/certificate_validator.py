from pyasn1_alt_modules import rfc5280

from pkilint import validation


class CorrectVersionValidator(validation.ScalarFieldValueEqualityValidator):
    def __init__(self):
        super().__init__(
            path="certificate.tbsCertificate.version",
            value=rfc5280.Version.namedValues["v3"],
            validations=validation.ValidationFinding(
                validation.ValidationFindingSeverity.ERROR,
                "pkix.certificate_version_is_not_v3",
            ),
        )


class SignatureAlgorithmMatchValidator(validation.DEREqualityValidator):
    def __init__(self):
        super().__init__(
            other_node_retriever=(lambda n: n.navigate("^.tbsCertificate.signature")),
            path="certificate.signatureAlgorithm",
            validation=validation.ValidationFinding(
                validation.ValidationFindingSeverity.ERROR,
                "pkix.certificate_signature_algorithm_mismatch",
            ),
        )


class IssuerUniqueIdAbsenceValidator(validation.NodePresenceValidator):
    VALIDATION_ISSUER_UNIQUE_ID_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.issuer_unique_id_present"
    )

    def __init__(self):
        super().__init__(
            node_retriever=lambda n: n.navigate("issuerUniqueID"),
            presence_finding=self.VALIDATION_ISSUER_UNIQUE_ID_PRESENT,
            pdu_class=rfc5280.TBSCertificate,
        )


class SubjectUniqueIdAbsenceValidator(validation.NodePresenceValidator):
    VALIDATION_SUBJECT_UNIQUE_ID_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.subject_unique_id_present"
    )

    def __init__(self):
        super().__init__(
            node_retriever=lambda n: n.navigate("subjectUniqueID"),
            presence_finding=self.VALIDATION_SUBJECT_UNIQUE_ID_PRESENT,
            pdu_class=rfc5280.TBSCertificate,
        )
