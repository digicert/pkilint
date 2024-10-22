from pyasn1_alt_modules import rfc5280

from pkilint import validation


class VersionPresenceValidator(validation.NodePresenceValidator):
    VALIDATION_VERSION_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.crl_version_missing"
    )

    def __init__(self):
        node_retriever = lambda n: n.navigate("version")

        super().__init__(
            node_retriever=node_retriever,
            absence_finding=self.VALIDATION_VERSION_MISSING,
            pdu_class=rfc5280.TBSCertList,
        )


class CorrectVersionValidator(validation.ScalarFieldValueEqualityValidator):
    def __init__(self):
        super().__init__(
            path="certificateList.tbsCertList.version",
            value=rfc5280.Version.namedValues["v2"],
            validations=validation.ValidationFinding(
                validation.ValidationFindingSeverity.ERROR, "pkix.crl_version_is_not_v2"
            ),
        )


class SignatureAlgorithmMatchValidator(validation.DEREqualityValidator):
    def __init__(self):
        super().__init__(
            other_node_retriever=(lambda n: n.navigate("^.tbsCertList.signature")),
            path="signatureAlgorithm",
            validation=validation.ValidationFinding(
                validation.ValidationFindingSeverity.ERROR,
                "pkix.crl_signature_algorithm_match",
            ),
        )


class RevokedCertificatesEmptyValidator(validation.Validator):
    VALIDATION_REVOKED_CERTIFICATES_EMPTY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.crl_revoked_certificates_empty",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_REVOKED_CERTIFICATES_EMPTY],
            pdu_class=rfc5280.TBSCertList,
        )

    def validate(self, node):
        revoked_certificates = node.children.get("revokedCertificates")

        if revoked_certificates is not None and not any(revoked_certificates.pdu):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_REVOKED_CERTIFICATES_EMPTY
            )
