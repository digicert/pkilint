import datetime

from pkilint import validation, document
from pkilint.pkix import time


class CertificateSaneValidityPeriodValidator(time.SaneValidityPeriodValidator):
    VALIDATION_NEGATIVE_VALIDITY_PERIOD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.certificate_negative_validity_period",
    )

    def __init__(self):
        super().__init__(
            end_validity_node_retriever=lambda n: n.navigate("^.notAfter"),
            path="certificate.tbsCertificate.validity.notBefore",
            validation=self.VALIDATION_NEGATIVE_VALIDITY_PERIOD,
        )


class CertificateValidityPeriodStartRetriever(document.ValidityPeriodStartRetriever):
    def __call__(self, certificate, *args, **kwargs) -> datetime.datetime:
        return certificate.not_before
