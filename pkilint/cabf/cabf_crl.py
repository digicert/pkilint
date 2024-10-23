import operator
from datetime import timedelta

from pyasn1_alt_modules import rfc5280

from pkilint import validation
from pkilint.pkix import crl, time
from pkilint.pkix.crl import crl_extension


def create_validity_period_validator(crl_type: crl.CertificateRevocationListType):
    if crl_type == crl.CertificateRevocationListType.CRL:
        max_validity_days = 10
        finding = "cabf.crl_invalid_validity_period"
    else:
        max_validity_days = 365  # TODO: handle leap years?
        finding = "cabf.arl_invalid_validity_period"

    thresholds = [
        (
            operator.le,
            timedelta(days=max_validity_days),
            validation.ValidationFinding(
                validation.ValidationFindingSeverity.ERROR, finding
            ),
        )
    ]

    return time.ValidityPeriodThresholdsValidator(
        path="certificateList.tbsCertList.thisUpdate",
        end_validity_node_retriever=lambda n: n.navigate("^.nextUpdate"),
        validity_period_thresholds=thresholds,
    )


class CabfCrlReasonCodeAllowlistValidator(
    crl_extension.CrlReasonCodeAllowlistValidator
):
    VALIDATION_PROHIBITED_CRL_REASON_CODE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.crl_prohibited_reason_code"
    )

    def __init__(self, crl_type: crl.CertificateRevocationListType):
        allowed_reasons = [
            rfc5280.CRLReason.namedValues[r]
            for r in [
                "keyCompromise",
                "affiliationChanged",
                "superseded",
                "cessationOfOperation",
                "privilegeWithdrawn",
            ]
        ]

        if crl_type == crl.CertificateRevocationListType.ARL:
            allowed_reasons.append(rfc5280.CRLReason.namedValues["cACompromise"])

        super().__init__(allowed_reasons, self.VALIDATION_PROHIBITED_CRL_REASON_CODE)
