from pkilint import validation
from pkilint.pkix import time


class CrlSaneValidityPeriodValidator(time.SaneValidityPeriodValidator):
    VALIDATION_NEGATIVE_VALIDITY_PERIOD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.crl_negative_validity_period"
    )

    def __init__(self):
        super().__init__(
            end_validity_node_retriever=lambda n: n.navigate("^.nextUpdate"),
            path="certificateList.tbsCertList.thisUpdate",
            validation=self.VALIDATION_NEGATIVE_VALIDITY_PERIOD,
        )
