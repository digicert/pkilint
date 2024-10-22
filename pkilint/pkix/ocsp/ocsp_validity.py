from pkilint import validation, document
from pkilint.pkix import time


class OCSPSaneValidityPeriodValidator(time.SaneValidityPeriodValidator):
    VALIDATION_NEGATIVE_VALIDITY_PERIOD = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.ocsp_negative_validity_period"
    )

    def __init__(self):
        super().__init__(
            end_validity_node_retriever=lambda n: n.navigate("^.nextUpdate"),
            path_re=document.get_re_for_path_glob(
                "oCSPResponse.responseBytes.response.basicOCSPResponse.tbsResponseData.responses.*.thisUpdate"
            ),
            predicate=lambda n: "nextUpdate" in n.parent.children,
            validation=self.VALIDATION_NEGATIVE_VALIDITY_PERIOD,
        )
