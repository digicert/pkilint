from pkilint import validation
from pkilint.adobe import asn1


class AdobeTimestampValidator(validation.Validator):
    VALIDATION_INVALID_GENERALNAME_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "adbe.invalid_timestamp_location_type",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_INVALID_GENERALNAME_TYPE],
            pdu_class=asn1.AdobeTimestamp,
        )

    def validate(self, node):
        gn = node.children["location"]

        gn_type, _ = gn.child

        if gn_type != "uniformResourceIdentifier":
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_GENERALNAME_TYPE,
                f"Invalid Adobe timestamp location type: {gn_type}",
            )
