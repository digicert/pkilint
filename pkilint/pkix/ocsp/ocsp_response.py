from pyasn1_alt_modules import rfc6960

from pkilint import document, validation


class OCSPResponseDecoder(document.ValueDecoder):
    def __init__(self, *, type_mappings):
        super().__init__(
            type_path="responseType", value_path="response", type_mappings=type_mappings
        )


class OCSPResponseDecodingValidator(validation.DecodingValidator):
    def __init__(self, *, decode_func, **kwargs):
        super().__init__(
            pdu_class=rfc6960.ResponseBytes, decode_func=decode_func, **kwargs
        )


class OCSPResponseStatusValidator(validation.Validator):
    VALIDATION_ERROR_RESPONSE_HAS_BYTES = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.ocsp_error_response_has_response_body",
    )

    VALIDATION_STATUS_NUMBER_4 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.ocsp_response_status_code_4"
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_ERROR_RESPONSE_HAS_BYTES,
                self.VALIDATION_STATUS_NUMBER_4,
            ],
            pdu_class=rfc6960.OCSPResponseStatus,
        )

    def validate(self, node):
        findings = []

        if node.pdu == rfc6960.OCSPResponseStatus("undefinedStatus"):
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_STATUS_NUMBER_4, None
                )
            )

        if (
            node.pdu != rfc6960.OCSPResponseStatus("successful")
            and "responseBytes" in node.parent.children
        ):
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_ERROR_RESPONSE_HAS_BYTES, None
                )
            )

        return validation.ValidationResult(self, node, findings)


class OCSPResponseIsBasicValidator(validation.Validator):
    VALIDATION_RESPONSE_IS_NOT_BASIC = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.ocsp_response_is_not_basic"
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_RESPONSE_IS_NOT_BASIC],
            pdu_class=rfc6960.ResponseBytes,
        )

    def validate(self, node):
        type_oid = node.children["responseType"].pdu

        if type_oid != rfc6960.id_pkix_ocsp_basic:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_RESPONSE_IS_NOT_BASIC,
                f"Unknown response type: {str(type_oid)}",
            )
