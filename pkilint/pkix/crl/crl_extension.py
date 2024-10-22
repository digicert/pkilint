from pyasn1.type.constraint import ValueRangeConstraint
from pyasn1_alt_modules import rfc5280

from pkilint import validation
from pkilint.pkix import extension


class CrlNumberPresenceValidator(extension.ExtensionPresenceValidator):
    def __init__(self):
        finding = validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR, "pkix.crl_number_missing"
        )

        super().__init__(
            extension_oid=rfc5280.id_ce_cRLNumber,
            validation=finding,
            pdu_class=rfc5280.CertificateList,
        )


class CrlNumberValueValidator(validation.ASN1ConstraintValidator):
    VALIDATION_FINDING_CRL_NUMBER_OOR = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "pkix.crl_number_out_of_range"
    )

    MAX_VALUE = (1 << 159) - 1

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.CRLNumber,
            validations=[self.VALIDATION_FINDING_CRL_NUMBER_OOR],
            constraint=ValueRangeConstraint(0, self.MAX_VALUE),
        )


class AuthorityKeyIdentifierPresenceValidator(extension.ExtensionPresenceValidator):
    def __init__(self):
        finding = validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            "pkix.authority_key_identifier_missing",
        )

        super().__init__(
            extension_oid=rfc5280.id_ce_authorityKeyIdentifier,
            validation=finding,
            pdu_class=rfc5280.CertificateList,
        )


class CrlNumberCriticalityValidator(extension.ExtensionCriticalityValidator):
    def __init__(self):
        finding = validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            "pkix.crl_number_extension_critical",
        )

        super().__init__(
            type_oid=rfc5280.id_ce_cRLNumber, is_critical=False, validation=finding
        )


class CrlReasonCodeValidator(validation.Validator):
    VALIDATION_UNSPECIFIED_REASON_CODE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "pkix.crl_unspecified_crl_entry_reason_code",
    )

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.CRLReason,
            validations=[self.VALIDATION_UNSPECIFIED_REASON_CODE],
        )

    def validate(self, node):
        unspecified = rfc5280.CRLReason.namedValues["unspecified"]

        if node.pdu == unspecified:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNSPECIFIED_REASON_CODE
            )


class CrlReasonCodeCriticalityValidator(extension.ExtensionCriticalityValidator):
    def __init__(self):
        finding = validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            "pkix.crl_reason_code_extension_critical",
        )

        super().__init__(
            type_oid=rfc5280.id_ce_cRLReasons, is_critical=False, validation=finding
        )


class CrlReasonCodeAllowlistValidator(validation.Validator):
    def __init__(
        self,
        allowed_reason_codes,
        prohibited_reason_code_validation: validation.ValidationFinding,
    ):
        self._allowed_reason_codes = allowed_reason_codes
        self._prohibited_reason_code_validation = prohibited_reason_code_validation

        super().__init__(
            pdu_class=rfc5280.CRLReason,
            validations=[self._prohibited_reason_code_validation],
        )

    def validate(self, node):
        if node.pdu not in self._allowed_reason_codes:
            raise validation.ValidationFindingEncountered(
                self._prohibited_reason_code_validation,
                f'Prohibited reason code "{node.pdu}"',
            )
