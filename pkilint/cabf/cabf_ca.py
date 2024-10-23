from pyasn1_alt_modules import rfc5280

from pkilint import validation
from pkilint.itu import bitstring
from pkilint.pkix.certificate.certificate_extension import KeyUsageBitName


# BR 7.1.2.10.7
class CaKeyUsageValidator(validation.Validator):
    VALIDATION_CA_CERT_REQUIRED_BIT_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.ca_certificate_required_ku_missing",
    )

    VALIDATION_CA_CERT_PROHIBITED_BIT_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.ca_certificate_prohibited_ku_present",
    )

    VALIDATION_CA_CERT_NO_DIG_SIG = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "cabf.ca_certificate_no_digital_signature_bit",
    )

    _PROHIBITED_KUS = {str(n) for n in rfc5280.KeyUsage.namedValues} - {
        KeyUsageBitName.DIGITAL_SIGNATURE,
        KeyUsageBitName.KEY_CERT_SIGN,
        KeyUsageBitName.CRL_SIGN,
    }

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_CA_CERT_REQUIRED_BIT_MISSING,
                self.VALIDATION_CA_CERT_PROHIBITED_BIT_PRESENT,
                self.VALIDATION_CA_CERT_NO_DIG_SIG,
            ],
            pdu_class=rfc5280.KeyUsage,
        )

    def validate(self, node):
        if not bitstring.has_named_bit(node, KeyUsageBitName.KEY_CERT_SIGN):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CA_CERT_REQUIRED_BIT_MISSING, "keyCertSign not asserted"
            )
        if not bitstring.has_named_bit(node, KeyUsageBitName.CRL_SIGN):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CA_CERT_REQUIRED_BIT_MISSING, "cRLSign not asserted"
            )
        prohibited_kus_asserted = [
            k for k in self._PROHIBITED_KUS if bitstring.has_named_bit(node, k)
        ]

        if any(prohibited_kus_asserted):
            prohibited_kus_str = ", ".join(prohibited_kus_asserted)
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CA_CERT_PROHIBITED_BIT_PRESENT,
                f"Prohibited KUs present: {prohibited_kus_str}",
            )

        if not bitstring.has_named_bit(node, KeyUsageBitName.DIGITAL_SIGNATURE):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CA_CERT_NO_DIG_SIG
            )


class CaBasicConstraintsValidator(validation.Validator):
    VALIDATION_CA_BIT_NOT_SET = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.ca_basic_constraints_ca_bit_not_set",
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_CA_BIT_NOT_SET,
            pdu_class=rfc5280.BasicConstraints,
        )

    def validate(self, node):
        if not bool(node.children["cA"].pdu):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CA_BIT_NOT_SET
            )
