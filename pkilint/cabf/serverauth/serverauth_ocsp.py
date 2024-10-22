from pyasn1_alt_modules import rfc5280, rfc6960, rfc6962

import pkilint.common
from pkilint import validation, common
from pkilint.itu import bitstring
from pkilint.pkix import Rfc2119Word
from pkilint.pkix.certificate.certificate_extension import KeyUsageBitName

_CODE_CLASSIFIER = "cabf.serverauth.ocsp_responder"


class OcspResponderKeyUsageValidator(validation.Validator):
    """Validates that the content of the key usage extension conforms with BR 7.1.2.8.7."""

    VALIDATION_DIGSIG_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        _CODE_CLASSIFIER + ".digitalsignature_bit_missing",
    )

    VALIDATION_PROHIBITED_KU_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        _CODE_CLASSIFIER + ".prohibited_ku_present",
    )

    _PROHIBITED_KUS = {str(n) for n in rfc5280.KeyUsage.namedValues} - {
        KeyUsageBitName.DIGITAL_SIGNATURE
    }

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_DIGSIG_MISSING,
                self.VALIDATION_PROHIBITED_KU_PRESENT,
            ],
            pdu_class=rfc5280.KeyUsage,
        )

    def validate(self, node):
        if not bitstring.has_named_bit(node, KeyUsageBitName.DIGITAL_SIGNATURE):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_DIGSIG_MISSING
            )

        prohibited_kus_asserted = sorted(
            (k for k in self._PROHIBITED_KUS if bitstring.has_named_bit(node, k))
        )

        if any(prohibited_kus_asserted):
            prohibited_kus_str = ", ".join(prohibited_kus_asserted)

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_KU_PRESENT,
                f"Prohibited KUs present: {prohibited_kus_str}",
            )


class OcspAuthorityInformationAccessAccessMethodPresenceValidator(
    common.AuthorityInformationAccessAccessMethodPresenceValidator
):
    """Validates that the content of the AIA extension conforms with BR 7.1.2.8.3."""

    _ACCESS_METHOD_ALLOWANCES = {
        rfc5280.id_ad_ocsp: Rfc2119Word.SHOULD_NOT,
    }

    def __init__(self):
        super().__init__(
            self._ACCESS_METHOD_ALLOWANCES, _CODE_CLASSIFIER, Rfc2119Word.MUST_NOT
        )


class OcspExtensionAllowanceValidator(
    pkilint.common.ExtensionIdentifierAllowanceValidator
):
    """Validates that the included extensions conform with BR 7.1.2.8.2."""

    _EXTENSION_ALLOWANCES = {
        rfc5280.id_ce_authorityKeyIdentifier: Rfc2119Word.MUST,
        rfc5280.id_ce_extKeyUsage: Rfc2119Word.MUST,
        rfc6960.id_pkix_ocsp_nocheck: Rfc2119Word.MUST,
        rfc5280.id_ce_keyUsage: Rfc2119Word.MUST,
        rfc5280.id_ce_basicConstraints: Rfc2119Word.MAY,
        rfc5280.id_ce_nameConstraints: Rfc2119Word.MUST_NOT,
        rfc5280.id_ce_subjectAltName: Rfc2119Word.MUST_NOT,
        rfc5280.id_ce_subjectKeyIdentifier: Rfc2119Word.SHOULD,
        rfc5280.id_pe_authorityInfoAccess: Rfc2119Word.SHOULD_NOT,
        rfc5280.id_ce_certificatePolicies: Rfc2119Word.MUST_NOT,
        rfc5280.id_ce_cRLDistributionPoints: Rfc2119Word.MUST_NOT,
        rfc6962.id_ce_embeddedSCT: Rfc2119Word.MAY,
    }

    def __init__(self):
        super().__init__(
            self._EXTENSION_ALLOWANCES, _CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT
        )


class OcspEkuAllowanceValidator(pkilint.common.ExtendedKeyUsageAllowanceValidator):
    """Validates that the extended key usage value conforms to BR 7.1.2.8.5."""

    _EKU_ALLOWANCES = {
        rfc5280.id_kp_OCSPSigning: Rfc2119Word.MUST,
    }

    def __init__(self):
        super().__init__(self._EKU_ALLOWANCES, _CODE_CLASSIFIER, Rfc2119Word.MUST_NOT)


class OcspBasicConstraintsValidator(validation.Validator):
    """Validates that the basic constraints extension value conforms to BR 7.1.2.8.4."""

    VALIDATION_CA_BIT_SET = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        _CODE_CLASSIFIER + ".basic_constraints_ca_bit_set",
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_CA_BIT_SET, pdu_class=rfc5280.BasicConstraints
        )

    def validate(self, node):
        if bool(node.children["cA"].pdu):
            raise validation.ValidationFindingEncountered(self.VALIDATION_CA_BIT_SET)
