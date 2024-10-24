from pyasn1_alt_modules import rfc5280, rfc6962

from pkilint import common, validation
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.pkix import Rfc2119Word

_CODE_CLASSIFIER = "cabf.serverauth.cross_ca"


class CrossCertificateExtensionAllowanceValidator(
    common.ExtensionIdentifierAllowanceValidator
):
    """Validates that the extensions conform with BR 7.1.2.2.3."""

    _EXTENSION_ALLOWANCES = {
        rfc5280.id_ce_authorityKeyIdentifier: Rfc2119Word.MUST,
        rfc5280.id_ce_basicConstraints: Rfc2119Word.MUST,
        rfc5280.id_ce_certificatePolicies: Rfc2119Word.MUST,
        rfc5280.id_ce_cRLDistributionPoints: Rfc2119Word.MUST,
        rfc5280.id_ce_keyUsage: Rfc2119Word.MUST,
        rfc5280.id_ce_subjectKeyIdentifier: Rfc2119Word.MUST,
        rfc5280.id_pe_authorityInfoAccess: Rfc2119Word.SHOULD,
        rfc5280.id_ce_nameConstraints: Rfc2119Word.MUST_NOT,
        rfc6962.id_ce_embeddedSCT: Rfc2119Word.MAY,
    }

    def __init__(self, certificate_type):
        self._extension_allowances = self._EXTENSION_ALLOWANCES.copy()

        if certificate_type in serverauth_constants.EXTERNAL_CROSS_CA_TYPES:
            eku_allowance_word = Rfc2119Word.MUST
        elif certificate_type in serverauth_constants.INTERNAL_CROSS_CA_TYPES:
            eku_allowance_word = Rfc2119Word.SHOULD
        else:
            raise ValueError(f"Unsupported certificate type: {certificate_type}")

        self._extension_allowances[rfc5280.id_ce_extKeyUsage] = eku_allowance_word

        super().__init__(
            self._extension_allowances, _CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT
        )


class CrossCertificateAllowedEkuValidator(common.ExtendedKeyUsageAllowanceValidator):
    """Validates that the content of the extended key usage conforms to BR 7.1.2.2.4 and 7.1.2.2.5."""

    _RESTRICTED_EKU_ALLOWANCES = {
        rfc5280.id_kp_serverAuth: Rfc2119Word.MUST,
        rfc5280.id_kp_clientAuth: Rfc2119Word.MAY,
        rfc5280.id_kp_emailProtection: Rfc2119Word.MUST_NOT,
        rfc5280.id_kp_codeSigning: Rfc2119Word.MUST_NOT,
        rfc5280.id_kp_timeStamping: Rfc2119Word.MUST_NOT,
        rfc5280.id_kp_OCSPSigning: Rfc2119Word.MUST_NOT,
    }

    VALIDATION_EXTERNAL_CROSS_CA_ANYEKU_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        _CODE_CLASSIFIER + ".external_anyeku_present",
    )

    VALIDATION_INTERNAL_CROSS_CA_ANYEKU_WITH_OTHER_EKU = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        _CODE_CLASSIFIER + ".internal_with_anyeku_and_other_eku",
    )

    def __init__(self, certificate_type: serverauth_constants.CertificateType):
        self._certificate_type = certificate_type

        super().__init__(
            self._RESTRICTED_EKU_ALLOWANCES, _CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT
        )

        self._validations.extend(
            [
                self.VALIDATION_INTERNAL_CROSS_CA_ANYEKU_WITH_OTHER_EKU,
                self.VALIDATION_EXTERNAL_CROSS_CA_ANYEKU_PRESENT,
            ]
        )

    def validate(self, node):
        ekus = {n.pdu for n in node.children.values()}

        if rfc5280.anyExtendedKeyUsage in ekus:
            if self._certificate_type in serverauth_constants.EXTERNAL_CROSS_CA_TYPES:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_EXTERNAL_CROSS_CA_ANYEKU_PRESENT
                )
            elif self._certificate_type in serverauth_constants.INTERNAL_CROSS_CA_TYPES:
                if len(node.children) != 1:
                    raise validation.ValidationFindingEncountered(
                        self.VALIDATION_INTERNAL_CROSS_CA_ANYEKU_WITH_OTHER_EKU
                    )
            else:
                raise ValueError(
                    f"Unsupported certificate type: {self._certificate_type}"
                )
        else:
            return super().validate(node)
