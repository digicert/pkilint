from pyasn1_alt_modules import rfc5280

from pkilint import validation
from pkilint.common import common_name
from pkilint.pkix import general_name, extension

_ALLOWED_GENERAL_NAME_TYPES = {general_name.GeneralNameTypeName.DNS_NAME}


class NcpWCommonNameValidator(common_name.CommonNameValidator):
    """
    WEB-4.1.3-4 (d):

    If necessary to distinguish the website identified by the subject name, the subject commonName may contain a
    domain name or a Wildcard Domain Name (as defined in BRG [9]) which is one of the dNSName values of
    the subjectAltName extension of a website authentication certificate.
    """

    VALIDATION_COMMON_NAME_UNKNOWN_SOURCE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_4.web-4.1.3-4.common_name_unknown_source",
    )

    def __init__(self):
        super().__init__(
            _ALLOWED_GENERAL_NAME_TYPES, self.VALIDATION_COMMON_NAME_UNKNOWN_SOURCE
        )


class QncpWCommonNameValidator(common_name.CommonNameValidator):
    """
    WEB-4.1.4-2:

    If necessary to distinguish the website identified by the subject name, the subject commonName may contain a
    domain name or a Wildcard Domain Name (as defined in BRG [9]) which is one of the dNSName values of
    the subjectAltName extension of a website authentication certificate.
    """

    VALIDATION_COMMON_NAME_UNKNOWN_SOURCE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_4.web-4.1.4-2.common_name_unknown_source",
    )

    def __init__(self):
        super().__init__(
            _ALLOWED_GENERAL_NAME_TYPES, self.VALIDATION_COMMON_NAME_UNKNOWN_SOURCE
        )


class NcpWExtendedKeyUsagePresenceValidator(extension.ExtensionPresenceValidator):
    """
    WEB-4.1.3-4: The following certificate profile requirements specified in the BRG [9] shall apply for subject
    certificate fields addressed by the following sub-sections of BRG [9] (the version of BRG [9] shall be as referenced
    in ETSI EN 319 411-1 [6] for [WEB] requirements):
    a) 7.1.2.3 f) extKeyUsage
    """

    VALIDATION_EKU_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_4.web-4.1.3-4.eku_missing",
    )

    def __init__(self):
        super().__init__(
            extension_oid=rfc5280.id_ce_extKeyUsage,
            validation=self.VALIDATION_EKU_MISSING,
            pdu_class=rfc5280.Extensions,
        )


class NcpWSubjectAltNamePresenceValidator(extension.ExtensionPresenceValidator):
    """
    WEB-4.1.3-4: The following certificate profile requirements specified in the BRG [9] shall apply for subject
    certificate fields addressed by the following sub-sections of BRG [9] (the version of BRG [9] shall be as referenced
    in ETSI EN 319 411-1 [6] for [WEB] requirements):
    a) 7.1.2.3 b) Subject Alternative Name
    """

    VALIDATION_SAN_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_4.web-4.1.3-4.san_missing",
    )

    def __init__(self):
        super().__init__(
            extension_oid=rfc5280.id_ce_subjectAltName,
            validation=self.VALIDATION_SAN_MISSING,
            pdu_class=rfc5280.Extensions,
        )


class NcpWCriticalityExtendedKeyUsageValidator(extension.ExtensionCriticalityValidator):
    """Validates that the criticality of the EKU extension conforms to BRG."""

    EXTENDED_KEY_USAGE_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_4.web-4.1.3-4.eku_extension_is_critical",
    )

    def __init__(self):
        super().__init__(
            validation=self.EXTENDED_KEY_USAGE_CRITICAL,
            type_oid=rfc5280.id_ce_extKeyUsage,
            is_critical=False,
        )
