from pkilint import validation
from pkilint.common import common_name
from pkilint.pkix import general_name


_ALLOWED_GENERAL_NAME_TYPES = {general_name.GeneralNameTypeName.DNS_NAME}


class QncpWGenCommonNameValidator(common_name.CommonNameValidator):
    """
    WEB-4.1.3-4 (d):

    If necessary to distinguish the website identified by the subject name, the subject commonName may contain a
    domain name or a Wildcard Domain Name (as defined in BRG [9]) which is one of the dNSName values of
    the subjectAltName extension of a website authentication certificate.
    """
    VALIDATION_COMMON_NAME_UNKNOWN_SOURCE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_4.web-4.1.3-4.common_name_unknown_source'
    )

    def __init__(self):
        super().__init__(
            _ALLOWED_GENERAL_NAME_TYPES,
            self.VALIDATION_COMMON_NAME_UNKNOWN_SOURCE
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
        'etsi.en_319_412_4.web-4.1.4-2.common_name_unknown_source'
    )

    def __init__(self):
        super().__init__(
            _ALLOWED_GENERAL_NAME_TYPES,
            self.VALIDATION_COMMON_NAME_UNKNOWN_SOURCE
        )
