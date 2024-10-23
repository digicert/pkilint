from pkilint import finding_filter
from pkilint.pkix import general_name
from pkilint.pkix.certificate import certificate_extension


class NameConstraintsCriticalityFilter(finding_filter.ValidationFindingFilter):
    def __init__(self):
        super().__init__(
            certificate_extension.NameConstraintsCriticalityValidator.VALIDATION_NC_NOT_CRITICAL
        )


class DnsNameGeneralNamePreferredNameSyntaxFilter(
    finding_filter.ValidationFindingFilter
):
    def __init__(self):
        super().__init__(
            general_name.GeneralNameDnsNameSyntaxValidator.VALIDATION_NOT_PREFERRED_NAME_SYNTAX
        )


class EndEntitySubjectKeyIdentifierMissingFilter(
    finding_filter.ValidationFindingFilter
):
    def __init__(self):
        super().__init__(
            certificate_extension.SubjectKeyIdentifierPresenceValidator.VALIDATION_EE_SKID_MISSING
        )


class PolicyQualifierPresentFilter(finding_filter.ValidationFindingFilter):
    def __init__(self):
        super().__init__(
            certificate_extension.CertificatePolicyQualifierValidator.VALIDATION_POLICY_HAS_QUALIFIER
        )
