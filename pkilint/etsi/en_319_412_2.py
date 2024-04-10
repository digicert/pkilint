import enum
from typing import Optional

from pyasn1_alt_modules import rfc5280, rfc3739

from pkilint import validation, oid, document, common
from pkilint.etsi import etsi_constants
from pkilint.itu import bitstring
from pkilint.pkix import extension, name, Rfc2119Word
from pkilint.pkix.certificate.certificate_extension import KeyUsageBitName


class CertificatePoliciesCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_CERTIFICATE_POLICIES_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'etsi.en_319_412_2.gen-4.3.3-1.critical_certificate_policies_extension'
    )

    def __init__(self):
        super().__init__(validation=self.VALIDATION_CERTIFICATE_POLICIES_CRITICAL,
                         type_oid=rfc5280.id_ce_certificatePolicies,
                         is_critical=False)


class SubjectAlternativeNameCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_SAN_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.gen-4.3.5-1.san_extension_is_critical'
    )

    def __init__(self):
        super().__init__(validation=self.VALIDATION_SAN_CRITICAL,
                         type_oid=rfc5280.id_ce_subjectAltName,
                         is_critical=False)


class IssuerAlternativeNameCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_ISSUER_ALTERNATIVE_NAME_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.gen-4.3.6-1.ian_extension_is_critical'
    )

    def __init__(self):
        super().__init__(validation=self.VALIDATION_ISSUER_ALTERNATIVE_NAME_CRITICAL,
                         type_oid=rfc5280.id_ce_issuerAltName,
                         is_critical=False)


class ExtendedKeyUsageCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_EXTENDED_KEY_USAGE_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.gen-4.3.10-1.eku_extension_is_critical'
    )

    def __init__(self):
        super().__init__(validation=self.VALIDATION_EXTENDED_KEY_USAGE_CRITICAL,
                         type_oid=rfc5280.id_ce_extKeyUsage,
                         is_critical=False)


class CRLDistributionPointsCriticalityValidator(extension.ExtensionCriticalityValidator):
    CRL_DISTRIBUTION_POINTS_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.gen-4.3.11-5.crl_extension_is_critical'
    )

    def __init__(self):
        super().__init__(validation=self.CRL_DISTRIBUTION_POINTS_CRITICAL,
                         type_oid=rfc5280.id_ce_cRLDistributionPoints,
                         is_critical=False)


class NaturalPersonSubjectAttributeAllowanceValidator(validation.Validator):
    """
    NAT-4.2.4-1: The subject field shall include the following attributes as specified in Recommendation ITU-T X.520:
    • countryName;
    • choice of (givenName and/or surname) or pseudonym; and
    • commonName.
    """
    VALIDATION_NATURAL_PERSON_NAME_ATTRIBUTE_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-4.2.4-1.required_attribute_missing'
    )

    """
    NAT-4.2.4-4 The pseudonym attribute shall not be present if the givenName
    and surname attribute are present.
    """
    VALIDATION_MIXED_PSEUDONYM_AND_NAME_ATTRIBUTES_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-4.2.4-4.mixed_pseudonym_and_name_attributes_present'
    )

    """
    NAT 4.2.4-3 The subject field shall not contain more than one instance of commonName and countryName
    """
    VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-4.2.4-3.prohibited_duplicate_attribute_present'
    )

    _REQUIRED_ATTRIBUTES = {
        rfc5280.id_at_countryName,
        rfc5280.id_at_commonName,
    }

    _PSEUDONYM_AND_NAME_ATTRIBUTES = {
        rfc5280.id_at_givenName,
        rfc5280.id_at_surname,
        rfc5280.id_at_pseudonym,
    }

    _PROHIBITED_DUPLICATE_ATTRIBUTES = {
        rfc5280.id_at_countryName,
        rfc5280.id_at_commonName,
    }

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_NATURAL_PERSON_NAME_ATTRIBUTE_MISSING,
                self.VALIDATION_MIXED_PSEUDONYM_AND_NAME_ATTRIBUTES_PRESENT,
                self.VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT
            ],
            pdu_class=rfc5280.Name
        )

    def validate(self, node):
        attr_counts = name.get_name_attribute_counts(node)

        attrs_present = set(attr_counts.keys())

        missing_attrs = None

        if not attrs_present.issuperset(self._REQUIRED_ATTRIBUTES):
            missing_attrs = self._REQUIRED_ATTRIBUTES - attrs_present
        elif attrs_present.isdisjoint(self._PSEUDONYM_AND_NAME_ATTRIBUTES):
            missing_attrs = self._PSEUDONYM_AND_NAME_ATTRIBUTES - attrs_present

        if missing_attrs:
            oid_str = oid.format_oids(missing_attrs)

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NATURAL_PERSON_NAME_ATTRIBUTE_MISSING,
                f'Required attributes missing: {oid_str}'
            )

        if all((a in attrs_present for a in self._PSEUDONYM_AND_NAME_ATTRIBUTES)):
            raise validation.ValidationFindingEncountered(self.VALIDATION_MIXED_PSEUDONYM_AND_NAME_ATTRIBUTES_PRESENT)

        for a in self._PROHIBITED_DUPLICATE_ATTRIBUTES:
            if attr_counts[a] > 1:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT,
                    f'Prohibited duplicate attribute present: {a}'
                )


class NaturalPersonExtensionIdentifierAllowanceValidator(common.ExtensionIdentifierAllowanceValidator):
    _CODE_CLASSIFIER = 'etsi.en_319_412_2'

    _ALLOWANCES = {
        # GEN-4.3.1-1
        rfc5280.id_ce_authorityKeyIdentifier: Rfc2119Word.MUST,
        # NAT-4.3.2-1
        rfc5280.id_ce_keyUsage: Rfc2119Word.MUST,
        # GEN-4.3.3-2
        rfc5280.id_ce_certificatePolicies: Rfc2119Word.MUST,
        # GEN-4.3.4-1
        rfc5280.id_ce_policyMappings: Rfc2119Word.MUST_NOT,

        rfc5280.id_ce_subjectAltName: Rfc2119Word.MAY,
        rfc5280.id_ce_issuerAltName: Rfc2119Word.MAY,
        rfc5280.id_ce_subjectDirectoryAttributes: Rfc2119Word.MAY,
        # GEN-4.3.8-1
        rfc5280.id_ce_nameConstraints: Rfc2119Word.MUST_NOT,
        # GEN-4.3.9-1
        rfc5280.id_ce_policyConstraints: Rfc2119Word.MUST_NOT,
        rfc5280.id_ce_cRLDistributionPoints: Rfc2119Word.MAY,
        # GEN-4.3.12-1
        rfc5280.id_ce_inhibitAnyPolicy: Rfc2119Word.MUST_NOT,
        # GEN-4.4.1-2
        rfc5280.id_pe_authorityInfoAccess: Rfc2119Word.MUST,
    }

    def __init__(self, certificate_type: etsi_constants.CertificateType):
        allowances = self._ALLOWANCES.copy()

        if certificate_type in etsi_constants.EU_QWAC_TYPES:
            allowances[rfc3739.id_pe_qcStatements] = Rfc2119Word.MUST
        else:
            allowances[rfc3739.id_pe_qcStatements] = Rfc2119Word.MAY

        super().__init__(allowances, self._CODE_CLASSIFIER, Rfc2119Word.MAY)


class KeyUsageValueValidator(validation.Validator):
    """
    NAT-4.3.2-1: The key usage extension shall be present and shall contain one (and only one) of the key usage settings
    defined in table 1 (A, B, C, D, E or F).
    """
    VALIDATION_UNKNOWN_KEY_USAGE_SETTING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-4.3.2-1.unknown_key_usage_setting'
    )

    """
    NAT-4.3.2-1: ... Type A, C or E should be used to avoid mixed usage of keys.
    """
    VALIDATION_MIXED_KEY_USAGE_SETTING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'etsi.en_319_412_2.nat-4.3.2-1.mixed_key_usage_setting'
    )

    """
    NAT-4.3.2-2: Certificates used to validate commitment to signed content (e.g. documents, agreements and/or
    transactions) shall be limited to type A, B or F.
    """
    VALIDATION_INVALID_CONTENT_COMMITMENT_SETTING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.en_319_412_2.nat-4.3.2-1.invalid_content_commitment_setting'
    )

    """
    NAT-4.3.2-3: Of these alternatives, type A should be used (see the security note 2 below).
    """
    VALIDATION_NON_PREFERRED_CONTENT_COMMITMENT_SETTING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'etsi.en_319_412_2.nat-4.3.2-3.non_preferred_content_commitment_setting'
    )

    _ALL_KUS = {str(n) for n in rfc5280.KeyUsage.namedValues}

    def __init__(self, is_content_commitment_type: Optional[bool]):
        super().__init__(
            validations=[
                self.VALIDATION_UNKNOWN_KEY_USAGE_SETTING,
                self.VALIDATION_MIXED_KEY_USAGE_SETTING,
                self.VALIDATION_INVALID_CONTENT_COMMITMENT_SETTING,
                self.VALIDATION_NON_PREFERRED_CONTENT_COMMITMENT_SETTING,
            ],
            pdu_class=rfc5280.KeyUsage
        )

        self._is_content_commitment_type = is_content_commitment_type

    class KeyUsageSetting(enum.Enum):
        A = ({KeyUsageBitName.NON_REPUDIATION}, set())
        B = ({KeyUsageBitName.NON_REPUDIATION, KeyUsageBitName.DIGITAL_SIGNATURE}, set())
        C = ({KeyUsageBitName.DIGITAL_SIGNATURE}, set())
        D = ({KeyUsageBitName.DIGITAL_SIGNATURE}, {KeyUsageBitName.KEY_AGREEMENT, KeyUsageBitName.KEY_ENCIPHERMENT})
        E = (set(), {KeyUsageBitName.KEY_AGREEMENT, KeyUsageBitName.KEY_ENCIPHERMENT})
        F = (
            {KeyUsageBitName.NON_REPUDIATION, KeyUsageBitName.DIGITAL_SIGNATURE},
            {KeyUsageBitName.KEY_AGREEMENT, KeyUsageBitName.KEY_ENCIPHERMENT}
        )

    _CONTENT_COMMITMENT_SETTINGS = {KeyUsageSetting.A, KeyUsageSetting.B, KeyUsageSetting.F}
    _NON_CONTENT_COMMITMENT_SETTINGS = {s for s in KeyUsageSetting} - _CONTENT_COMMITMENT_SETTINGS

    _MIXED_USE_SETTINGS = {KeyUsageSetting.B, KeyUsageSetting.D, KeyUsageSetting.F}

    @classmethod
    def _detect_setting(cls, key_usage_node: document.PDUNode) -> Optional[KeyUsageSetting]:
        asserted_bits = {k for k in cls._ALL_KUS if bitstring.has_named_bit(key_usage_node, k)}

        for setting in cls.KeyUsageSetting:
            n_of_n_required_bits, one_of_n_required_bits = setting.value

            allowed_bits = n_of_n_required_bits | one_of_n_required_bits

            if (
                asserted_bits >= n_of_n_required_bits and
                (len(one_of_n_required_bits & asserted_bits) == 1 or not one_of_n_required_bits) and
                not any(asserted_bits - allowed_bits)
            ):
                return setting

        return None

    def validate(self, node):
        setting = self._detect_setting(node)

        if setting is None:
            raise validation.ValidationFindingEncountered(self.VALIDATION_UNKNOWN_KEY_USAGE_SETTING)

        if self._is_content_commitment_type is not None:
            if self._is_content_commitment_type:
                if setting not in self._CONTENT_COMMITMENT_SETTINGS:
                    raise validation.ValidationFindingEncountered(self.VALIDATION_INVALID_CONTENT_COMMITMENT_SETTING)
                elif setting != self.KeyUsageSetting.A:
                    raise validation.ValidationFindingEncountered(
                        self.VALIDATION_NON_PREFERRED_CONTENT_COMMITMENT_SETTING
                    )
            elif not self._is_content_commitment_type and setting not in self._NON_CONTENT_COMMITMENT_SETTINGS:
                raise validation.ValidationFindingEncountered(self.VALIDATION_INVALID_CONTENT_COMMITMENT_SETTING)

        if setting in self._MIXED_USE_SETTINGS:
            raise validation.ValidationFindingEncountered(self.VALIDATION_MIXED_KEY_USAGE_SETTING)
