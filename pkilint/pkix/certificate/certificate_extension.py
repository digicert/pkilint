import unicodedata
from typing import NamedTuple, Set

from pyasn1.type.univ import ObjectIdentifier
from pyasn1_alt_modules import rfc5280, rfc4262

from pkilint import validation
from pkilint.itu.bitstring import has_named_bit
from pkilint.pkix import extension
from pkilint.pkix.extension import (get_criticality_from_decoded_node,
                                    ExtensionCriticalityValidator
                                    )

CERTIFICATE_POLICY_QUALIFIER_MAPPINGS = {
    rfc5280.id_qt_cps: rfc5280.CPSuri(),
    rfc5280.id_qt_unotice: rfc5280.UserNotice(),
}


class BasicConstraintsValidator(validation.Validator):
    VALIDATION_ILLEGAL_PATHLEN_SET = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.basic_constraints.has_pathlen_for_non_ca'
    )
    VALIDATION_NOT_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.basic_constraints.extension_not_critical'
    )

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.BasicConstraints,
            validations=[
                self.VALIDATION_ILLEGAL_PATHLEN_SET,
                self.VALIDATION_NOT_CRITICAL,
            ]
        )

    def validate(self, node):
        is_ca = bool(node.children['cA'].pdu)

        if not is_ca and 'pathLenConstraint' in node.children:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ILLEGAL_PATHLEN_SET,
                f'Certificate is end-entity but has pathLenConstraint of '
                f'{int(node.children["pathLenConstraint"].pdu)} set'
            )

        is_critical = get_criticality_from_decoded_node(node)

        if not is_critical and is_ca:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NOT_CRITICAL,
                'CA certificate does not have critical basicConstraints'
            )


class CertificatePolicySet(NamedTuple):
    required: bool
    policies: Set[ObjectIdentifier]


def _format_policy_oids(oids):
    return ', '.join(map(str, oids))


class CertificatePolicyOIDValidator(validation.Validator):
    VALIDATION_REQUIRED_POLICY_OID_NOT_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.required_certificate_policy_oid_missing'
    )

    VALIDATION_CONFLICTING_POLICY_OIDS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.conflicting_certificate_policy_oids'
    )

    VALIDATION_UNKNOWN_POLICY_OID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.unknown_certificate_policy_oid'
    )

    VALIDATION_ANYPOLICY_IN_END_ENTITY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'pkix.anypolicy_certificate_policy_in_end_entity_certificate'
    )

    def __init__(self, *, policy_sets, allow_other_policies=True):
        self._policy_sets = policy_sets
        self._allow_other_policies = allow_other_policies

        validations = [
            self.VALIDATION_REQUIRED_POLICY_OID_NOT_PRESENT,
            self.VALIDATION_CONFLICTING_POLICY_OIDS,
            self.VALIDATION_ANYPOLICY_IN_END_ENTITY,
        ]

        if not allow_other_policies:
            validations.append(self.VALIDATION_UNKNOWN_POLICY_OID)

        super().__init__(
            pdu_class=rfc5280.CertificatePolicies,
            validations=validations
        )

    def validate(self, node):
        policy_oids = {
            policy.children['policyIdentifier'].pdu
            for policy in node.children.values()
        }

        findings = []

        if not self._allow_other_policies:
            all_specified_policies = set()
            for policy_set in self._policy_sets:
                all_specified_policies += policy_set.policies

            other_policies = policy_oids - all_specified_policies
            if len(other_policies) > 0:
                other_policies_str = _format_policy_oids(other_policies)
                findings.append(validation.ValidationFindingDescription(
                    self.VALIDATION_UNKNOWN_POLICY_OID,
                    f'Unknown certificate policies: {other_policies_str}'
                ))

        is_ca = node.document.is_ca

        for policy_set in self._policy_sets:
            policy_intersection = policy_set.policies & policy_oids

            if policy_set.required and len(policy_intersection) == 0:
                policies_str = _format_policy_oids(policy_set.policies)

                findings.append(validation.ValidationFindingDescription(
                    self.VALIDATION_REQUIRED_POLICY_OID_NOT_PRESENT,
                    f'None of the following certificate policies are present: '
                    f'{policies_str}'
                ))

            if not is_ca and len(policy_intersection) > 1:
                policies_str = _format_policy_oids(policy_intersection)

                findings.append(validation.ValidationFindingDescription(
                    self.VALIDATION_CONFLICTING_POLICY_OIDS,
                    f'Conflicting certificate policies present: {policies_str}'
                ))

        if not is_ca and rfc5280.anyPolicy in policy_oids:
            findings.append(validation.ValidationFindingDescription(
                self.VALIDATION_ANYPOLICY_IN_END_ENTITY,
                None
            ))

        return validation.ValidationResult(self, node, findings)


class SubjectKeyIdentifierPresenceValidator(validation.Validator):
    VALIDATION_EE_SKID_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'pkix.certificate_skid_end_entity_missing'
    )

    VALIDATION_CA_SKID_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.certificate_skid_ca_missing'
    )

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.Certificate,
            validations=[
                self.VALIDATION_EE_SKID_MISSING,
                self.VALIDATION_CA_SKID_MISSING,
            ])

    def validate(self, node):
        is_ca = node.document.is_ca

        skid_ext = node.document.get_extension_by_oid(
            rfc5280.id_ce_subjectKeyIdentifier
        )

        if skid_ext is None:
            if is_ca:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_CA_SKID_MISSING
                )
            else:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_EE_SKID_MISSING
                )


class SubjectKeyIdentifierCriticalityValidator(ExtensionCriticalityValidator):
    VALIDATION_SKID_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.certificate_skid_extension_critical'
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc5280.id_ce_subjectKeyIdentifier,
            is_critical=False,
            validation=self.VALIDATION_SKID_CRITICAL
        )


class CrlDpCriticalityValidator(ExtensionCriticalityValidator):
    VALIDATION_CRLDP_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'pkix.certificate_crldp_extension_critical'
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc5280.id_ce_cRLDistributionPoints,
            is_critical=False,
            validation=self.VALIDATION_CRLDP_CRITICAL
        )


class NameConstraintsCriticalityValidator(ExtensionCriticalityValidator):
    VALIDATION_NC_NOT_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.certificate_name_constraints_extension_not_critical'
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc5280.id_ce_nameConstraints,
            is_critical=True,
            validation=self.VALIDATION_NC_NOT_CRITICAL
        )


class NameConstraintsValidator(validation.Validator):
    VALIDATION_NO_SUBTREES = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.name_constraints_no_subtrees'
    )

    VALIDATION_NC_IN_EE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.name_constraints_in_ee_certificate'
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_NO_SUBTREES,
                self.VALIDATION_NC_IN_EE
            ],
            pdu_class=rfc5280.NameConstraints
        )

    def validate(self, node):
        if not node.document.is_ca:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NC_IN_EE
            )

        if len(node.children) == 0:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NO_SUBTREES
            )


class NameConstraintsGeneralSubtreeValidator(validation.Validator):
    VALIDATION_NON_DEFAULT_MINIMUM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.name_constraints_non_default_minimum'
    )

    VALIDATION_MAXIMUM_SPECIFIED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.name_constraints_maximum_specified'
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_NON_DEFAULT_MINIMUM,
                self.VALIDATION_MAXIMUM_SPECIFIED,
            ],
            pdu_class=rfc5280.GeneralSubtree
        )

    def validate(self, node):
        results = []

        minimum_dist = int(node.children['minimum'].pdu)
        if minimum_dist != 0:
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_NON_DEFAULT_MINIMUM,
                    f'Non-default minimum distance: {minimum_dist}'
                )
            )

        if 'maximum' in node.children:
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_MAXIMUM_SPECIFIED,
                    None
                )
            )

        return validation.ValidationResult(self, node, results)


def _get_policy_oids(ext):
    return {
        pi.children['policyIdentifier'].pdu
        for pi in ext.children.values()
    }


class IssuerSubjectPolicyChainValidator(validation.Validator):
    VALIDATION_SUBJECT_CERTIFICATE_POLICY_MISMATCH = (
        validation.ValidationFinding(
            validation.ValidationFindingSeverity.NOTICE,
            'pkix.certificate_subject_has_policy_not_in_issuer'
        )
    )

    VALIDATION_SUBJECT_NO_CP_EXTENSION = validation.ValidationFinding(
        validation.ValidationFindingSeverity.INFO,
        'pkix.certificate_has_no_certificate_policies_extension'
    )

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.CertificatePolicies,
            validations=[
                self.VALIDATION_SUBJECT_CERTIFICATE_POLICY_MISMATCH,
                self.VALIDATION_SUBJECT_NO_CP_EXTENSION,
            ]
        )

    def validate(self, node):
        subject_cert = node.document.parent['subject']

        cp_ext_and_idx = subject_cert.get_extension_by_oid(
            rfc5280.id_ce_certificatePolicies
        )

        if cp_ext_and_idx is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_SUBJECT_NO_CP_EXTENSION
            )

        subject_cert_cp_ext_decoded = cp_ext_and_idx[0].navigate(
            'extnValue.certificatePolicies'
        )

        issuer_cert_policy_oids = _get_policy_oids(node)
        subject_cert_policy_oids = _get_policy_oids(
            subject_cert_cp_ext_decoded
        )

        if rfc5280.anyPolicy not in issuer_cert_policy_oids:
            difference = subject_cert_policy_oids - issuer_cert_policy_oids

            if len(difference) > 0:
                difference_str = ', '.join(map(str, difference))

                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_SUBJECT_CERTIFICATE_POLICY_MISMATCH,
                    f'Policy OIDs found in subject certificate but not in '
                    f'issuer certificate: {difference_str}'
                )


class DuplicatePolicyValidator(validation.Validator):
    VALIDATION_DUPLICATE_POLICIES = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.duplicate_certificate_policy_oids'
    )

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_DUPLICATE_POLICIES],
                         pdu_class=rfc5280.CertificatePolicies
                         )

    def validate(self, node):
        policy_oids = [
            pi.children['policyIdentifier'].pdu
            for pi in node.children.values()
        ]

        duplicates = [
            o
            for o in policy_oids
            if policy_oids.count(o) > 1
        ]

        if len(duplicates) > 0:
            dups_str = ', '.join(map(str, duplicates))

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_DUPLICATE_POLICIES,
                f'Duplicate policy identifiers: {dups_str}'
            )


class CertificatePolicyQualifierValidator(validation.Validator):
    VALIDATION_POLICY_HAS_QUALIFIER = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'pkix.certificate_policies_policy_has_qualifier'
    )

    VALIDATION_ANYPOLICY_DISALLOWED_QUALIFIER = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.certificate_policies_anypolicy_has_prohibited_qualifier'
    )

    def __init__(self):
        super().__init__(pdu_class=rfc5280.PolicyInformation,
                         validations=[
                             self.VALIDATION_POLICY_HAS_QUALIFIER,
                             self.VALIDATION_ANYPOLICY_DISALLOWED_QUALIFIER,
                         ]
                         )

    def validate(self, node):
        if 'policyQualifiers' in node.children:
            if node.children['policyIdentifier'].pdu == rfc5280.anyPolicy:
                disallowed_qualifiers = [
                    q.children['policyQualifierId'].pdu
                    for q in node.children['policyQualifiers'].children.values()
                    if q.children['policyQualifierId'].pdu not in [
                        rfc5280.id_qt_cps,
                        rfc5280.id_qt_unotice,
                    ]
                ]

                if len(disallowed_qualifiers) > 0:
                    message = ', '.join(map(str, disallowed_qualifiers))

                    raise validation.ValidationFindingEncountered(
                        self.VALIDATION_ANYPOLICY_DISALLOWED_QUALIFIER,
                        f'anyPolicy has disallowed qualifiers: {message}'
                    )

            if len(node.children['policyQualifiers'].children) > 0:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_POLICY_HAS_QUALIFIER
                )


class CertificatePoliciesUserNoticeValidator(validation.Validator):
    VALIDATION_NOTICEREF_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'pkix.certificate_policies_usernotice_has_noticeRef'
    )

    VALIDATION_EXPLICITTEXT_INVALID_ENCODING_5280 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.rfc5280_certificate_policies_invalid_explicit_text_encoding'
    )

    VALIDATION_EXPLICITTEXT_INVALID_ENCODING_6818 = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.rfc6818_certificate_policies_invalid_explicit_text_encoding'
    )

    VALIDATION_EXPLICITTEXT_HAS_CONTROL_CHARACTER = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'pkix.certificate_policies_explicit_text_has_control_character'
    )

    VALIDATION_EXPLICITTEXT_NOT_NFC = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'pkix.certificate_policies_explicit_text_not_nfc_normalized'
    )

    def __init__(self):
        super().__init__(pdu_class=rfc5280.UserNotice, validations=[
            self.VALIDATION_NOTICEREF_PRESENT,
            self.VALIDATION_EXPLICITTEXT_INVALID_ENCODING_5280,
            self.VALIDATION_EXPLICITTEXT_INVALID_ENCODING_6818,
            self.VALIDATION_EXPLICITTEXT_HAS_CONTROL_CHARACTER,
            self.VALIDATION_EXPLICITTEXT_NOT_NFC,
        ])

    def validate(self, node):
        results = []

        if 'noticeRef' in node.children:
            results.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_NOTICEREF_PRESENT,
                    None
                )
            )

        explicit_text = node.children.get('explicitText')

        if explicit_text is not None:
            encoding, value = explicit_text.child

            if encoding not in ['ia5String', 'utf8String']:
                results.append(
                    validation.ValidationFindingDescription(
                        self.VALIDATION_EXPLICITTEXT_INVALID_ENCODING_5280,
                        f'Invalid encoding: {encoding}'
                    )
                )

            if encoding not in ['bmpString', 'utf8String', 'visibleString']:
                results.append(
                    validation.ValidationFindingDescription(
                        self.VALIDATION_EXPLICITTEXT_INVALID_ENCODING_6818,
                        f'Invalid encoding: {encoding}'
                    )
                )

            if str(value.pdu) != unicodedata.normalize('NFC', str(value.pdu)):
                results.append(
                    validation.ValidationFindingDescription(
                        self.VALIDATION_EXPLICITTEXT_NOT_NFC,
                        None
                    )
                )

            if any((
                    ord(c) <= 0x1f or (0x7f <= ord(c) <= 0x9f)
                    for c in str(value.pdu)
            )):
                results.append(
                    validation.ValidationFindingDescription(
                        self.VALIDATION_EXPLICITTEXT_HAS_CONTROL_CHARACTER,
                        None
                    )
                )

        return validation.ValidationResult(self, node, results)


class KeyUsagePresenceValidator(extension.ExtensionPresenceValidator):
    VALIDATION_CA_NO_KU_EXTENSION = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.ca_certificate_no_ku_extension'
    )

    def __init__(self):
        super().__init__(
            extension_oid=rfc5280.id_ce_keyUsage,
            validation=self.VALIDATION_CA_NO_KU_EXTENSION,
            pdu_class=rfc5280.Extensions,
            predicate=lambda n: n.document.is_ca
        )


class KeyUsageCriticalityValidator(validation.Validator):
    VALIDATION_KU_NOT_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'pkix.key_usage_extension_not_critical'
    )

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.KeyUsage,
            validations=[self.VALIDATION_KU_NOT_CRITICAL]
        )

    def validate(self, node):
        if not get_criticality_from_decoded_node(node):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_KU_NOT_CRITICAL
            )


class KeyUsageValidator(validation.Validator):
    VALIDATION_NO_BITS_SET = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.no_ku_bits_set'
    )

    VALIDATION_CA_KEYCERTSIGN_NOT_SET = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.ca_certificate_keycertsign_keyusage_not_set'
    )

    VALIDATION_EE_KEYCERTSIGN_SET = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.ee_certificate_keycertsign_keyusage_set'
    )

    VALIDATION_EO_AND_DO_SET = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.both_encipheronly_and_decipheronly_ku_set'
    )

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.KeyUsage,
            validations=[
                self.VALIDATION_NO_BITS_SET,
                self.VALIDATION_CA_KEYCERTSIGN_NOT_SET,
                self.VALIDATION_EE_KEYCERTSIGN_SET,
                self.VALIDATION_EO_AND_DO_SET,
            ]
        )

    def validate(self, node):
        if not any(
                map(
                    lambda kn: has_named_bit(node, kn),
                    rfc5280.KeyUsage.namedValues.keys()
                )
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NO_BITS_SET
            )

        is_ca = node.document.is_ca

        has_keycertsign = has_named_bit(node, 'keyCertSign')

        if is_ca and not has_keycertsign:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CA_KEYCERTSIGN_NOT_SET
            )
        elif not is_ca and has_keycertsign:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_EE_KEYCERTSIGN_SET
            )

        has_eo = has_named_bit(node, 'encipherOnly')
        has_do = has_named_bit(node, 'decipherOnly')

        if has_eo and has_do:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_EO_AND_DO_SET
            )


class AuthorityKeyIdentifierPresenceValidator(validation.Validator):
    VALIDATION_AKI_EXTENSION_NOT_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.authority_key_identifier_extension_absent'
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_AKI_EXTENSION_NOT_PRESENT],
            pdu_class=rfc5280.Certificate
        )

    def validate(self, node):
        ext = node.document.get_extension_by_oid(
            rfc5280.id_ce_authorityKeyIdentifier
        )

        if not node.document.is_self_signed and ext is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_AKI_EXTENSION_NOT_PRESENT
            )


class AuthorityInformationAccessCriticalityValidator(
    ExtensionCriticalityValidator
):
    VALIDATION_AIA_EXTENSION_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.authority_information_access_extension_critical'
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc5280.id_pe_authorityInfoAccess,
            is_critical=False,
            validation=self.VALIDATION_AIA_EXTENSION_CRITICAL
        )


class AuthorityKeyIdentifierCriticalityValidator(ExtensionCriticalityValidator):
    VALIDATION_AKID_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.certificate_akid_extension_critical'
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc5280.id_ce_authorityKeyIdentifier,
            is_critical=False,
            validation=self.VALIDATION_AKID_CRITICAL
        )


class SubjectInformationAccessCriticalityValidator(
    ExtensionCriticalityValidator
):
    VALIDATION_SIA_EXTENSION_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.subject_information_access_extension_critical'
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc5280.id_pe_subjectInfoAccess,
            is_critical=False,
            validation=self.VALIDATION_SIA_EXTENSION_CRITICAL
        )


class SubjectAlternativeNameCriticalityValidator(validation.TypeMatchingValidator):
    VALIDATION_SAN_NOT_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.san_extension_not_critical'
    )

    VALIDATION_SAN_IS_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'pkix.san_extension_is_critical'
    )

    def __init__(self):
        super().__init__(type_path='extnID', type_oid=rfc5280.id_ce_subjectAltName, value_path='critical',
                         pdu_class=rfc5280.Extension, validations=[
                            self.VALIDATION_SAN_NOT_CRITICAL, self.VALIDATION_SAN_IS_CRITICAL
                         ])

    def validate_with_value(self, node, value_node):
        is_critical = bool(value_node.pdu)

        subject_node = node.navigate(':certificate.tbsCertificate.subject.rdnSequence')

        if not any(subject_node.children) and not is_critical:
            raise validation.ValidationFindingEncountered(self.VALIDATION_SAN_NOT_CRITICAL)

        if any(subject_node.children) and is_critical:
            raise validation.ValidationFindingEncountered(self.VALIDATION_SAN_IS_CRITICAL)


class SubjectDirectoryAttributesCriticalityValidator(ExtensionCriticalityValidator):
    VALIDATION_SDA_EXTENSION_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.subject_directory_attributes_extension_critical'
    )

    def __init__(self):
        super().__init__(type_oid=rfc5280.id_ce_subjectDirectoryAttributes, is_critical=False,
                         validation=self.VALIDATION_SDA_EXTENSION_CRITICAL)


class SmimeCapabilitiesCriticalityValidator(ExtensionCriticalityValidator):
    VALIDATION_SMIME_CAPABILITIES_EXTENSION_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'pkix.smime_capabilities_extension_critical'
    )

    def __init__(self):
        super().__init__(type_oid=rfc4262.smimeCapabilities, is_critical=False,
                         validation=self.VALIDATION_SMIME_CAPABILITIES_EXTENSION_CRITICAL)
