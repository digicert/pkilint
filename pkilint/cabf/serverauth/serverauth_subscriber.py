import ipaddress
import operator
from datetime import timedelta

from pyasn1_alt_modules import rfc5280, rfc6962, rfc5480

import pkilint.common
from pkilint import validation, document, oid, common
from pkilint.cabf import cabf_name
from pkilint.cabf.asn1 import ev_guidelines
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.common import organization_id
from pkilint.common.organization_id import ParsedOrganizationIdentifier
from pkilint.itu import x520_name, bitstring
from pkilint.pkix import Rfc2119Word, general_name, time


def _parse_organization_identifier_extension(
        ext_node: document.PDUNode) -> organization_id.ParsedOrganizationIdentifier:
    state_province_node = ext_node.children.get('registrationStateOrProvince')

    state_province = str(state_province_node.pdu) if state_province_node else None

    reference_node = ext_node.children.get('registrationReference')
    reference = str(reference_node.pdu) if reference_node else None

    return organization_id.ParsedOrganizationIdentifier(
        raw=None,
        scheme=str(ext_node.children['registrationSchemeIdentifier'].pdu),
        is_national_scheme=False,
        country=str(ext_node.children['registrationCountry'].pdu),
        state_province=state_province,
        reference=reference
    )


class CABFOrganizationIdentifierExtensionValidator(cabf_name.CabfOrganizationIdentifierValidatorBase):
    """Validates that the content of the CA/B Forum organizationIdentifier extension conforms with EVG 9.8.2."""

    def __init__(self):
        super().__init__(
            invalid_format_validation=None,
            enforce_strict_state_province_format=True,
            pdu_class=ev_guidelines.CABFOrganizationIdentifier
        )

    @classmethod
    def parse_organization_id_node(cls, node: document.PDUNode) -> ParsedOrganizationIdentifier:
        return _parse_organization_identifier_extension(node)


class EvSubscriberAttributeAllowanceValidator(pkilint.common.AttributeIdentifierAllowanceValidator):
    """Validates that the content of the subject conforms to EVG 9.2."""

    _CODE_CLASSIFIER = 'cabf.ev_guidelines'

    _ATTRIBUTE_ALLOWANCES = {
        rfc5280.id_at_countryName: Rfc2119Word.MUST,
        rfc5280.id_at_stateOrProvinceName: Rfc2119Word.MAY,
        rfc5280.id_at_localityName: Rfc2119Word.MAY,
        rfc5280.id_at_serialNumber: Rfc2119Word.MUST,
        x520_name.id_at_businessCategory: Rfc2119Word.MUST,
        rfc5280.id_at_organizationName: Rfc2119Word.MUST,
        x520_name.id_at_organizationIdentifier: Rfc2119Word.MAY,
        x520_name.id_at_postalCode: Rfc2119Word.MAY,
        x520_name.id_at_streetAddress: Rfc2119Word.MAY,
        ev_guidelines.id_evat_jurisdiction_countryName: Rfc2119Word.MUST,
        ev_guidelines.id_evat_jurisdiction_stateOrProvinceName: Rfc2119Word.MAY,
        ev_guidelines.id_evat_jurisdiction_localityName: Rfc2119Word.MAY,
        rfc5280.id_at_commonName: Rfc2119Word.SHOULD_NOT,
    }

    def __init__(self):
        super().__init__(self._ATTRIBUTE_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.MUST_NOT)


class DvSubcriberAttributeAllowanceValidator(pkilint.common.AttributeIdentifierAllowanceValidator):
    """Validates that the content of the subject field conforms with BR 7.1.7.2."""

    _CODE_CLASSIFIER = 'cabf.serverauth.dv'

    _ATTRIBUTE_ALLOWANCES = {
        rfc5280.id_at_countryName: Rfc2119Word.MAY,
        rfc5280.id_at_commonName: Rfc2119Word.SHOULD_NOT,
    }

    def __init__(self):
        super().__init__(self._ATTRIBUTE_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.MUST_NOT)


class IvSubscriberAttributeAllowanceValidator(pkilint.common.AttributeIdentifierAllowanceValidator):
    """Validates that the content of the subject field conforms with BR 7.1.7.3."""

    _CODE_CLASSIFIER = 'cabf.serverauth.iv'

    _ATTRIBUTE_ALLOWANCES = {
        rfc5280.id_at_countryName: Rfc2119Word.MUST,
        rfc5280.id_at_stateOrProvinceName: Rfc2119Word.MAY,
        rfc5280.id_at_localityName: Rfc2119Word.MAY,
        x520_name.id_at_postalCode: Rfc2119Word.SHOULD_NOT,
        x520_name.id_at_streetAddress: Rfc2119Word.SHOULD_NOT,
        rfc5280.id_at_organizationName: Rfc2119Word.SHOULD_NOT,
        rfc5280.id_at_surname: Rfc2119Word.MUST,
        rfc5280.id_at_givenName: Rfc2119Word.MUST,
        rfc5280.id_at_organizationalUnitName: Rfc2119Word.MUST_NOT,
        rfc5280.id_at_commonName: Rfc2119Word.SHOULD_NOT,
    }

    def __init__(self):
        super().__init__(self._ATTRIBUTE_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT)


class OvSubscriberAttributeAllowanceValidator(pkilint.common.AttributeIdentifierAllowanceValidator):
    """Validates that the content of the subject field conforms with BR 7.1.7.4."""

    _CODE_CLASSIFIER = 'cabf.serverauth.ov'

    _ATTRIBUTE_ALLOWANCES = {
        rfc5280.id_domainComponent: Rfc2119Word.MAY,
        rfc5280.id_at_countryName: Rfc2119Word.MUST,
        rfc5280.id_at_stateOrProvinceName: Rfc2119Word.MAY,
        rfc5280.id_at_localityName: Rfc2119Word.MAY,
        x520_name.id_at_postalCode: Rfc2119Word.SHOULD_NOT,
        x520_name.id_at_streetAddress: Rfc2119Word.SHOULD_NOT,
        rfc5280.id_at_organizationName: Rfc2119Word.MUST,
        rfc5280.id_at_surname: Rfc2119Word.MUST_NOT,
        rfc5280.id_at_givenName: Rfc2119Word.MUST_NOT,
        rfc5280.id_at_organizationalUnitName: Rfc2119Word.MUST_NOT,
        rfc5280.id_at_commonName: Rfc2119Word.SHOULD_NOT,
    }

    def __init__(self):
        super().__init__(self._ATTRIBUTE_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT)


# EVG 9.2.6, BR 7.1.2.7.3, BR 7.1.2.7.4
class IdentityCertificateStateProvinceAndLocalityPresenceValidator(validation.Validator):
    """Validates that the stateOrProvinceName and/or localityName subject attributes are present, as per
    EVG 9.2.6, BR 7.1.2.7.3, and BR 7.1.2.7.4."""

    VALIDATION_STATEPROVINCE_AND_LOCALITY_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.subscriber_stateprovince_and_locality_missing'
    )

    def __init__(self):
        super().__init__(validations=self.VALIDATION_STATEPROVINCE_AND_LOCALITY_MISSING,
                         path='certificate.tbsCertificate.subject'
                         )

    def validate(self, node):
        stp_attr = node.document.get_subject_attributes_by_type(rfc5280.id_at_stateOrProvinceName)
        loc_attr = node.document.get_subject_attributes_by_type(rfc5280.id_at_localityName)

        if not any(stp_attr) and not any(loc_attr):
            raise validation.ValidationFindingEncountered(self.VALIDATION_STATEPROVINCE_AND_LOCALITY_MISSING)


class EvSubscriberJurisdictionPresenceValidator(validation.Validator):
    """Validates that jurisdictionStateOrProvinceName is present when jurisdictionLocalityName is present,
    as per EVG 9.2.4."""

    VALIDATION_JURIS_STP_ABSENT_LOCALITY_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.ev_guidelines.jurisdiction_locality_present_stateprovince_missing'
    )

    def __init__(self):
        super().__init__(validations=self.VALIDATION_JURIS_STP_ABSENT_LOCALITY_PRESENT,
                         path='certificate.tbsCertificate.subject')

    def validate(self, node):
        juris_stp_attr = node.document.get_subject_attributes_by_type(
            ev_guidelines.id_evat_jurisdiction_stateOrProvinceName)
        juris_loc_attr = node.document.get_subject_attributes_by_type(ev_guidelines.id_evat_jurisdiction_localityName)

        if any(juris_loc_attr) and not any(juris_stp_attr):
            raise validation.ValidationFindingEncountered(self.VALIDATION_JURIS_STP_ABSENT_LOCALITY_PRESENT)


class SubscriberExtensionAllowanceValidator(pkilint.common.ExtensionIdentifierAllowanceValidator):
    """Validates that the included extensions conform with BR 7.1.2.7.6."""

    _CODE_CLASSIFIER = 'cabf.serverauth.subscriber'

    _EXTENSION_ALLOWANCES = {
        rfc5280.id_pe_authorityInfoAccess: Rfc2119Word.MUST,
        rfc5280.id_ce_authorityKeyIdentifier: Rfc2119Word.MUST,
        rfc5280.id_ce_certificatePolicies: Rfc2119Word.MUST,
        rfc5280.id_ce_extKeyUsage: Rfc2119Word.MUST,
        rfc5280.id_ce_subjectAltName: Rfc2119Word.MUST,
        rfc5280.id_ce_nameConstraints: Rfc2119Word.MUST_NOT,
        rfc5280.id_ce_keyUsage: Rfc2119Word.SHOULD,
        rfc5280.id_ce_basicConstraints: Rfc2119Word.MAY,
        rfc5280.id_ce_cRLDistributionPoints: Rfc2119Word.MAY,
        rfc5280.id_ce_subjectKeyIdentifier: Rfc2119Word.SHOULD_NOT,
    }

    def __init__(self, certificate_type):
        allowances = self._EXTENSION_ALLOWANCES.copy()

        if certificate_type in serverauth_constants.SUBSCRIBER_PRECERT_TYPES:
            allowances.update({
                rfc6962.id_ce_criticalPoison: Rfc2119Word.MUST,
                rfc6962.id_ce_embeddedSCT: Rfc2119Word.MUST_NOT,
            })
        elif certificate_type in serverauth_constants.SUBSCRIBER_FINAL_CERTIFICATE_TYPES:
            allowances.update({
                rfc6962.id_ce_criticalPoison: Rfc2119Word.MUST_NOT,
                rfc6962.id_ce_embeddedSCT: Rfc2119Word.MAY,
            })
        else:
            raise ValueError(f'Unsupported certificate type: {certificate_type}')

        super().__init__(allowances, self._CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT)


class SubscriberEkuAllowanceValidator(pkilint.common.ExtendedKeyUsageAllowanceValidator):
    """Validates that the content of the extended key usage extension conforms with BR 7.1.2.7.10."""

    _CODE_CLASSIFIER = 'cabf.serverauth.subscriber'

    _EKU_ALLOWANCES = {
        rfc5280.id_kp_serverAuth: Rfc2119Word.MUST,
        rfc5280.id_kp_clientAuth: Rfc2119Word.MAY,
        rfc5280.id_kp_codeSigning: Rfc2119Word.MUST_NOT,
        rfc5280.id_kp_emailProtection: Rfc2119Word.MUST_NOT,
        rfc5280.id_kp_timeStamping: Rfc2119Word.MUST_NOT,
        rfc5280.id_kp_OCSPSigning: Rfc2119Word.MUST_NOT,
        rfc5280.anyExtendedKeyUsage: Rfc2119Word.MUST_NOT,
        rfc6962.id_kp_precertificateSigning: Rfc2119Word.MUST_NOT,
    }

    def __init__(self):
        super().__init__(self._EKU_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT)


class SubscriberKeyUsageValidator(validation.Validator):
    """Validates that the content of the key usage extension conforms with BR 7.1.2.7.11."""

    VALIDATION_REQUIRED_KU_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.subscriber_required_ku_missing'
    )

    VALIDATION_RECOMMENDED_KU_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'cabf.serverauth.subscriber_recommended_ku_missing'
    )

    VALIDATION_PROHIBITED_KU_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.subscriber_prohibited_ku_present'
    )

    VALIDATION_DISCOURAGED_KU_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'cabf.serverauth.subscriber_discouraged_ku_present'
    )

    VALIDATION_RSA_DIGSIG_AND_KEYENCIPHERMENT_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'cabf.serverauth.subscriber_rsa_digitalsignature_and_keyencipherment_present'
    )

    _SPKI_OID_TO_KU_ALLOWANCES_MAPPING = {
        rfc5480.rsaEncryption: {
            'digitalSignature': Rfc2119Word.SHOULD,
            'keyEncipherment': Rfc2119Word.MAY,
            'dataEncipherment': Rfc2119Word.SHOULD_NOT,
        },
        rfc5480.id_ecPublicKey: {
            'digitalSignature': Rfc2119Word.MUST,
            'keyAgreement': Rfc2119Word.SHOULD_NOT,
        },
    }

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_REQUIRED_KU_MISSING, self.VALIDATION_PROHIBITED_KU_PRESENT,
                                      self.VALIDATION_RECOMMENDED_KU_MISSING, self.VALIDATION_DISCOURAGED_KU_PRESENT,
                                      self.VALIDATION_RSA_DIGSIG_AND_KEYENCIPHERMENT_PRESENT],
                         pdu_class=rfc5280.KeyUsage)

    def validate(self, node):
        spki_alg_oid = node.navigate(':certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm').pdu

        allowances = self._SPKI_OID_TO_KU_ALLOWANCES_MAPPING.get(spki_alg_oid)

        if allowances is None:
            # unsupported SPKI, just return and let another validator throw the error
            return

        warning_findings = []

        for k in rfc5280.KeyUsage.namedValues:
            k = str(k)

            requirement_word = allowances.get(k)

            if bitstring.has_named_bit(node, k):
                if requirement_word is None:
                    raise validation.ValidationFindingEncountered(
                        self.VALIDATION_PROHIBITED_KU_PRESENT,
                        f'Prohibited KU present: {k}'
                    )
                elif requirement_word == Rfc2119Word.SHOULD_NOT:
                    warning_findings.append(validation.ValidationFindingDescription(
                        self.VALIDATION_DISCOURAGED_KU_PRESENT,
                        f'Discouraged KU present: {k}'
                    ))
            else:
                if requirement_word == Rfc2119Word.MUST:
                    raise validation.ValidationFindingEncountered(
                        self.VALIDATION_REQUIRED_KU_MISSING,
                        f'Required KU missing: {k}'
                    )
                elif requirement_word == Rfc2119Word.SHOULD:
                    warning_findings.append(validation.ValidationFindingDescription(
                        self.VALIDATION_RECOMMENDED_KU_MISSING,
                        f'Recommended KU missing: {k}'
                    ))

        if spki_alg_oid == rfc5480.rsaEncryption and (
                bitstring.has_named_bit(node, 'digitalSignature') and
                bitstring.has_named_bit(node, 'keyEncipherment')):
            warning_findings.append(
                validation.ValidationFindingDescription(self.VALIDATION_RSA_DIGSIG_AND_KEYENCIPHERMENT_PRESENT, None)
            )

        return validation.ValidationResult(self, node, warning_findings)


class SubscriberSanGeneralNameTypeValidator(validation.Validator):
    """Validates that the types of GeneralNames included in the SAN extension conform to BR 7.1.2.7.12."""

    VALIDATION_PROHIBITED_SAN_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.prohibited_san_type'
    )

    def __init__(self):
        super().__init__(validations=self.VALIDATION_PROHIBITED_SAN_TYPE, pdu_class=rfc5280.GeneralName,
                         predicate=lambda n: n.parent is not None and isinstance(n.parent.pdu, rfc5280.SubjectAltName))

    def validate(self, node):
        gn_type, _ = node.child

        if gn_type not in {'dNSName', 'iPAddress'}:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_SAN_TYPE,
                f'Prohibited SAN GeneralName type: {gn_type}'
            )


class EvSanGeneralNameTypeValidator(validation.Validator):
    """Validates that the types of GeneralNames included in the SAN extension conform to EVG 9.8.1."""

    VALIDATION_PROHIBITED_SAN_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.ev_guidelines.prohibited_san_type'
    )

    def __init__(self):
        super().__init__(validations=self.VALIDATION_PROHIBITED_SAN_TYPE, pdu_class=rfc5280.GeneralName,
                         predicate=lambda n: n.parent is not None and isinstance(n.parent.pdu, rfc5280.SubjectAltName))

    def validate(self, node):
        gn_type, _ = node.child

        if gn_type != 'dNSName':
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_SAN_TYPE,
                f'Prohibited SAN GeneralName type: {gn_type}'
            )


class SubscriberValidityPeriodValidator(time.ValidityPeriodThresholdsValidator):
    """Validates that the validity period conforms to BR 7.1.2.7."""

    _THRESHOLDS = [
        (
            operator.le,
            timedelta(days=398),
            validation.ValidationFinding(
                validation.ValidationFindingSeverity.ERROR,
                'cabf.certificate_validity_period_exceeds_398_days'
            )
        ),
        (
            operator.le,
            timedelta(days=397),
            validation.ValidationFinding(
                validation.ValidationFindingSeverity.WARNING,
                'cabf.certificate_validity_period_exceeds_397_days'
            )
        )
    ]

    def __init__(self):
        super().__init__(end_validity_node_retriever=lambda n: n.navigate('^.notAfter'),
                         inclusive_second=True,
                         validity_period_thresholds=self._THRESHOLDS,
                         path='certificate.tbsCertificate.validity.notBefore'
                         )


class SubscriberCommonNameValidator(validation.Validator):
    """Validates that the content of the commonName attribute conforms to BR 7.1.4.3."""

    VALIDATION_COMMON_NAME_UNKNOWN_SOURCE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.subscriber_common_name_unknown_source'
    )

    VALIDATION_UNPARSED_CN_ENCOUNTERED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'cabf.serverauth.unparsed_common_name_encountered'
    )

    VALIDATION_UNPARSED_SAN_EXTENSION_ENCOUNTERED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'cabf.serverauth.unparsed_san_extension_encountered'
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_COMMON_NAME_UNKNOWN_SOURCE, self.VALIDATION_UNPARSED_CN_ENCOUNTERED,
                         self.VALIDATION_UNPARSED_SAN_EXTENSION_ENCOUNTERED],
            pdu_class=rfc5280.X520CommonName)

    def validate(self, node):
        # unparsed CN, return
        if not any(node.children):
            raise validation.ValidationFindingEncountered(self.VALIDATION_UNPARSED_CN_ENCOUNTERED)

        _, value_node = node.child
        value_str = str(value_node.pdu)

        san_ext_and_idx = node.document.get_extension_by_oid(rfc5280.id_ce_subjectAltName)

        if san_ext_and_idx is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_COMMON_NAME_UNKNOWN_SOURCE,
                f'Unknown source for value of common name: "{value_str}"'
            )

        san_ext_node, _ = san_ext_and_idx

        try:
            san_value_node = san_ext_node.navigate('extnValue.subjectAltName')
        except document.PDUNavigationFailedError:
            # unparsed SAN extension, return
            raise validation.ValidationFindingEncountered(self.VALIDATION_UNPARSED_SAN_EXTENSION_ENCOUNTERED)

        for gn in san_value_node.children.values():
            gn_type, gn_value = gn.child

            if gn_type == 'dNSName' and str(gn_value.pdu) == value_str:
                return
            elif gn_type == 'iPAddress':
                address_octets = gn_value.pdu.asOctets()

                if len(address_octets) == 4:
                    ip_addr = ipaddress.IPv4Address(address_octets)
                elif len(address_octets) == 16:
                    ip_addr = ipaddress.IPv6Address(address_octets)
                else:
                    # whoa Nellie! let the PKIX validator complain about this one
                    continue

                if str(ip_addr) == value_str:
                    return

        raise validation.ValidationFindingEncountered(
            self.VALIDATION_COMMON_NAME_UNKNOWN_SOURCE,
            f'Unknown source for value of common name: "{value_str}"'
        )


class SubscriberExtensionCriticalityValidator(pkilint.common.ExtensionCriticalityValidator):
    """Validates that the criticality of extensions conforms to BR 7.1.2.7.6."""

    _CODE_CLASSIFIER = 'cabf.serverauth.subscriber'

    _CRITICALITY_MAPPING = {
        rfc5280.id_pe_authorityInfoAccess: False,
        rfc5280.id_ce_authorityKeyIdentifier: False,
        rfc5280.id_ce_certificatePolicies: False,
        rfc5280.id_ce_extKeyUsage: False,
        rfc5280.id_ce_keyUsage: True,
        rfc5280.id_ce_basicConstraints: True,
        rfc5280.id_ce_cRLDistributionPoints: False,
        rfc6962.id_ce_embeddedSCT: False,
        rfc5280.id_ce_subjectKeyIdentifier: False,
    }

    def __init__(self):
        super().__init__(self._CRITICALITY_MAPPING, self._CODE_CLASSIFIER, Rfc2119Word.MUST, Rfc2119Word.MUST)


class SubscriberBasicConstraintsValidator(validation.Validator):
    VALIDATION_CA_BIT_SET = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.subscriber_basic_constraints_ca_bit_set'
    )

    def __init__(self):
        super().__init__(validations=self.VALIDATION_CA_BIT_SET, pdu_class=rfc5280.BasicConstraints)

    def validate(self, node):
        if bool(node.children['cA'].pdu):
            raise validation.ValidationFindingEncountered(self.VALIDATION_CA_BIT_SET)


class SubscriberPoliciesValidator(validation.Validator):
    """Validates that the certificate policy OID(s) conform to BR 7.1.2.7.9."""
    VALIDATION_ANYPOLICY_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.subscriber_anypolicy_oid_present'
    )

    VALIDATION_MULTIPLE_RESERVED_OIDS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.ca_multiple_reserved_policy_oids'
    )

    VALIDATION_NO_RESERVED_OID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.subscriber_missing_reserved_policy_oid'
    )

    VALIDATION_FIRST_OID_NOT_RESERVED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        'cabf.serverauth.subscriber_first_policy_oid_not_reserved'
    )

    def __init__(self, certificate_type: serverauth_constants.CertificateType):
        if certificate_type not in serverauth_constants.SUBSCRIBER_CERTIFICATE_TYPES:
            raise ValueError(f'Unsupported certificate type: {certificate_type}')

        self._certificate_type = certificate_type

        if certificate_type in serverauth_constants.EV_CERTIFICATE_TYPES:
            self._expected_reserved_oid = serverauth_constants.ID_POLICY_EV
        elif certificate_type in serverauth_constants.OV_CERTIFICATE_TYPES:
            self._expected_reserved_oid = serverauth_constants.ID_POLICY_OV
        elif certificate_type in serverauth_constants.IV_CERTIFICATE_TYPES:
            self._expected_reserved_oid = serverauth_constants.ID_POLICY_IV
        elif certificate_type in serverauth_constants.DV_CERTIFICATE_TYPES:
            self._expected_reserved_oid = serverauth_constants.ID_POLICY_DV
        else:
            raise ValueError(f'Unsupported certificate type: {certificate_type}')

        super().__init__(validations=[self.VALIDATION_ANYPOLICY_PRESENT,
                                      self.VALIDATION_MULTIPLE_RESERVED_OIDS,
                                      self.VALIDATION_NO_RESERVED_OID,
                                      self.VALIDATION_FIRST_OID_NOT_RESERVED],
                         pdu_class=rfc5280.CertificatePolicies)

    def validate(self, node):
        policy_oids = [pi.children['policyIdentifier'].pdu for pi in node.children.values()]

        if rfc5280.anyPolicy in policy_oids:
            raise validation.ValidationFindingEncountered(self.VALIDATION_ANYPOLICY_PRESENT)

        if self._expected_reserved_oid not in policy_oids:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NO_RESERVED_OID,
                f'Required policy OID "{str(self._expected_reserved_oid)}" missing')

        reserved_oids = set(policy_oids) & serverauth_constants.SERVERAUTH_RESERVED_POLICY_OIDS

        if len(reserved_oids) > 1:
            oids_str = oid.format_oids(reserved_oids)

            raise validation.ValidationFindingEncountered(self.VALIDATION_MULTIPLE_RESERVED_OIDS,
                                                          f'Multiple reserved policy OIDs present: {oids_str}')

        if policy_oids[0] not in serverauth_constants.SERVERAUTH_RESERVED_POLICY_OIDS:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_FIRST_OID_NOT_RESERVED
            )


class EvWildcardAllowanceValidator(validation.Validator):
    """Validates that wildcard dNSNames conform to EVG 9.8.1."""

    VALIDATION_EV_WILDCARD_SAN_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.ev_guidelines.ev_wildcard_san_present'
    )

    def __init__(self):
        super().__init__(validations=self.VALIDATION_EV_WILDCARD_SAN_PRESENT,
                         predicate=general_name.create_generalname_type_predicate('dNSName'))

    def validate(self, node):
        value = str(node.pdu)

        if value.startswith('*') and not value.lower().endswith('.onion'):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_EV_WILDCARD_SAN_PRESENT,
                f'Wildcard SAN present: "{value}"'
            )


class SubscriberAuthorityInformationAccessAccessMethodPresenceValidator(
        common.AuthorityInformationAccessAccessMethodPresenceValidator):
    """Validates that AIA access methods conform to BR 7.1.2.10.3."""

    _CODE_CLASSIFIER = 'cabf.serverauth.subscriber'

    _ACCESS_METHOD_ALLOWANCES = {
        rfc5280.id_ad_ocsp: Rfc2119Word.MUST,
        rfc5280.id_ad_caIssuers: Rfc2119Word.SHOULD,
    }

    def __init__(self):
        super().__init__(self._ACCESS_METHOD_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.MUST_NOT)


class OrganizationIdentifierConsistentSubjectAndExtensionValidator(validation.Validator):
    """Validates that the content of the organizationIdentifier subject attributes and the organizationIdentifier
    extension are consistent, as per EVG 9.2.8 and 9.2.9."""

    VALIDATION_CABF_ORG_ID_NO_EXT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.organization_identifier_extension_absent'
    )

    VALIDATION_CABF_ORG_ID_MISMATCHED_VALUE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'cabf.serverauth.organization_identifier_mismatched_value'
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_CABF_ORG_ID_NO_EXT,
                cabf_name.CabfOrganizationIdentifierAttributeValidator.VALIDATION_ORGANIZATION_ID_INVALID_FORMAT,
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_VALUE,
            ],
            pdu_class=x520_name.X520OrganizationIdentifier,
            predicate=lambda n: any(n.children)
        )

    def validate(self, node):
        ext_and_idx = node.document.get_extension_by_oid(
            ev_guidelines.id_CABFOrganizationIdentifier
        )

        if ext_and_idx is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CABF_ORG_ID_NO_EXT
            )

        ext_node, _ = ext_and_idx
        try:
            ext_node = ext_node.navigate('extnValue.cABFOrganizationIdentifier')
        except document.PDUNavigationFailedError:
            return

        attr_value = str(node.child[1].pdu)

        try:
            org_id_attr_parsed = organization_id.parse_organization_identifier(attr_value)
        except ValueError as e:
            raise validation.ValidationFindingEncountered(
                cabf_name.CabfOrganizationIdentifierAttributeValidator.VALIDATION_ORGANIZATION_ID_INVALID_FORMAT,
                str(e)
            )

        org_id_ext_parsed = _parse_organization_identifier_extension(ext_node)

        try:
            organization_id.assert_parsed_organization_identifier_equal(
                org_id_attr_parsed, 'attribute', org_id_ext_parsed, 'extension'
            )
        except ValueError as e:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CABF_ORG_ID_MISMATCHED_VALUE,
                str(e)
            )


