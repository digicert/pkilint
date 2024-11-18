from pyasn1_alt_modules import rfc5280, rfc6962

import pkilint.common
from pkilint import validation, oid, common, document
from pkilint.cabf.serverauth import serverauth_constants
from pkilint.itu import x520_name
from pkilint.pkix import Rfc2119Word


class CaCertificatePoliciesValidator(validation.Validator):
    """Validates that the content of the certificate policies extension complies with BR  7.1.2.10.5."""

    VALIDATION_ANYPOLICY_EXTERNAL_CA = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.ca_external_anypolicy",
    )

    VALIDATION_MULTIPLE_RESERVED_OIDS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.ca_multiple_reserved_policy_oids",
    )

    VALIDATION_NO_RESERVED_OID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.ca_missing_reserved_policy_oid",
    )

    VALIDATION_NON_TLS_CA_HAS_SERVERAUTH_OID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.ca_non_tls_has_reserved_policy_oid",
    )

    VALIDATION_ANYPOLICY_WITH_OTHER_OID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.ca_anypolicy_with_other_policy_oid",
    )

    VALIDATION_FIRST_OID_NOT_RESERVED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.serverauth.ca_first_policy_oid_not_reserved",
    )

    def __init__(self, certificate_type: serverauth_constants.CertificateType):
        self._certificate_type = certificate_type

        super().__init__(
            validations=[
                self.VALIDATION_ANYPOLICY_EXTERNAL_CA,
                self.VALIDATION_MULTIPLE_RESERVED_OIDS,
                self.VALIDATION_NO_RESERVED_OID,
                self.VALIDATION_NON_TLS_CA_HAS_SERVERAUTH_OID,
                self.VALIDATION_ANYPOLICY_WITH_OTHER_OID,
                self.VALIDATION_FIRST_OID_NOT_RESERVED,
            ],
            pdu_class=rfc5280.CertificatePolicies,
        )

    def validate(self, node):
        policy_oids = [
            pi.children["policyIdentifier"].pdu for pi in node.children.values()
        ]

        has_any_policy = rfc5280.anyPolicy in policy_oids

        if has_any_policy:
            if self._certificate_type in serverauth_constants.EXTERNAL_CA_TYPES:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_ANYPOLICY_EXTERNAL_CA
                )

            if len(policy_oids) > 1:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_ANYPOLICY_WITH_OTHER_OID
                )
        else:
            reserved_oids = (
                set(policy_oids) & serverauth_constants.SERVERAUTH_RESERVED_POLICY_OIDS
            )

            if (
                self._certificate_type
                == serverauth_constants.CertificateType.NON_TLS_CA
            ):
                if any(reserved_oids):
                    oids = oid.format_oids(reserved_oids)

                    raise validation.ValidationFindingEncountered(
                        self.VALIDATION_NON_TLS_CA_HAS_SERVERAUTH_OID,
                        f"Non-TLS CA has reserved policy OID(s): {oids}",
                    )
            else:
                if not any(reserved_oids):
                    raise validation.ValidationFindingEncountered(
                        self.VALIDATION_NO_RESERVED_OID
                    )

            if (
                len(reserved_oids) > 1
                and self._certificate_type
                not in serverauth_constants.ROOT_KEY_CROSS_CA_TYPES
            ):
                oids_str = oid.format_oids(reserved_oids)

                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_MULTIPLE_RESERVED_OIDS,
                    f"Multiple reserved policy OIDs present: {oids_str}",
                )

            if (
                self._certificate_type
                != serverauth_constants.CertificateType.NON_TLS_CA
                and policy_oids[0]
                not in serverauth_constants.SERVERAUTH_RESERVED_POLICY_OIDS
            ):
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_FIRST_OID_NOT_RESERVED
                )


class TlsCaCertificateAllowedEkuValidator(common.ExtendedKeyUsageAllowanceValidator):
    """Validates that the content of the extended key usage extension complies with BR  7.1.2.10.6."""

    _CODE_CLASSIFIER = "cabf.serverauth.ca"

    _EKU_ALLOWANCES = {
        **{
            e: Rfc2119Word.MUST_NOT
            for e in (
                rfc5280.id_kp_codeSigning,
                rfc5280.id_kp_emailProtection,
                rfc5280.id_kp_OCSPSigning,
                rfc5280.anyExtendedKeyUsage,
                rfc6962.id_kp_precertificateSigning,
            )
        },
        rfc5280.id_kp_serverAuth: Rfc2119Word.MUST,
        rfc5280.id_kp_clientAuth: Rfc2119Word.MAY,
    }

    def __init__(self):
        super().__init__(
            self._EKU_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT
        )


# BR 7.1.2.4.2
class PrecertSigningCaCertificateAllowedEkuValidator(
    common.ExtendedKeyUsageAllowanceValidator
):
    """Validates that the content of the extended key usage extension complies with BR  7.1.2.4.2."""

    _CODE_CLASSIFIER = "cabf.serverauth.ca_precert_signing"

    _EKU_ALLOWANCES = {
        rfc6962.id_kp_precertificateSigning: Rfc2119Word.MUST,
    }

    def __init__(self):
        super().__init__(
            self._EKU_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.MUST_NOT
        )


# BR 7.1.2.3.3
class NonTlsCaCertificateAllowedEkuValidator(common.ExtendedKeyUsageAllowanceValidator):
    _CODE_CLASSIFIER = "cabf.serverauth.non_tls_ca"

    _EKU_ALLOWANCES = {
        e: Rfc2119Word.MUST_NOT
        for e in (
            rfc5280.id_kp_serverAuth,
            rfc5280.id_kp_OCSPSigning,
            rfc5280.anyExtendedKeyUsage,
            rfc6962.id_kp_precertificateSigning,
        )
    }

    def __init__(self):
        super().__init__(self._EKU_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.MAY)


class CaRequiredSubjectAttributesValidator(
    pkilint.common.AttributeIdentifierAllowanceValidator
):
    """Validates that the subject contains attributes in accordance with BR 7.1.2.10.2."""

    _CODE_CLASSIFIER = "cabf.serverauth.ca"

    _ATTRIBUTE_ALLOWANCES = {
        rfc5280.id_at_countryName: Rfc2119Word.MUST,
        rfc5280.id_at_stateOrProvinceName: Rfc2119Word.MAY,
        rfc5280.id_at_localityName: Rfc2119Word.MAY,
        x520_name.id_at_postalCode: Rfc2119Word.MAY,
        x520_name.id_at_streetAddress: Rfc2119Word.MAY,
        rfc5280.id_at_organizationName: Rfc2119Word.MUST,
        rfc5280.id_at_commonName: Rfc2119Word.MUST,
    }

    def __init__(self, certificate_type: serverauth_constants.CertificateType):
        self._attribute_allowances = self._ATTRIBUTE_ALLOWANCES.copy()

        if certificate_type in (
            serverauth_constants.TLS_CA_TYPES
            | {serverauth_constants.CertificateType.ROOT_CA}
        ):
            ou_allowance_word = Rfc2119Word.MUST_NOT
        else:
            ou_allowance_word = Rfc2119Word.SHOULD_NOT

        self._attribute_allowances[rfc5280.id_at_organizationalUnitName] = (
            ou_allowance_word
        )

        super().__init__(
            self._attribute_allowances, self._CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT
        )


class NameConstraintsBaseTypeValidator(validation.Validator):
    """Validates that each subtree of a name constraints extension conforms with BR 7.1.2.10.8."""

    VALIDATION_DISCOURAGED_BASE_NAME_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.serverauth.name_constraints_discouraged_name_type",
    )

    VALIDATION_DIRNAME_IN_EXCLUDED_SUBTREES = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.serverauth.name_constraints_dirname_in_excluded_subtrees",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_DISCOURAGED_BASE_NAME_TYPE,
                self.VALIDATION_DIRNAME_IN_EXCLUDED_SUBTREES,
            ],
            pdu_class=rfc5280.GeneralSubtree,
        )

    def validate(self, node):
        gn_type, gn_value = node.children["base"].child

        if gn_type not in {"dNSName", "iPAddress", "directoryName"}:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_DISCOURAGED_BASE_NAME_TYPE,
                f"Discouraged GeneralSubtree base type: {gn_type}",
            )

        if node.parent.name == "excludedSubtrees" and gn_type == "directoryName":
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_DIRNAME_IN_EXCLUDED_SUBTREES
            )


# all extension criticalities are aligned for the CA profiles; BR 7.1.2.5.1 has the most comprehensive specification
class CaCertificateExtensionCriticalityValidator(common.ExtensionCriticalityValidator):
    """Validates that the criticality of all extensions conforms with BR 7.1.2.5.1."""

    _CODE_CLASSIFIER = "cabf.serverauth.ca"

    _CRITICALITY_MAPPING = {
        rfc5280.id_ce_authorityKeyIdentifier: False,
        rfc5280.id_ce_basicConstraints: True,
        rfc5280.id_ce_certificatePolicies: False,
        rfc5280.id_ce_cRLDistributionPoints: False,
        rfc5280.id_ce_keyUsage: True,
        rfc5280.id_ce_subjectKeyIdentifier: False,
        rfc5280.id_ce_extKeyUsage: False,
        rfc5280.id_pe_authorityInfoAccess: False,
        rfc6962.id_ce_embeddedSCT: False,
    }

    def __init__(self):
        super().__init__(
            self._CRITICALITY_MAPPING,
            self._CODE_CLASSIFIER,
            Rfc2119Word.MUST,
            Rfc2119Word.MUST,
        )


class CaCertificateExtensionAllowanceValidator(
    common.ExtensionIdentifierAllowanceValidator
):
    """Validates that the included extensions conform with BR 7.1.2.4.1, 7.1.2.5.1, or 7.1.2.6.1 (depending on
    certificate type)"""

    _CODE_CLASSIFIER = "cabf.serverauth.ca"

    _EXTENSION_ALLOWANCES = {
        rfc5280.id_ce_authorityKeyIdentifier: Rfc2119Word.MUST,
        rfc5280.id_ce_basicConstraints: Rfc2119Word.MUST,
        rfc5280.id_ce_certificatePolicies: Rfc2119Word.MUST,
        rfc5280.id_ce_cRLDistributionPoints: Rfc2119Word.MUST,
        rfc5280.id_ce_keyUsage: Rfc2119Word.MUST,
        rfc5280.id_ce_subjectKeyIdentifier: Rfc2119Word.MUST,
        rfc5280.id_ce_extKeyUsage: Rfc2119Word.MUST,
        rfc5280.id_pe_authorityInfoAccess: Rfc2119Word.SHOULD,
    }

    def __init__(self, certificate_type):
        extension_allowances = self._EXTENSION_ALLOWANCES.copy()

        if certificate_type in serverauth_constants.CONSTRAINED_TLS_CA_TYPES:
            extension_allowances[rfc5280.id_ce_nameConstraints] = Rfc2119Word.MUST
        else:
            extension_allowances[rfc5280.id_ce_nameConstraints] = Rfc2119Word.MAY

        if certificate_type != serverauth_constants.CertificateType.PRECERT_SIGNING_CA:
            extension_allowances[rfc6962.id_ce_embeddedSCT] = Rfc2119Word.MAY

        super().__init__(
            extension_allowances, self._CODE_CLASSIFIER, Rfc2119Word.SHOULD_NOT
        )


class CaCertificateAuthorityInformationAccessAccessMethodPresenceValidator(
    common.AuthorityInformationAccessAccessMethodPresenceValidator
):
    """Validates that the content of the authority information access extension conforms to BR 7.1.2.10.3."""

    _CODE_CLASSIFIER = "cabf.serverauth.ca"

    _ACCESS_METHOD_ALLOWANCES = {
        rfc5280.id_ad_ocsp: Rfc2119Word.MAY,
        rfc5280.id_ad_caIssuers: Rfc2119Word.MAY,
    }

    def __init__(self):
        super().__init__(
            self._ACCESS_METHOD_ALLOWANCES, self._CODE_CLASSIFIER, Rfc2119Word.MUST_NOT
        )


# BR 7.1.2.5.2
class TlsCaTechnicallyConstrainedValidator(validation.Validator):
    """Validates that the CA is technically constrained in accordance with BR 7.1.2.5.2."""

    VALIDATION_INCOMPLETE_NAME_CONSTRAINTS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.serverauth.ca.incomplete_name_constraints",
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_INCOMPLETE_NAME_CONSTRAINTS,
            pdu_class=rfc5280.NameConstraints,
        )

    def validate(self, node):
        try:
            permitted_subtrees = node.navigate("permittedSubtrees")
        except document.PDUNavigationFailedError:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INCOMPLETE_NAME_CONSTRAINTS,
                '"permittedSubtrees" is absent',
            )

        has_dirname_constraint = False
        has_dnsname_constraint = False
        has_ipv4_constraint = False
        has_ipv6_constraint = False

        for subtree in permitted_subtrees.children.values():
            gn_type, gn_value = subtree.children["base"].child

            if gn_type == "directoryName":
                has_dirname_constraint = True
            elif gn_type == "dNSName":
                has_dnsname_constraint = True
            elif gn_type == "iPAddress":
                ip_network_octet_len = len(gn_value.pdu.asOctets())

                if ip_network_octet_len == 8:
                    has_ipv4_constraint = True
                else:
                    has_ipv6_constraint = True

        if not has_dirname_constraint:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INCOMPLETE_NAME_CONSTRAINTS,
                '"permittedSubtrees" does not contain a directoryName',
            )

        if (
            has_dirname_constraint
            and has_dnsname_constraint
            and has_ipv4_constraint
            and has_ipv6_constraint
        ):
            return

        try:
            excluded_subtrees = node.navigate("excludedSubtrees")
        except document.PDUNavigationFailedError:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INCOMPLETE_NAME_CONSTRAINTS,
                '"excludedSubtrees" absent with incomplete constraints in "permittedSubtrees"',
            )

        for subtree in excluded_subtrees.children.values():
            gn_type, gn_value = subtree.children["base"].child

            if gn_type == "dNSName" and len(str(gn_value.pdu)) == 0:
                has_dnsname_constraint = True
            elif gn_type == "iPAddress":
                ip_network_octets = gn_value.pdu.asOctets()

                if all((o == 0 for o in ip_network_octets)):
                    ip_network_octet_len = len(ip_network_octets)

                    if ip_network_octet_len == 8:
                        has_ipv4_constraint = True
                    else:
                        has_ipv6_constraint = True

        if (
            has_dirname_constraint
            and has_dnsname_constraint
            and has_ipv4_constraint
            and has_ipv6_constraint
        ):
            return
        else:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INCOMPLETE_NAME_CONSTRAINTS
            )
