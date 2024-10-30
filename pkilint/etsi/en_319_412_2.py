import typing

from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc3739

import pkilint.etsi.asn1.en_319_411_2
from pkilint import validation, oid, document, common
from pkilint.etsi import asn1 as etsi_asn1, etsi_shared
from pkilint.etsi import etsi_constants
from pkilint.etsi.asn1 import en_319_411_2
from pkilint.pkix import extension, name, Rfc2119Word
from pkilint.pkix.general_name import GeneralNameTypeName


class CertificatePoliciesCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_CERTIFICATE_POLICIES_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "etsi.en_319_412_2.gen-4.3.3-1.critical_certificate_policies_extension",
    )

    def __init__(self):
        super().__init__(
            validation=self.VALIDATION_CERTIFICATE_POLICIES_CRITICAL,
            type_oid=rfc5280.id_ce_certificatePolicies,
            is_critical=False,
        )


class SubjectAlternativeNameCriticalityValidator(
    extension.ExtensionCriticalityValidator
):
    VALIDATION_SAN_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.gen-4.3.5-1.san_extension_is_critical",
    )

    def __init__(self):
        super().__init__(
            validation=self.VALIDATION_SAN_CRITICAL,
            type_oid=rfc5280.id_ce_subjectAltName,
            is_critical=False,
        )


class IssuerAlternativeNameCriticalityValidator(
    extension.ExtensionCriticalityValidator
):
    VALIDATION_ISSUER_ALTERNATIVE_NAME_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.gen-4.3.6-1.ian_extension_is_critical",
    )

    def __init__(self):
        super().__init__(
            validation=self.VALIDATION_ISSUER_ALTERNATIVE_NAME_CRITICAL,
            type_oid=rfc5280.id_ce_issuerAltName,
            is_critical=False,
        )


class ExtendedKeyUsageCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_EXTENDED_KEY_USAGE_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.gen-4.3.10-1.eku_extension_is_critical",
    )

    def __init__(self):
        super().__init__(
            validation=self.VALIDATION_EXTENDED_KEY_USAGE_CRITICAL,
            type_oid=rfc5280.id_ce_extKeyUsage,
            is_critical=False,
        )


class CRLDistributionPointsCriticalityValidator(
    extension.ExtensionCriticalityValidator
):
    CRL_DISTRIBUTION_POINTS_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.gen-4.3.11-5.crl_extension_is_critical",
    )

    def __init__(self):
        super().__init__(
            validation=self.CRL_DISTRIBUTION_POINTS_CRITICAL,
            type_oid=rfc5280.id_ce_cRLDistributionPoints,
            is_critical=False,
        )


class NaturalPersonSubjectAttributeAllowanceValidator(validation.Validator):
    """
    NAT-4.2.4-1: The subject field shall include the following attributes as specified in Recommendation ITU-T X.520:
    • countryName;
    • choice of (givenName and/or surname) or pseudonym; and
    • commonName.
    """

    VALIDATION_NATURAL_PERSON_NAME_ATTRIBUTE_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.nat-4.2.4-1.required_attribute_missing",
    )

    """
    NAT-4.2.4-4 The pseudonym attribute shall not be present if the givenName
    and surname attribute are present.
    """
    VALIDATION_MIXED_PSEUDONYM_AND_NAME_ATTRIBUTES_PRESENT = (
        validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            "etsi.en_319_412_2.nat-4.2.4-4.mixed_pseudonym_and_name_attributes_present",
        )
    )

    """
    NAT 4.2.4-3 The subject field shall not contain more than one instance of commonName and countryName
    """
    VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.nat-4.2.4-3.prohibited_duplicate_attribute_present",
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
                self.VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT,
            ],
            pdu_class=rfc5280.Name,
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
                f"Required attributes missing: {oid_str}",
            )

        if all((a in attrs_present for a in self._PSEUDONYM_AND_NAME_ATTRIBUTES)):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_MIXED_PSEUDONYM_AND_NAME_ATTRIBUTES_PRESENT
            )

        for a in self._PROHIBITED_DUPLICATE_ATTRIBUTES:
            if attr_counts[a] > 1:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_PROHIBITED_DUPLICATE_ATTRIBUTE_PRESENT,
                    f"Prohibited duplicate attribute present: {a}",
                )


class NaturalPersonExtensionIdentifierAllowanceValidator(
    common.ExtensionIdentifierAllowanceValidator
):
    _CODE_CLASSIFIER = "etsi.en_319_412_2"

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


def _general_name_has_uri_prefixes(uri_prefixes_lower, general_name_node):
    gn_type, gn_value = general_name_node.child

    if gn_type == GeneralNameTypeName.UNIFORM_RESOURCE_IDENTIFIER:
        uri_lower = str(gn_value.pdu).lower()

        return any(uri_lower.startswith(p) for p in uri_prefixes_lower)

    return False


_HTTP_OR_HTTPS_PREFIXES = {"http://", "https://"}
_HTTP_OR_LDAP_PREFIXES = {"http://", "ldap://"}


def _aia_extension_has_aia_ocsp_http_uri(aia_syntax_node):
    for ad in aia_syntax_node.children.values():
        if ad.children["accessMethod"].pdu == rfc5280.id_ad_ocsp:

            location_node = ad.children["accessLocation"]

            if _general_name_has_uri_prefixes(_HTTP_OR_HTTPS_PREFIXES, location_node):
                return True

    return False


class CrlDistributionPointsExtensionPresenceValidator(validation.Validator):
    """
    GEN-4.3.11-2: If the certificate does not include any access location of an OCSP responder as specified in clause
    4.4.1, then the certificate shall include a CRL distribution point extension.
    """

    VALIDATION_CRLDP_EXTENSION_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.gen-4.3.11-2.crldp_extension_missing",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_CRLDP_EXTENSION_MISSING],
            pdu_class=rfc5280.Extensions,
        )

    def validate(self, node):
        crldp_ext_and_idx = node.document.get_extension_by_oid(
            rfc5280.id_ce_cRLDistributionPoints
        )

        if crldp_ext_and_idx:
            return

        aia_ext_and_idx = node.document.get_extension_by_oid(
            rfc5280.id_pe_authorityInfoAccess
        )

        if aia_ext_and_idx is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CRLDP_EXTENSION_MISSING
            )

        ext, idx = aia_ext_and_idx

        try:
            _, aia_syntax_node = ext.children["extnValue"].child
        except ValueError:
            # no decoded AIA extension. Let other validator flag that finding
            return

        if not _aia_extension_has_aia_ocsp_http_uri(aia_syntax_node):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CRLDP_EXTENSION_MISSING
            )


class CrlDistributionPointsValidator(validation.Validator):
    """
    GEN-4.3.11-4: At least one of the present references shall use either http (http://) IETF RFC 7230-7235 [3] or ldap
    (ldap://) IETF RFC 4516 [4] scheme.
    """

    VALIDATION_CRLDP_DP_NO_REQUIRED_URI = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.gen-4.3.11-4.http_or_ldap_crldp_distribution_point_uri_missing",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_CRLDP_DP_NO_REQUIRED_URI],
            pdu_class=rfc5280.CRLDistributionPoints,
        )

    def validate(self, node):
        for distribution_point in node.children.values():
            try:
                full_name_node = distribution_point.navigate(
                    "distributionPoint.fullName"
                )
            except document.PDUNavigationFailedError:
                continue

            if any(
                _general_name_has_uri_prefixes(_HTTP_OR_LDAP_PREFIXES, gn)
                for gn in full_name_node.children.values()
            ):
                return

        raise validation.ValidationFindingEncountered(
            self.VALIDATION_CRLDP_DP_NO_REQUIRED_URI
        )


class AuthorityInformationAccessValidator(validation.Validator):
    """
    GEN-4.4.1-3: The Authority Information Access extension shall include an accessMethod OID,
    id-ad-caIssuers, with an accessLocation value specifying at least one access location of a valid CA
    certificate of the issuing CA.
    """

    VALIDATION_AIA_CA_ISSUERS_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.gen-4.4.1-3.ca_issuers_aia_access_method_absent",
    )

    """
    GEN-4.4.1-4: At least one accessLocation shall use the http (http://) IETF RFC 7230-7235 [3] scheme or https
    (https://) IETF RFC 2818 [5] scheme.
    """
    VALIDATION_AIA_CA_ISSUERS_HTTP_URI_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.gen-4.4.1-4.ca_issuers_aia_access_method_http_uri_missing",
    )

    """
    GEN-4.4.1-6: If OCSP is supported by the issuing CA, at least one access location shall specify either the http
    (http://) IETF RFC 7230-7235 [3] or https (https://) IETF RFC 2818 [5] scheme.
    """
    VALIDATION_AIA_OCSP_HTTP_URI_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.gen-4.4.1-6.ocsp_aia_access_method_http_uri_missing",
    )

    """
    GEN-4.4.1-8: If the certificate does not include any CRL distribution point extension in accordance with clause
    4.3.11, a reference to at least one OCSP responder shall be present.
    """
    VALIDATION_AIA_OCSP_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.gen-4.4.1-8.ocsp_aia_access_method_absent",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_AIA_CA_ISSUERS_MISSING,
                self.VALIDATION_AIA_CA_ISSUERS_HTTP_URI_MISSING,
                self.VALIDATION_AIA_OCSP_MISSING,
                self.VALIDATION_AIA_OCSP_HTTP_URI_MISSING,
            ],
            pdu_class=rfc5280.AuthorityInfoAccessSyntax,
        )

    @classmethod
    def _get_locations_for_method(cls, method_oid, aia_syntax_node):
        return [
            ad.children["accessLocation"]
            for ad in aia_syntax_node.children.values()
            if ad.children["accessMethod"].pdu == method_oid
        ]

    def validate(self, node):
        ca_issuers_gns = self._get_locations_for_method(rfc5280.id_ad_caIssuers, node)

        if not ca_issuers_gns:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_AIA_CA_ISSUERS_MISSING
            )

        if not any(
            _general_name_has_uri_prefixes(_HTTP_OR_HTTPS_PREFIXES, gn)
            for gn in ca_issuers_gns
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_AIA_CA_ISSUERS_HTTP_URI_MISSING
            )

        # only check for OCSP if no CRL DP extension is absent
        if (
            node.document.get_extension_by_oid(rfc5280.id_ce_cRLDistributionPoints)
            is None
        ):
            ocsp_gns = self._get_locations_for_method(rfc5280.id_ad_ocsp, node)

            if not ocsp_gns:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_AIA_OCSP_MISSING
                )

            if not any(
                _general_name_has_uri_prefixes(_HTTP_OR_HTTPS_PREFIXES, gn)
                for gn in ocsp_gns
            ):
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_AIA_OCSP_HTTP_URI_MISSING
                )


class QualifiedCertificatePoliciesValidator(validation.Validator):
    """
    QCS-5.2-1: When certificates are issued as EU Qualified Certificates, they should include, in the certificate
    policies extension, one of the certificate policy identifiers defined in clause 5.3 of ETSI EN 319 411-2
    """

    VALIDATION_RECOMMENDED_POLICY_IDENTIFIER_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "etsi.en_319_412_2.qcs-5.2-1.recommended_certificate_type_policy_identifier_missing",
    )

    VALIDATION_MULTIPLE_POLICY_IDENTIFIERS_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.qcs-5.2-1.multiple_certificate_type_policy_identifiers_present",
    )

    """
    QCS-5.2-2: Policy identifiers included in the certificate policies extension of EU Qualified Certificates shall be
    consistent with the QCStatements according to clause 5.1.
    """
    VALIDATION_MISMATCHED_POLICY_IDENTIFIER_FOR_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.qcs-5.2-2.mismatched_policy_identifier_for_certificate_type",
    )

    # TODO: add EU qualified non-website types
    _CERTIFICATE_TYPE_SET_TO_POLICY_IDENTIFIER_MAPPINGS = [
        (etsi_constants.QEVCP_W_EIDAS_CERTIFICATE_TYPES, en_319_411_2.id_qcp_web),
        (etsi_constants.QNCP_W_OV_EIDAS_CERTIFICATE_TYPES, en_319_411_2.id_qncp_web),
        (etsi_constants.QNCP_W_IV_EIDAS_CERTIFICATE_TYPES, en_319_411_2.id_qncp_web),
        (
            etsi_constants.QNCP_W_GEN_LP_EIDAS_CERTIFICATE_TYPES,
            en_319_411_2.id_qncp_web_gen,
        ),
        (
            etsi_constants.QNCP_W_GEN_NP_EIDAS_CERTIFICATE_TYPES,
            en_319_411_2.id_qncp_web_gen,
        ),
        (
            etsi_constants.QCP_N_QSCD_CERTIFICATE_TYPES,
            en_319_411_2.id_qcp_natural_qscd,
        ),
    ]

    def __init__(self, certificate_type: etsi_constants.CertificateType):
        super().__init__(
            validations=[
                self.VALIDATION_RECOMMENDED_POLICY_IDENTIFIER_MISSING,
                self.VALIDATION_MULTIPLE_POLICY_IDENTIFIERS_PRESENT,
                self.VALIDATION_MISMATCHED_POLICY_IDENTIFIER_FOR_TYPE,
            ],
            pdu_class=rfc5280.CertificatePolicies,
        )

        self._certificate_type = certificate_type

        self._recommended_policy_oid = (
            self._get_recommended_policy_oid_for_certificate_type()
        )

    def match(self, node):
        # TODO: add support for non-QWAC types
        return super().match(node) and self._recommended_policy_oid is not None

    def _get_recommended_policy_oid_for_certificate_type(
        self,
    ) -> typing.Optional[univ.ObjectIdentifier]:
        return next(
            (
                p
                for t, p in self._CERTIFICATE_TYPE_SET_TO_POLICY_IDENTIFIER_MAPPINGS
                if self._certificate_type in t
            ),
            None,
        )

    def validate(self, node):
        policy_oids = node.document.policy_oids

        certificate_type_policy_oids = (
            policy_oids & pkilint.etsi.asn1.en_319_411_2.QUALIFIED_POLICY_OIDS
        )

        if len(certificate_type_policy_oids) > 1:
            oids = oid.format_oids(certificate_type_policy_oids)

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_MULTIPLE_POLICY_IDENTIFIERS_PRESENT,
                f"Multiple certificate type policy identifiers present: {oids}",
            )
        elif not certificate_type_policy_oids:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_RECOMMENDED_POLICY_IDENTIFIER_MISSING,
                f'Missing recommended certificate type policy identifier "{self._recommended_policy_oid}"',
            )
        elif self._recommended_policy_oid not in certificate_type_policy_oids:
            # if we're here, then there's one element in the set, so it's safe to do this
            policy_oid = next(iter(certificate_type_policy_oids))

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_MISMATCHED_POLICY_IDENTIFIER_FOR_TYPE,
                f"Certificate type is {self._certificate_type} ({self._recommended_policy_oid}) but certificate "
                f'contains certificate type policy identifier "{policy_oid}"',
            )


class NaturalPersonKeyUsageValidator(etsi_shared.KeyUsageValidator):
    """
    NAT-4.3.2-2: Certificates used to validate commitment to signed content (e.g. documents, agreements and/or
    transactions) shall be limited to type A, B or F.
    """

    VALIDATION_INVALID_CONTENT_COMMITMENT_SETTING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.en_319_412_2.nat-4.3.2-1.invalid_content_commitment_setting",
    )

    """
    NAT-4.3.2-3: Of these alternatives, type A should be used (see the security note 2 below).
    """
    VALIDATION_NON_PREFERRED_CONTENT_COMMITMENT_SETTING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "etsi.en_319_412_2.nat-4.3.2-3.non_preferred_content_commitment_setting",
    )

    def __init__(self, is_content_commitment_type):
        super().__init__(
            is_content_commitment_type,
            self.VALIDATION_INVALID_CONTENT_COMMITMENT_SETTING,
            self.VALIDATION_NON_PREFERRED_CONTENT_COMMITMENT_SETTING,
        )


class ExtensionsPresenceValidator(common.ExtensionsPresenceValidator):
    VALIDATION_EXTENSIONS_FIELD_ABSENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "etsi.extensions_field_absent"
    )

    def __init__(self):
        super().__init__(self.VALIDATION_EXTENSIONS_FIELD_ABSENT)
