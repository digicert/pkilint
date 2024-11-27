from typing import Callable, Mapping, Optional

from pyasn1.type import univ
from pyasn1_alt_modules import rfc5280, rfc6962, rfc6960, rfc3739

from pkilint import validation, document, pkix
from pkilint.cabf.asn1 import ev_guidelines
from pkilint.itu import x520_name
from pkilint.pkix import Rfc2119Word

OID_TO_CODE_NAME = {
    # EKUs
    rfc5280.id_kp_codeSigning: "codesigning",
    rfc5280.id_kp_emailProtection: "emailprotection",
    rfc5280.id_kp_timeStamping: "timestamping",
    rfc5280.id_kp_OCSPSigning: "ocspsigning",
    rfc5280.anyExtendedKeyUsage: "anyeku",
    rfc6962.id_kp_precertificateSigning: "precertsigning",
    rfc5280.id_kp_serverAuth: "serverauth",
    rfc5280.id_kp_clientAuth: "clientauth",
    # extensions
    rfc5280.id_ce_authorityKeyIdentifier: "authority_key_identifier",
    rfc5280.id_ce_basicConstraints: "basic_constraints",
    rfc5280.id_ce_certificatePolicies: "certificate_policies",
    rfc5280.id_ce_cRLDistributionPoints: "crl_distribution_points",
    rfc5280.id_ce_keyUsage: "key_usage",
    rfc5280.id_ce_subjectKeyIdentifier: "subject_key_identifier",
    rfc5280.id_ce_extKeyUsage: "extended_key_usage",
    rfc5280.id_pe_authorityInfoAccess: "authority_info_access",
    rfc5280.id_ce_nameConstraints: "name_constraints",
    rfc6962.id_ce_embeddedSCT: "sct_list",
    rfc5280.id_ce_subjectAltName: "subject_altname",
    rfc6962.id_ce_criticalPoison: "precert_poison",
    rfc6960.id_pkix_ocsp_nocheck: "ocsp_nocheck",
    rfc3739.id_pe_qcStatements: "qc_statements",
    rfc5280.id_ce_policyMappings: "policy_mappings",
    rfc5280.id_ce_policyConstraints: "policy_constraints",
    rfc5280.id_ce_inhibitAnyPolicy: "inhibit_any_policy",
    # AIA access methods
    rfc5280.id_ad_ocsp: "ocsp",
    rfc5280.id_ad_caIssuers: "ca_issuers",
    # attributes
    rfc5280.id_at_countryName: "country",
    rfc5280.id_at_stateOrProvinceName: "state_or_province",
    rfc5280.id_at_localityName: "locality",
    x520_name.id_at_postalCode: "postal_code",
    x520_name.id_at_streetAddress: "street_address",
    rfc5280.id_at_organizationName: "organization_name",
    rfc5280.id_at_commonName: "common_name",
    rfc5280.id_at_organizationalUnitName: "organizational_unit_name",
    rfc5280.id_at_serialNumber: "serial_number",
    x520_name.id_at_businessCategory: "business_category",
    ev_guidelines.id_evat_jurisdiction_countryName: "jurisdiction_country",
    ev_guidelines.id_evat_jurisdiction_stateOrProvinceName: "jurisdiction_state_or_province",
    ev_guidelines.id_evat_jurisdiction_localityName: "jurisdiction_locality",
    rfc5280.id_at_surname: "surname",
    rfc5280.id_at_givenName: "given_name",
    x520_name.id_at_organizationIdentifier: "organization_identifier",
}


class ElementIdentifierAllowanceValidator(validation.Validator):
    # use global mappings by default
    _OID_TO_CODE_NAME = OID_TO_CODE_NAME

    @classmethod
    def _create_finding(
        cls, fmt: str, rfc2119word: pkix.Rfc2119Word, o: univ.ObjectIdentifier
    ):
        if rfc2119word == pkix.Rfc2119Word.MAY:
            return None
        else:
            return validation.ValidationFinding(
                rfc2119word.to_severity, fmt.format(oid=cls._OID_TO_CODE_NAME[o])
            )

    def __init__(
        self,
        element_name: str,
        element_oid_retriever: Callable[[document.PDUNode], document.PDUNode],
        known_element_allowances: Mapping[univ.ObjectIdentifier, pkix.Rfc2119Word],
        unexpected_presence_code_format: str = None,
        unexpected_absence_code_format: str = None,
        unknown_element_presence_finding: Optional[validation.ValidationFinding] = None,
        **kwargs,
    ):
        self._element_name = element_name
        self._element_oid_retriever = element_oid_retriever

        self._expected_element_presences = {
            o: self._create_finding(unexpected_absence_code_format, w, o)
            for o, w in known_element_allowances.items()
            if w in {Rfc2119Word.MAY, Rfc2119Word.SHOULD, Rfc2119Word.MUST}
        }
        self._expected_element_absences = {
            o: self._create_finding(unexpected_presence_code_format, w, o)
            for o, w in known_element_allowances.items()
            if w in {Rfc2119Word.MAY, Rfc2119Word.SHOULD_NOT, Rfc2119Word.MUST_NOT}
        }

        self._unknown_element_presence_finding = unknown_element_presence_finding

        validations = [
            a for a in self._expected_element_presences.values() if a is not None
        ] + [a for a in self._expected_element_absences.values() if a is not None]

        if unknown_element_presence_finding is not None:
            validations.append(unknown_element_presence_finding)

        super().__init__(validations=list(validations), **kwargs)

    def validate(self, node):
        oids = {self._element_oid_retriever(n).pdu for n in node.children.values()}

        # process unexpected present elements
        finding_descriptions = [
            validation.ValidationFindingDescription(v, None)
            for o, v in self._expected_element_absences.items()
            if o in oids and v is not None
        ]

        # process unexpected absent elements
        finding_descriptions.extend(
            [
                validation.ValidationFindingDescription(v, None)
                for o, v in self._expected_element_presences.items()
                if o not in oids and v is not None
            ]
        )

        # process unknown elements
        if self._unknown_element_presence_finding is not None:
            finding_descriptions.extend(
                [
                    validation.ValidationFindingDescription(
                        self._unknown_element_presence_finding,
                        f"Unknown {self._element_name} present: {str(o)}",
                    )
                    for o in oids
                    if o not in self._expected_element_presences
                    and o not in self._expected_element_absences
                ]
            )

        return validation.ValidationResult(self, node, finding_descriptions)


class ExtensionsPresenceValidator(validation.Validator):
    def __init__(self, validation_extensions_field_absent):
        self._validation_extensions_field_absent = validation_extensions_field_absent

        super().__init__(
            validations=validation_extensions_field_absent,
            pdu_class=rfc5280.TBSCertificate,
        )

    def validate(self, node):
        if "extensions" not in node.children:
            raise validation.ValidationFindingEncountered(
                self._validation_extensions_field_absent
            )


class ExtensionIdentifierAllowanceValidator(ElementIdentifierAllowanceValidator):
    @staticmethod
    def _retrieve_extension_id(node):
        return node.children["extnID"]

    def __init__(
        self,
        extension_allowances,
        finding_code_classifier: str,
        unknown_extension_allowance: Rfc2119Word,
    ):
        unknown_extension_finding = (
            None
            if unknown_extension_allowance == Rfc2119Word.MAY
            else (
                validation.ValidationFinding(
                    unknown_extension_allowance.to_severity,
                    f"{finding_code_classifier}.unknown_extension_present",
                )
            )
        )

        super().__init__(
            "extension",
            ExtensionIdentifierAllowanceValidator._retrieve_extension_id,
            extension_allowances,
            f"{finding_code_classifier}.{{oid}}_extension_present",
            f"{finding_code_classifier}.{{oid}}_extension_absent",
            unknown_extension_finding,
            pdu_class=rfc5280.Extensions,
        )


class ExtendedKeyUsageAllowanceValidator(ElementIdentifierAllowanceValidator):
    @staticmethod
    def _retrieve_eku(node):
        return node

    def __init__(
        self,
        eku_allowances,
        finding_code_classifier: str,
        unknown_eku_allowance: Rfc2119Word,
    ):
        unknown_eku_finding = (
            None
            if unknown_eku_allowance == Rfc2119Word.MAY
            else (
                validation.ValidationFinding(
                    unknown_eku_allowance.to_severity,
                    f"{finding_code_classifier}.unknown_eku_present",
                )
            )
        )
        super().__init__(
            "EKU",
            ExtendedKeyUsageAllowanceValidator._retrieve_eku,
            eku_allowances,
            f"{finding_code_classifier}.{{oid}}_eku_present",
            f"{finding_code_classifier}.{{oid}}_eku_absent",
            unknown_eku_finding,
            pdu_class=rfc5280.ExtKeyUsageSyntax,
        )


class ExtensionCriticalityValidator(validation.Validator):
    def __init__(
        self,
        criticality_mapping: Mapping[univ.ObjectIdentifier, bool],
        finding_code_classifier: str,
        critical_adherence_word: Rfc2119Word,
        non_critical_adherence_word: Rfc2119Word,
    ):
        self._expected_critical_extensions = {
            o: validation.ValidationFinding(
                critical_adherence_word.to_severity,
                f"{finding_code_classifier}.non_critical_{OID_TO_CODE_NAME[o]}_extension",
            )
            for o, c in criticality_mapping.items()
            if c and critical_adherence_word is not Rfc2119Word.MAY
        }
        self._expected_non_critical_extensions = {
            o: validation.ValidationFinding(
                critical_adherence_word.to_severity,
                f"{finding_code_classifier}.critical_{OID_TO_CODE_NAME[o]}_extension",
            )
            for o, c in criticality_mapping.items()
            if not c and non_critical_adherence_word is not Rfc2119Word.MAY
        }

        validations = list(self._expected_critical_extensions.values()) + list(
            self._expected_non_critical_extensions.values()
        )

        super().__init__(validations=validations, pdu_class=rfc5280.Extension)

    def validate(self, node):
        ext_oid = node.children["extnID"].pdu

        actual_criticality = bool(node.children["critical"].pdu)

        if actual_criticality:
            non_critical_finding = self._expected_non_critical_extensions.get(ext_oid)

            if non_critical_finding is not None:
                raise validation.ValidationFindingEncountered(non_critical_finding)
        else:
            critical_finding = self._expected_critical_extensions.get(ext_oid)

            if critical_finding is not None:
                raise validation.ValidationFindingEncountered(critical_finding)


class AuthorityInformationAccessAccessMethodPresenceValidator(
    ElementIdentifierAllowanceValidator
):
    @staticmethod
    def _retrieve_access_method_id(node):
        return node.children["accessMethod"]

    def __init__(
        self,
        access_method_allowances,
        finding_code_classifier: str,
        unknown_access_method_allowance: Rfc2119Word,
    ):
        unknown_access_method_finding = (
            None
            if unknown_access_method_allowance == Rfc2119Word.MAY
            else (
                validation.ValidationFinding(
                    unknown_access_method_allowance.to_severity,
                    f"{finding_code_classifier}.unknown_aia_access_method_present",
                )
            )
        )

        super().__init__(
            "access method",
            AuthorityInformationAccessAccessMethodPresenceValidator._retrieve_access_method_id,
            access_method_allowances,
            f"{finding_code_classifier}.{{oid}}_aia_access_method_present",
            f"{finding_code_classifier}.{{oid}}_aia_access_method_absent",
            unknown_access_method_finding,
            pdu_class=rfc5280.AuthorityInfoAccessSyntax,
        )


class AttributeIdentifierAllowanceValidator(ElementIdentifierAllowanceValidator):
    @staticmethod
    def _retrieve_attribute_type_id(node):
        # assume one ATV per RDN
        return node.navigate("0.type")

    def __init__(
        self,
        attribute_allowances,
        finding_code_classifier: str,
        unknown_attribute_allowance: Rfc2119Word,
        path: str = "certificate.tbsCertificate.subject.rdnSequence",
    ):
        unexpected_attribute_finding = (
            None
            if unknown_attribute_allowance == Rfc2119Word.MAY
            else (
                validation.ValidationFinding(
                    unknown_attribute_allowance.to_severity,
                    finding_code_classifier + ".unknown_attribute_present",
                )
            )
        )

        super().__init__(
            "attribute",
            AttributeIdentifierAllowanceValidator._retrieve_attribute_type_id,
            attribute_allowances,
            finding_code_classifier + ".{oid}_attribute_present",
            finding_code_classifier + ".{oid}_attribute_absent",
            unexpected_attribute_finding,
            path=path,
        )
