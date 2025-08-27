import typing
from urllib.parse import urlparse

from pyasn1_alt_modules import rfc5280, rfc3279, rfc5480, rfc8398, rfc8410, rfc3739

import pkilint.adobe.asn1 as adobe_asn1
from pkilint import oid, validation
from pkilint.cabf.smime import smime_constants
from pkilint.cabf.smime.smime_constants import Generation, ValidationLevel
from pkilint.cabf.smime.smime_name import get_email_addresses_from_san
from pkilint.iso import lei
from pkilint.itu import bitstring
from pkilint.nist.asn1 import csor
from pkilint.pkix import extension
from pkilint.pkix.certificate.certificate_extension import KeyUsageBitName


class CertificatePoliciesPresenceValidator(extension.ExtensionPresenceValidator):
    VALIDATION_CERTIFICATE_POLICIES_EXTENSION_ABSENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.certificate_policies_extension_missing",
    )

    def __init__(self):
        super().__init__(
            extension_oid=rfc5280.id_ce_certificatePolicies,
            validation=self.VALIDATION_CERTIFICATE_POLICIES_EXTENSION_ABSENT,
            pdu_class=rfc5280.Extensions,
        )


class ExtendedKeyUsagePresenceValidator(extension.ExtensionPresenceValidator):
    VALIDATION_EKU_EXTENSION_ABSENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.extended_key_usage_extension_missing",
    )

    def __init__(self):
        super().__init__(
            extension_oid=rfc5280.id_ce_extKeyUsage,
            validation=self.VALIDATION_EKU_EXTENSION_ABSENT,
            pdu_class=rfc5280.Extensions,
        )


class CabfSmimeKeyUsagePresenceValidator(extension.ExtensionPresenceValidator):
    VALIDATION_KU_EXTENSION_ABSENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.key_usage_extension_missing",
    )

    def __init__(self):
        super().__init__(
            extension_oid=rfc5280.id_ce_keyUsage,
            validation=self.VALIDATION_KU_EXTENSION_ABSENT,
            pdu_class=rfc5280.Extensions,
        )


class SubjectAlternativeNamePresenceValidator(extension.ExtensionPresenceValidator):
    VALIDATION_SAN_EXTENSION_ABSENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.smime.san_extension_missing"
    )

    def __init__(self):
        super().__init__(
            extension_oid=rfc5280.id_ce_subjectAltName,
            validation=self.VALIDATION_SAN_EXTENSION_ABSENT,
            pdu_class=rfc5280.Extensions,
        )


class LeiPresenceValidator(validation.Validator):
    VALIDATION_LEI_EXTENSION_PROHIBITED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.lei_extension_prohibited",
    )

    def __init__(self, validation_level):
        super().__init__(
            validations=[self.VALIDATION_LEI_EXTENSION_PROHIBITED], pdu_class=lei.Lei
        )

        self._validation_level = validation_level

    def validate(self, node):
        if self._validation_level in {
            ValidationLevel.MAILBOX,
            ValidationLevel.INDIVIDUAL,
        }:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_LEI_EXTENSION_PROHIBITED
            )


class LeiRolePresenceValidator(validation.Validator):
    VALIDATION_LEI_ROLE_EXTENSION_PROHIBITED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.lei_role_extension_prohibited",
    )

    def __init__(self, validation_level):
        super().__init__(
            validations=[self.VALIDATION_LEI_ROLE_EXTENSION_PROHIBITED],
            pdu_class=lei.Role,
        )

        self._validation_level = validation_level

    def validate(self, node):
        if self._validation_level != ValidationLevel.SPONSORED:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_LEI_ROLE_EXTENSION_PROHIBITED
            )


class LeiCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_LEI_EXTENSION_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.smime.lei_extension_critical"
    )

    def __init__(self):
        super().__init__(
            type_oid=lei.id_ce_lei,
            is_critical=False,
            validation=self.VALIDATION_LEI_EXTENSION_CRITICAL,
        )


class LeiRoleCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_LEI_ROLE_EXTENSION_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.lei_role_extension_critical",
    )

    def __init__(self):
        super().__init__(
            type_oid=lei.id_ce_role,
            is_critical=False,
            validation=self.VALIDATION_LEI_ROLE_EXTENSION_CRITICAL,
        )


class RequiredPolicyIdentifierValidator(validation.Validator):
    VALIDATION_NO_CABF_RESERVED_OID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.no_required_reserved_policy_oid",
    )

    VALIDATION_MULTIPLE_RESERVED_OIDS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.multiple_reserved_policy_oids",
    )

    VALIDATION_ANYPOLICY_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.smime.anypolicy_present"
    )

    def __init__(self, validation_level, generation):
        self._validation_level = validation_level
        self._generation = generation

        super().__init__(
            validations=[
                self.VALIDATION_NO_CABF_RESERVED_OID,
                self.VALIDATION_MULTIPLE_RESERVED_OIDS,
                self.VALIDATION_ANYPOLICY_PRESENT,
            ],
            pdu_class=rfc5280.CertificatePolicies,
        )

    def validate(self, node):
        oids = set(
            (pi.children["policyIdentifier"].pdu for pi in node.children.values())
        )

        findings = []

        if rfc5280.anyPolicy in oids:
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_ANYPOLICY_PRESENT, None
                )
            )

        expected_oid = smime_constants.get_policy_oid(
            self._validation_level, self._generation
        )

        all_smime_oids = set()
        for g in smime_constants.Generation:
            for v in smime_constants.ValidationLevel:
                all_smime_oids.add(smime_constants.get_policy_oid(v, g))

        cert_smime_oids = oids.intersection(all_smime_oids)

        if expected_oid not in cert_smime_oids:
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_NO_CABF_RESERVED_OID,
                    f"Required policy OID {str(expected_oid)} is missing",
                )
            )

        if len(cert_smime_oids) > 1:
            desc = ", ".join(map(str, cert_smime_oids))

            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_MULTIPLE_RESERVED_OIDS,
                    f"Multiple CA/B Reserved Policy OIDs found: {desc}",
                )
            )

        return validation.ValidationResult(self, node, findings)


class SmimeUserNoticeValidator(validation.Validator):
    VALIDATION_USERNOTICE_HAS_NOTICEREF = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.usernotice_has_noticeref",
    )

    def __init__(self):
        super().__init__(
            validations=self.VALIDATION_USERNOTICE_HAS_NOTICEREF,
            pdu_class=rfc5280.UserNotice,
        )

    def validate(self, node):
        if "noticeRef" in node.children:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_USERNOTICE_HAS_NOTICEREF
            )


class AllowedExtendedKeyUsageValidator(validation.Validator):
    VALIDATION_EMAIL_PROTECTION_EKU_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.emailprotection_eku_missing",
    )

    VALIDATION_PROHIBITED_EKU_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.smime.prohibited_eku_present"
    )

    _LEGACY_MP_PROHIBITED_EKUS = {
        rfc5280.anyExtendedKeyUsage,
        rfc5280.id_kp_codeSigning,
        rfc5280.id_kp_OCSPSigning,
        rfc5280.id_kp_serverAuth,
        rfc5280.id_kp_timeStamping,
    }

    def __init__(self, generation):
        self._generation = generation

        super().__init__(
            validations=[
                self.VALIDATION_EMAIL_PROTECTION_EKU_MISSING,
                self.VALIDATION_PROHIBITED_EKU_PRESENT,
            ],
            pdu_class=rfc5280.ExtKeyUsageSyntax,
        )

    def validate(self, node):
        kp_oids = set((kp.pdu for kp in node.children.values()))

        findings = []
        if rfc5280.id_kp_emailProtection not in kp_oids:
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_EMAIL_PROTECTION_EKU_MISSING, None
                )
            )

        if self._generation == smime_constants.Generation.STRICT:
            prohibited_kps = kp_oids.difference({rfc5280.id_kp_emailProtection})
        else:
            prohibited_kps = kp_oids.intersection(self._LEGACY_MP_PROHIBITED_EKUS)

        if len(prohibited_kps) > 0:
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_PROHIBITED_EKU_PRESENT,
                    f"Prohibited EKU(s) present: {oid.format_oids(prohibited_kps)}",
                )
            )

        return validation.ValidationResult(self, node, findings)


class KeyUsageAllowance(typing.NamedTuple):
    required_bit_names: typing.Set[str]
    optional_bit_names: typing.Set[str]
    allowed_bit_names: typing.Set[str]

    @staticmethod
    def from_bit_names(
        required_bit_names: typing.Set[str], optional_bit_names: typing.Set[str]
    ):
        return KeyUsageAllowance(
            required_bit_names=required_bit_names,
            optional_bit_names=optional_bit_names,
            allowed_bit_names=required_bit_names | optional_bit_names,
        )


class AlgorithmKeyUsageAllowances:
    VALIDATION_UNKNOWN_CERT_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.unknown_certificate_key_usage_type",
    )

    VALIDATION_PROHIBITED_KU_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.smime.prohibited_ku_present"
    )

    def __init__(
        self,
        signing_cert_allowance: typing.Optional[KeyUsageAllowance],
        key_mgmt_cert_allowance: typing.Optional[KeyUsageAllowance],
    ):
        self._signing_cert_allowance = signing_cert_allowance
        self._key_mgmt_cert_allowance = key_mgmt_cert_allowance

    def validate_asserted_bits(
        self, asserted_bit_names
    ) -> typing.Optional[validation.ValidationFindingDescription]:
        is_signing_cert = (
            self._signing_cert_allowance
            and asserted_bit_names & self._signing_cert_allowance.required_bit_names
        )
        is_key_mgmt_cert = (
            self._key_mgmt_cert_allowance
            and asserted_bit_names & self._key_mgmt_cert_allowance.required_bit_names
        )

        if not is_signing_cert and not is_key_mgmt_cert:
            return validation.ValidationFindingDescription(
                self.VALIDATION_UNKNOWN_CERT_TYPE, None
            )

        allowed_bit_names = set()
        if is_signing_cert:
            allowed_bit_names.update(self._signing_cert_allowance.allowed_bit_names)
        if is_key_mgmt_cert:
            allowed_bit_names.update(self._key_mgmt_cert_allowance.allowed_bit_names)

        prohibited_bit_names = asserted_bit_names - allowed_bit_names

        if prohibited_bit_names:
            ku_str = ", ".join(sorted(prohibited_bit_names))

            return validation.ValidationFindingDescription(
                self.VALIDATION_PROHIBITED_KU_PRESENT,
                f"Prohibited KUs present: {ku_str}",
            )

        return None


_DIGITAL_SIGNATURE_ALLOWANCES = KeyUsageAllowance.from_bit_names(
    {KeyUsageBitName.DIGITAL_SIGNATURE}, {KeyUsageBitName.NON_REPUDIATION}
)


class RsaKeyUsageAllowances(AlgorithmKeyUsageAllowances):
    def __init__(self, generation: Generation):
        optional_key_mgmt_bits = (
            set()
            if generation == Generation.STRICT
            else {KeyUsageBitName.DATA_ENCIPHERMENT}
        )

        super().__init__(
            _DIGITAL_SIGNATURE_ALLOWANCES,
            KeyUsageAllowance.from_bit_names(
                {KeyUsageBitName.KEY_ENCIPHERMENT}, optional_key_mgmt_bits
            ),
        )


class EcKeyUsageAllowances(AlgorithmKeyUsageAllowances):
    def __init__(self):
        super().__init__(
            _DIGITAL_SIGNATURE_ALLOWANCES,
            KeyUsageAllowance.from_bit_names(
                {KeyUsageBitName.KEY_AGREEMENT},
                {KeyUsageBitName.ENCIPHER_ONLY, KeyUsageBitName.DECIPHER_ONLY},
            ),
        )


class SingleUseDigitalSignatureAlgorithmAllowances(AlgorithmKeyUsageAllowances):
    def __init__(self):
        super().__init__(_DIGITAL_SIGNATURE_ALLOWANCES, None)


class MlkemKeyUsageAllowances(AlgorithmKeyUsageAllowances):
    def __init__(self):
        super().__init__(
            None,
            KeyUsageAllowance.from_bit_names({KeyUsageBitName.KEY_ENCIPHERMENT}, set()),
        )


class AllowedKeyUsageValidator(validation.Validator):
    VALIDATION_UNSUPPORTED_PUBKEY_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.unsupported_public_key_type",
    )

    _EDWARDS_CURVE_IDS = {
        rfc8410.id_Ed448,
        rfc8410.id_Ed25519,
    }

    _MLKEM_IDS = {
        csor.id_alg_ml_kem_512,
        csor.id_alg_ml_kem_768,
        csor.id_alg_ml_kem_1024,
    }

    _MLDSA_IDS = {
        csor.id_ml_dsa_44,
        csor.id_ml_dsa_65,
        csor.id_ml_dsa_87,
    }

    _ALL_BIT_NAMES = {str(n) for n in rfc5280.KeyUsage.namedValues}

    def __init__(self, generation):
        super().__init__(
            validations=[
                AlgorithmKeyUsageAllowances.VALIDATION_PROHIBITED_KU_PRESENT,
                AlgorithmKeyUsageAllowances.VALIDATION_UNKNOWN_CERT_TYPE,
                self.VALIDATION_UNSUPPORTED_PUBKEY_TYPE,
            ],
            pdu_class=rfc5280.KeyUsage,
        )

        single_use_digital_signature_alg_allowances = (
            SingleUseDigitalSignatureAlgorithmAllowances()
        )
        mlkem_allowances = MlkemKeyUsageAllowances()

        self._allowances = {
            rfc3279.rsaEncryption: RsaKeyUsageAllowances(generation),
            rfc5480.id_ecPublicKey: EcKeyUsageAllowances(),
            **{
                o: single_use_digital_signature_alg_allowances
                for o in self._EDWARDS_CURVE_IDS
            },
            **{o: single_use_digital_signature_alg_allowances for o in self._MLDSA_IDS},
            **{o: mlkem_allowances for o in self._MLKEM_IDS},
        }

    def validate(self, node):
        spki_alg_oid = node.navigate(
            ":certificate.tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm"
        ).pdu

        alg_allowances = self._allowances.get(spki_alg_oid)
        if alg_allowances is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_UNSUPPORTED_PUBKEY_TYPE
            )

        asserted_bit_names = {
            n for n in self._ALL_BIT_NAMES if bitstring.has_named_bit(node, n)
        }

        finding_desc = alg_allowances.validate_asserted_bits(asserted_bit_names)
        finding_descs = [finding_desc] if finding_desc else []

        return validation.ValidationResult(self, node, finding_descs)


class EndEntityValidator(validation.Validator):
    VALIDATION_SMIME_CERT_IS_CA = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR, "cabf.smime.is_ca_certificate"
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_SMIME_CERT_IS_CA],
            pdu_class=rfc5280.BasicConstraints,
        )

    def validate(self, node):
        if bool(node.children["cA"].pdu):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_SMIME_CERT_IS_CA
            )


class SubjectAlternativeNameContainsEmailAddressValidator(validation.Validator):
    VALIDATION_SAN_EMAIL_ADDRESS_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.san_does_not_contain_email_address",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_SAN_EMAIL_ADDRESS_MISSING],
            pdu_class=rfc5280.SubjectAltName,
        )

    def validate(self, node):
        if len(get_email_addresses_from_san(node.document)) == 0:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_SAN_EMAIL_ADDRESS_MISSING
            )


class SubjectAlternativeNameProhibitedGeneralNameTypesValidator(validation.Validator):
    VALIDATION_PROHIBITED_GENERALNAME_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.prohibited_generalname_type_present",
    )

    VALIDATION_PROHIBITED_OTHERNAME_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.prohibited_othername_type_present",
    )

    _ALLOWED_TYPES = {"rfc822Name", "directoryName", "otherName"}

    def __init__(self, generation):
        super().__init__(
            validations=[
                self.VALIDATION_PROHIBITED_GENERALNAME_TYPE,
                self.VALIDATION_PROHIBITED_OTHERNAME_TYPE,
            ],
            pdu_class=rfc5280.SubjectAltName,
        )

        self._generation = generation

    def validate(self, node):
        present_types = set((gn.child[0] for gn in node.children.values()))

        prohibited_present_types = present_types - self._ALLOWED_TYPES

        if len(prohibited_present_types) > 0:
            type_str = ", ".join(prohibited_present_types)

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_GENERALNAME_TYPE,
                f"Prohibited GeneralName type(s) present: {type_str}",
            )

        for gn in node.children.values():
            name, val = gn.child

            if name == "otherName":
                type_oid = val.children["type-id"].pdu

                if (
                    type_oid != rfc8398.id_on_SmtpUTF8Mailbox
                    and self._generation == Generation.STRICT
                ):
                    raise validation.ValidationFindingEncountered(
                        self.VALIDATION_PROHIBITED_OTHERNAME_TYPE,
                        f"Prohibited otherName present: {type_oid}",
                    )


class CabfSmimeKeyUsageCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_KU_NOT_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.smime.ku_extension_not_critical",
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc5280.id_ce_keyUsage,
            is_critical=True,
            validation=self.VALIDATION_KU_NOT_CRITICAL,
        )


class GmailAuthorityInfoAccessCaIssuersValidator(validation.Validator):
    VALIDATION_AIA_CA_ISSUERS_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "googl.gmail.authority_info_access_ca_issuers_missing",
    )

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.AuthorityInfoAccessSyntax,
            validations=[self.VALIDATION_AIA_CA_ISSUERS_MISSING],
        )

    def validate(self, node):
        if not any(
            (
                ad
                for ad in node.children.values()
                if ad.children["accessMethod"].pdu == rfc5280.id_ad_caIssuers
            )
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_AIA_CA_ISSUERS_MISSING
            )


class AllowedCrldpFullNameValidator(validation.Validator):
    VALIDATION_CRLDP_FULLNAME_PROHIBITED_GENERALNAME_TYPE = (
        validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            "cabf.smime.crldp_fullname_prohibited_generalname_type",
        )
    )

    VALIDATION_CRLDP_FULLNAME_PROHIBITED_URI_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.crldp_fullname_prohibited_uri_scheme",
    )

    def __init__(self, generation):
        super().__init__(
            validations=[
                self.VALIDATION_CRLDP_FULLNAME_PROHIBITED_URI_SCHEME,
                self.VALIDATION_CRLDP_FULLNAME_PROHIBITED_GENERALNAME_TYPE,
            ],
            pdu_class=rfc5280.DistributionPointName,
            predicate=lambda n: "fullName" in n.children,
        )

        self._generation = generation

    def validate(self, node):
        uris = [
            str(gn.child[1].pdu)
            for gn in node.navigate("fullName").children.values()
            if "uniformResourceIdentifier" in gn.children
        ]

        if len(uris) != len(node.navigate("fullName").children):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_CRLDP_FULLNAME_PROHIBITED_GENERALNAME_TYPE
            )

        allowed_schemes = (
            {"http", "ldap", "ftp"}
            if self._generation == Generation.LEGACY
            else {"http"}
        )
        for u in uris:
            scheme = urlparse(u).scheme

            if scheme.lower() not in allowed_schemes:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_CRLDP_FULLNAME_PROHIBITED_URI_SCHEME,
                    f'Prohibited URI scheme: "{scheme}"',
                )


class AllowedAiaUriSchemeValidator(validation.Validator):
    VALIDATION_PROHIBITED_GENERALNAME_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.aia_prohibited_generalname_type",
    )

    VALIDATION_PROHIBITED_URI_SCHEME = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.aia_prohibited_uri_scheme",
    )

    def __init__(self, generation):
        super().__init__(
            validations=[
                self.VALIDATION_PROHIBITED_GENERALNAME_TYPE,
                self.VALIDATION_PROHIBITED_URI_SCHEME,
            ],
            pdu_class=rfc5280.AccessDescription,
            predicate=lambda n: n.parent is not None
            and isinstance(n.parent, rfc5280.AuthorityInfoAccessSyntax),
        )

        self._generation = generation

    def validate(self, node):
        desc_node = node.children["accessLocation"]
        name, value = desc_node.child

        if name != "uniformResourceIdentifier":
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_GENERALNAME_TYPE,
                f"Prohibited AIA GeneralName type: {name}",
            )

        scheme = urlparse(str(value.pdu)).scheme

        allowed_schemes = (
            {"http", "ftp", "ldap"}
            if self._generation == Generation.LEGACY
            else {"http"}
        )
        if scheme.lower() not in allowed_schemes:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_URI_SCHEME,
                f"Prohibited AIA URI scheme: {scheme}",
            )


class SubjectDirectoryAttributesPresenceValidator(validation.Validator):
    VALIDATION_SDA_EXTENSION_PROHIBITED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.subject_directory_attributes_extension_prohibited",
    )

    def __init__(self, validation_level, generation):
        super().__init__(
            validations=[self.VALIDATION_SDA_EXTENSION_PROHIBITED],
            pdu_class=rfc5280.SubjectDirectoryAttributes,
        )

        self._validation_level = validation_level
        self._generation = generation

    def validate(self, node):
        if (
            self._validation_level == ValidationLevel.MAILBOX
            or self._generation != Generation.LEGACY
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_SDA_EXTENSION_PROHIBITED
            )


class QCStatementsCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_QCS_EXTENSION_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.qc_statements_extension_critical",
    )

    def __init__(self):
        super().__init__(
            type_oid=rfc3739.id_pe_qcStatements,
            is_critical=False,
            validation=self.VALIDATION_QCS_EXTENSION_CRITICAL,
        )


class AdobeTimestampCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_ADOBE_TIMESTAMP_EXTENSION_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.adobe_timestamp_extension_critical",
    )

    def __init__(self):
        super().__init__(
            type_oid=adobe_asn1.id_adobe_timestamp,
            is_critical=False,
            validation=self.VALIDATION_ADOBE_TIMESTAMP_EXTENSION_CRITICAL,
        )


class AdobeArchiveRevInfoCriticalityValidator(extension.ExtensionCriticalityValidator):
    VALIDATION_ADOBE_ARCHIVE_REVINFO_EXTENSION_CRITICAL = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.adobe_archive_revinfo_extension_critical",
    )

    def __init__(self):
        super().__init__(
            type_oid=adobe_asn1.id_adobe_archiverevinfo,
            is_critical=False,
            validation=self.VALIDATION_ADOBE_ARCHIVE_REVINFO_EXTENSION_CRITICAL,
        )


class AdobeTimestampPresenceValidator(validation.Validator):
    VALIDATION_ADOBE_TIMESTAMP_EXTENSION_PROHIBITED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "cabf.smime.adobe_timestamp_extension_prohibited",
    )

    def __init__(self, generation):
        self._generation = generation

        super().__init__(
            validations=[self.VALIDATION_ADOBE_TIMESTAMP_EXTENSION_PROHIBITED],
            pdu_class=adobe_asn1.AdobeTimestamp,
        )

    def validate(self, node):
        if self._generation == smime_constants.Generation.STRICT:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ADOBE_TIMESTAMP_EXTENSION_PROHIBITED
            )


class AdobeArchiveRevInfoPresenceValidator(validation.Validator):
    VALIDATION_ADOBE_ARCHIVE_REVINFO_EXTENSION_PROHIBITED = (
        validation.ValidationFinding(
            validation.ValidationFindingSeverity.ERROR,
            "cabf.smime.adobe_archive_revinfo_extension_prohibited",
        )
    )

    def __init__(self, generation):
        self._generation = generation

        super().__init__(
            validations=[self.VALIDATION_ADOBE_ARCHIVE_REVINFO_EXTENSION_PROHIBITED],
            pdu_class=adobe_asn1.AdobeArchiveRevInfo,
        )

    def validate(self, node):
        if self._generation == smime_constants.Generation.STRICT:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_ADOBE_ARCHIVE_REVINFO_EXTENSION_PROHIBITED
            )


class CrlDistributionPointPresenceValidator(extension.ExtensionPresenceValidator):
    VALIDATION_CRLDP_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.WARNING,
        "cabf.smime.crldp_extension_missing",
    )

    def __init__(self):
        super().__init__(
            extension_oid=rfc5280.id_ce_cRLDistributionPoints,
            validation=self.VALIDATION_CRLDP_MISSING,
            pdu_class=rfc5280.Extensions,
        )
