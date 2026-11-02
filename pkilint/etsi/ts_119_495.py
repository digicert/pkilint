import re

from iso3166 import countries_by_alpha2
from pyasn1_alt_modules import rfc3739, rfc5280

import pkilint.oid
from pkilint import validation
from pkilint.etsi import etsi_constants
from pkilint.etsi.asn1 import ts_119_495 as ts_119_495_asn1
from pkilint.itu import x520_name

# GEN-5.2.3-1A and GEN-5.2.3-5: the value used for NCAName and NCAId when the subject role is an international
# central bank (PSP_CB) or international public authority (PSP_PA)
_NCA_NOT_APPLICABLE_VALUE = "NA"

# GEN-5.2.3-1A and GEN-5.2.3-5: the roles for which NCAName and NCAId are not applicable
_NCA_NOT_APPLICABLE_ROLE_OIDS = frozenset(
    {
        ts_119_495_asn1.id_psd2_role_psp_cb,
        ts_119_495_asn1.id_psd2_role_psp_pa,
    }
)


def _get_psd2_role_oids(psd2_qc_type_node):
    """Returns the set of role OIDs conveyed in the RolesOfPSP field of a PSD2QcType node."""
    roles_node = psd2_qc_type_node.children.get("rolesOfPSP")

    if roles_node is None:
        return set()

    return {role.children["roleOfPspOid"].pdu for role in roles_node.children.values()}


def _has_nca_not_applicable_role(psd2_qc_type_node):
    """Returns True if any conveyed role is one for which GEN-5.2.3-1A and GEN-5.2.3-5 render NCAName and NCAId
    not applicable."""
    return bool(_get_psd2_role_oids(psd2_qc_type_node) & _NCA_NOT_APPLICABLE_ROLE_OIDS)


class RolesOfPspValidator(validation.Validator):
    """
    GEN-5.2.2-1: RolesOfPSP shall contain one or more roles or contain a single entry indicating that the role is
    unspecified.
    GEN-5.2.2-2: If the certificate is issued for EU PSD2 or EU IPR, the role object identifier shall be the
    appropriate one of the OIDs defined in the ASN.1 snippet below.
    GEN-5.2.2-3: If the certificate is issued for EU PSD2 the role name shall be the appropriate one of the abbreviated
    names defined in clause 4.2: PSP_AS, PSP_PI, PSP_AI, PSP_IC, PSP_CB or PSP_PA.
    GEN-5.2.2-3A: If the role is unspecified, the role name shall be "Unspecified".
    GEN-5.2.2-3B: If the certificate is issued for EU IPR, the role name should be the appropriate one of the
    abbreviated names defined in clause 4.2: VOP_RS or VOP_VS.
    REG-5.2.2-5: The TSP shall ensure that the name in roleOfPspName is the one associated with the role object
    identifier held in roleOfPspOid.
    """

    VALIDATION_PSP_ROLES_EMPTY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2.2-1.roles_of_psp_empty",
    )
    VALIDATION_PSP_ROLES_INVALID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2-2.invalid_psp_role",
    )

    VALIDATION_PSP_OIDS_INVALID = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2-2.invalid_psp_oid",
    )

    VALIDATION_PSP_ROLES_MISMATCH = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2.2-5.psp_role_mismatch",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_PSP_ROLES_EMPTY,
                self.VALIDATION_PSP_ROLES_INVALID,
                self.VALIDATION_PSP_ROLES_MISMATCH,
                self.VALIDATION_PSP_OIDS_INVALID,
            ],
            pdu_class=ts_119_495_asn1.RolesOfPSP,
        )
        self._expected_roles = {
            ts_119_495_asn1.id_psd2_role_psp_ai: "PSP_AI",
            ts_119_495_asn1.id_psd2_role_psp_as: "PSP_AS",
            ts_119_495_asn1.id_psd2_role_psp_cb: "PSP_CB",
            ts_119_495_asn1.id_psd2_role_psp_ic: "PSP_IC",
            ts_119_495_asn1.id_psd2_role_psp_pa: "PSP_PA",
            ts_119_495_asn1.id_psd2_role_psp_pi: "PSP_PI",
            ts_119_495_asn1.id_psd2_role_psp_unspecified: "Unspecified",
            ts_119_495_asn1.id_psd2_role_vop_rs: "VOP_RS",
            ts_119_495_asn1.id_psd2_role_vop_vs: "VOP_VS",
        }

    def validate(self, node):
        if not any(node.children):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PSP_ROLES_EMPTY
            )

        for child in node.children.values():
            psp_oid = child.children["roleOfPspOid"].pdu
            role_psp = str(child.children["roleOfPspName"].pdu)
            expected_role = self._expected_roles.get(psp_oid)

            if psp_oid not in self._expected_roles.keys():
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_PSP_OIDS_INVALID,
                    f"expected oid values are {pkilint.oid.format_oids(self._expected_roles.keys())} got {psp_oid}",
                )
            if role_psp not in self._expected_roles.values():
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_PSP_ROLES_INVALID,
                    f"expected role values are [ {', '.join(map(str, self._expected_roles.values()))}]. Got {role_psp}",
                )
            if role_psp != expected_role:
                raise validation.ValidationFindingEncountered(
                    self.VALIDATION_PSP_ROLES_MISMATCH,
                    f"Expected role is: {expected_role}. Role in cert is: {role_psp}. Oid in cert is: {psp_oid}",
                )


class PresenceofQCEUPDSStatementValidator(validation.Validator):
    """GEN-5.1.1 The Open Banking Attributes shall be included in a QCSTatement within the qcStatements extension
    as specified in clause 3.2.5 of IETF RFC 3739."""

    VALIDATION_QC_EU_PDS_MISSING = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.1.1.qc_eu_pds_missing",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_QC_EU_PDS_MISSING],
            pdu_class=rfc3739.QCStatements,
        )

    def validate(self, node):
        if (
            ts_119_495_asn1.id_etsi_psd2_qcStatement
            not in node.document.qualified_statement_ids
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_QC_EU_PDS_MISSING
            )


class NCANameLatinCharactersValidator(validation.Validator):
    """GEN-5.2.3-1: The NCAName shall be plain text using Latin alphabet provided by the Competent Authority itself
    for purpose of identification in certificates."""

    VALIDATION_NCA_NAME_NON_LATIN = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2.3-1.nca_name_non_latin",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_NCA_NAME_NON_LATIN],
            pdu_class=ts_119_495_asn1.NCAName,
        )

    def validate(self, node):
        nca_name = str(node.pdu)

        if not nca_name.isascii():
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_NCA_NAME_NON_LATIN, f"invalid NCA name: {nca_name}"
            )


class NCAIdValidator(validation.Validator):
    """GEN-5.2.3-2: Validator for NCAId structure.
    The NCAId shall contain information using the following structure in the presented order:
    • 2 character ISO 3166-1 country code representing the Competent Authority country;
    • hyphen-minus "-" (0x2D (ASCII), U+002D (UTF-8)); and
    • 2-8 character Competent Authority identifier without country code (A-Z uppercase only, no separator).

    GEN-5.2.3-5 provides an exemption from this structure for the international central bank (PSP_CB) and
    international public authority (PSP_PA) roles, for which the NCAId has the value "NA". That exemption is
    role-aware: the value "NA" is only left unevaluated when one of those roles is actually conveyed. For any
    other role, "NA" does not satisfy the structure above and is reported as an invalid structure.
    """

    VALIDATION_INVALID_STRUCTURE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2.3-2.invalid_structure",
    )
    VALIDATION_INVALID_ISO_COUNTRY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2.3-2.invalid_iso_country",
    )
    VALIDATION_INVALID_CA_IDENTIFIER = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2.3-2.invalid_ca_identifier",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_INVALID_STRUCTURE,
                self.VALIDATION_INVALID_ISO_COUNTRY,
                self.VALIDATION_INVALID_CA_IDENTIFIER,
            ],
            pdu_class=ts_119_495_asn1.NCAId,
        )

    def validate(self, node):
        nca_id = str(node.pdu)

        # GEN-5.2.3-5: exempted only when an exempt role (PSP_CB or PSP_PA) is actually conveyed. Using "NA" with
        # any other role is not permitted, so it is evaluated against the structure below and reported.
        if nca_id == _NCA_NOT_APPLICABLE_VALUE and _has_nca_not_applicable_role(
            node.parent
        ):
            return

        if nca_id.count("-") != 1:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_STRUCTURE,
                f"Invalid separator in NCAId: {nca_id}",
            )

        iso_country_code, ca_identifier = nca_id.rsplit("-", 1)

        if iso_country_code not in countries_by_alpha2:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_ISO_COUNTRY,
                f"Invalid ISO country code: {iso_country_code}",
            )

        if not (
            2 <= len(ca_identifier) <= 8
            and ca_identifier.isalpha()
            and ca_identifier.isupper()
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_CA_IDENTIFIER,
                f"Invalid Competent Authority identifier: {ca_identifier}",
            )


class NcaNaValueValidator(validation.Validator):
    """
    GEN-5.2.3-1A: If the subject role is international central bank (PSP_CB) or international public authority
    (PSP_PA), NCAName shall have the value "NA".

    GEN-5.2.3-5: If the subject role is international central bank (PSP_CB) or international public authority
    (PSP_PA), NCAId shall have the value "NA".

    Both requirements are conditioned on the roles conveyed in a sibling field, so this validator is bound to
    PSD2QcType rather than to NCAName/NCAId.

    The converse is also enforced: GEN-5.2.3-1A and GEN-5.2.3-5 permit the value "NA" only for those two roles.
    For NCAName this validator reports the prohibited use directly, as GEN-5.2.3-1 does not otherwise constrain
    the value. For NCAId no separate finding is raised here, because "NA" does not satisfy the structure
    mandated by GEN-5.2.3-2 and is reported by NCAIdValidator, whose exemption for "NA" is role-aware.
    """

    VALIDATION_NCA_NAME_NOT_NA = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2.3-1a.nca_name_not_na",
    )

    VALIDATION_NCA_ID_NOT_NA = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2.3-5.nca_id_not_na",
    )

    VALIDATION_PROHIBITED_NCA_NAME_NA = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2.3-1a.prohibited_nca_name_na_value",
    )

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_NCA_NAME_NOT_NA,
                self.VALIDATION_NCA_ID_NOT_NA,
                self.VALIDATION_PROHIBITED_NCA_NAME_NA,
            ],
            pdu_class=ts_119_495_asn1.PSD2QcType,
        )

    def validate(self, node):
        role_oids = _get_psd2_role_oids(node)
        exempt_roles = role_oids & _NCA_NOT_APPLICABLE_ROLE_OIDS

        nca_name_node = node.children.get("nCAName")
        nca_id_node = node.children.get("nCAId")

        nca_name = None if nca_name_node is None else str(nca_name_node.pdu)
        nca_id = None if nca_id_node is None else str(nca_id_node.pdu)

        findings = []

        if exempt_roles:
            formatted_roles = pkilint.oid.format_oids(exempt_roles)

            if nca_name is not None and nca_name != _NCA_NOT_APPLICABLE_VALUE:
                findings.append(
                    validation.ValidationFindingDescription(
                        self.VALIDATION_NCA_NAME_NOT_NA,
                        f'NCAName is "{nca_name}" but role {formatted_roles} requires '
                        f'"{_NCA_NOT_APPLICABLE_VALUE}"',
                    )
                )

            if nca_id is not None and nca_id != _NCA_NOT_APPLICABLE_VALUE:
                findings.append(
                    validation.ValidationFindingDescription(
                        self.VALIDATION_NCA_ID_NOT_NA,
                        f'NCAId is "{nca_id}" but role {formatted_roles} requires '
                        f'"{_NCA_NOT_APPLICABLE_VALUE}"',
                    )
                )
        elif nca_name == _NCA_NOT_APPLICABLE_VALUE:
            formatted_roles = (
                pkilint.oid.format_oids(role_oids) if role_oids else "<none>"
            )

            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_PROHIBITED_NCA_NAME_NA,
                    f'NCAName has the value "{_NCA_NOT_APPLICABLE_VALUE}", which is only permitted for the '
                    f"PSP_CB and PSP_PA roles, but the conveyed role(s) are {formatted_roles}",
                )
            )

        return validation.ValidationResult(self, node, findings)


class PsdOrganizationIdentifierFormatValidator(validation.Validator):
    """
    GEN-5.2.1-3: If an Authorization Number was issued by a Competent Authority the subject organizationIdentifier
    attribute should contain the Authorization Number encoded using the following structure in the presented order:

    • "PSD" as 3 character legal person identity type reference;
    • 2 character ISO 3166-1 [8] country code representing the Competent Authority country;
    • hyphen-minus "-" (0x2D (ASCII), U+002D (UTF-8));
    • 2-8 character Competent Authority identifier without country code (A-Z uppercase only, no separator);
    • hyphen-minus "-" (0x2D (ASCII), U+002D (UTF-8)); and
    • identifier (authorization number as specified by the Competent Authority. There are no restrictions on the
    characters used).

    ...

    GEN-5.3-3: The organizationIdentifier shall be present in the Subject's Distinguished Name and encoded with legal
    person syntax as specified in clause 5.2.1.
    """

    VALIDATION_INVALID_PSD_ORGANIZATION_ID_FORMAT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.gen-5.2.1-3.invalid_psd_organization_id_format",
    )

    _PSD_ORGID_FORMAT_REGEX = re.compile("^PSD[A-Z]{2}-[A-Z]{2,8}-.+$")

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_INVALID_PSD_ORGANIZATION_ID_FORMAT],
            pdu_class=x520_name.X520OrganizationIdentifier,
        )

    def validate(self, node):
        try:
            _, decoded_value_node = node.child
        except ValueError:
            return

        value_str = str(decoded_value_node.pdu)

        m = self._PSD_ORGID_FORMAT_REGEX.match(value_str)

        if m is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_PSD_ORGANIZATION_ID_FORMAT,
                f'Invalid PSD organization identifier format: "{value_str}"',
            )


class Psd2CertificatePolicyOidPresenceValidator(validation.Validator):
    """
    OVR-6.1-3: TSPs issuing certificates for EU PSD2 may use the following policy identifier to augment the policy
    requirements associated with policy identifier QEVCP-w, QNCP-w, or QNCP-w-gen as specified in ETSI
    EN 319 411-2 [5].

    OVR-6.1-3B [CONDITIONAL]: If the policy identifier QNCP-w-gen is used, then the TSP shall give precedence to the
    requirements defined in the present document.

    OVR-6.1-3C [CONDITIONAL]: If there are no conflicts between the requirements in the present document and those in
    the CA/Browser Forum EV Guidelines [i.11] then the following QCP-w-psd2 policy identifier may be used in addition
    to: QEVCP-w.
    """

    VALIDATION_PROHIBITED_PSD2_POLICY_OID_PRESENT = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "etsi.ts_119_495.ovr-6.1-3.prohibited_psd2_policy_oid_present",
    )

    def __init__(self, certificate_type):
        super().__init__(
            validations=[self.VALIDATION_PROHIBITED_PSD2_POLICY_OID_PRESENT],
            pdu_class=rfc5280.CertificatePolicies,
        )

        self._certificate_type = certificate_type

    def validate(self, node):
        if (
            ts_119_495_asn1.qcp_web_psd2 in node.document.policy_oids
            and self._certificate_type
            not in etsi_constants.PSD2_EIDAS_CERTIFICATE_TYPES
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_PROHIBITED_PSD2_POLICY_OID_PRESENT,
                f'Certificate type is "{self._certificate_type}" but PSD2 policy identifier is present',
            )
