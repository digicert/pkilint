import re

from iso3166 import countries_by_alpha2
from pyasn1_alt_modules import rfc3739, rfc5280

import pkilint.oid
from pkilint import validation
from pkilint.etsi import etsi_constants
from pkilint.etsi.asn1 import ts_119_495 as ts_119_495_asn1
from pkilint.itu import x520_name


class RolesOfPspValidator(validation.Validator):
    """
    GEN-5.2.2-1: RolesOfPSP shall contain one or more roles or contain a single entry indicating that the role is
    unspecified.
    GEN-5.2.2-2 If the certificate is issued for EU PSD2 the role object identifier shall be the
    appropriate one of the four OIDS defined in the ASN.1 snippet below; and
    GEN-5.2.2-3 If the certificate is issued for EU PSD2 the role name shall be  the appropriate one of the abbreviated
    names defined in clause 5.1 PSP_AS, PSP_PI, or PSP_IC.
    GEN-5.2.2-3A If the role is unspecified the role name shall be "Unspecified"
    GEN-5.2.2-5 The TSP shall ensure that the name in roleofPSPName is the one associated with the role object
    identifier held in roleofPSPOid.
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
            ts_119_495_asn1.id_psd2_role_psp_ic: "PSP_IC",
            ts_119_495_asn1.id_psd2_role_psp_pi: "PSP_PI",
            ts_119_495_asn1.id_psd2_role_psp_unspecified: "Unspecified",
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
    requirements associated with policy identifier QEVCP-w or QNCP-w as specified in ETSI EN 319 411-2 [5] giving
    precedence to the requirements defined in the present document.
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
