from pkilint import validation
from pkilint.etsi.asn1 import ts_119_495 as ts_119_495_asn1
from pyasn1_alt_modules import rfc3739
from iso3166 import countries_by_alpha2
import pkilint.oid



_ROLE_OID_TO_NAME_MAPPINGS = {
    ts_119_495_asn1.id_psd2_role_psp_as: 'PSP_AS',
    ts_119_495_asn1.id_psd2_role_psp_pi: 'PSP_PI',
    ts_119_495_asn1.id_psd2_role_psp_ai: 'PSP_AI',
    ts_119_495_asn1.id_psd2_role_psp_ic: 'PSP_IC',
}


class RolesOfPspValidator(validation.Validator):
    """GEN-5.2.2-1: RolesOfPSP shall contain one or more roles or contain a single entry indicating that the role is
    unspecified.
    GEN-5.2.2-2 If the certificate is issued for EU PSD2 the role object identifier shall be the appropriate one of the four OIDS
    defined in the ASN.1 snippet below; and 
    GEN-5.2.2-3 If the certificate is issued for EU PSD2 the role name shall be  the appropriate one of the abbreviated names 
    defined in clause 5.1 PSP_AS, PSP_PI, or PSP_IC. 
    GEN-5.2.2-3A If the role is unspecified the role name shall be "Unspecified"
    GEN-5.2.2-5 The TSP shall ensure that the name in roleofPSPName is the one associated with the role object 
    identifier held in roleofPSPOid. 
    """
    VALIDATION_PSP_ROLES_EMPTY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.ts_119_495.gen-5.2.2-1.roles_of_psp_empty'
    )
    VALIDATION_PSP_ROLES_INVALID = validation.ValidationFinding(validation.ValidationFindingSeverity.ERROR,
    'etsi.ts_119_495.gen-5.2-2.invalid_psp_role')

    VALIDATION_PSP_OIDS_INVALID = validation.ValidationFinding(validation.ValidationFindingSeverity.ERROR,
    'etsi.ts_119_495.gen-5.2-2.invalid_psp_oid')

    VALIDATION_PSP_ROLES_MISMATCH = validation.ValidationFinding(validation.ValidationFindingSeverity.ERROR,
    'etsi.ts_119_495.gen-5.2.2-5.psp_role_mismatch')

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_PSP_ROLES_EMPTY, self.VALIDATION_PSP_ROLES_INVALID, self.VALIDATION_PSP_ROLES_MISMATCH, self.VALIDATION_PSP_OIDS_INVALID], pdu_class=ts_119_495_asn1.RolesOfPSP)
        self._expected_roles = {ts_119_495_asn1.id_psd2_role_psp_ai: 'PSP_AI', ts_119_495_asn1.id_psd2_role_psp_as: 'PSP_AS',
        ts_119_495_asn1.id_psd2_role_psp_ic: 'PSP_IC', ts_119_495_asn1.id_psd2_role_psp_pi: 'PSP_PI', ts_119_495_asn1.id_psd2_role_psp_unspecified: 'Unspecified'}

    def validate(self, node):
        if not any(node.children):
            raise validation.ValidationFindingEncountered(self.VALIDATION_PSP_ROLES_EMPTY)
        
        for children in node.children.values():
            psp_oid = children.pdu['roleOfPspOid']
            role_psp = str(children.pdu['roleOfPspName'])
            expected_role = self._expected_roles.get(psp_oid)

            if psp_oid not in self._expected_roles.keys():
                raise validation.ValidationFindingEncountered(self.VALIDATION_PSP_OIDS_INVALID, f'expected oid values are {pkilint.oid.format_oids(self._expected_roles.keys())} got {psp_oid}')
            if role_psp not in self._expected_roles.values():
                raise validation.ValidationFindingEncountered(self.VALIDATION_PSP_ROLES_INVALID, f"expected role values are [ {', '.join(map(str, self._expected_roles.values()))}]. Got {role_psp}")
            if role_psp != expected_role:
                raise validation.ValidationFindingEncountered(self.VALIDATION_PSP_ROLES_MISMATCH, f'Expected role is: {expected_role}. Role in cert is: {role_psp}. Oid in cert is: {psp_oid}')

class PresenceofQCEUPDSStatementValidator(validation.Validator):
    """GEN-5.1.1 The Open Banking Attributes shall be included in a QCSTatement within the qcStatements extension
    as specified in clause 3.2.5 of IETF RFC 3739."""
    VALIDATION_QC_EU_PDS_MISSING = validation.ValidationFinding(validation.ValidationFindingSeverity.ERROR,
    'etsi.ts_119_495.gen-5.1.1.qc_eu_pds_missing')

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_QC_EU_PDS_MISSING], pdu_class=rfc3739.QCStatements)

    def validate(self, node):
        if ts_119_495_asn1.id_etsi_psd2_qcStatement not in node.document.qualified_statement_ids:
            raise validation.ValidationFindingEncountered(self.VALIDATION_QC_EU_PDS_MISSING)

class NCANameLatinCharactersValidator(validation.Validator):
    """GEN-5.2.3-1: The NCAName shall be plain text using Latin alphabet provided by the Competent Authority itself for purpose of identification in certificates."""
    VALIDATION_NCA_NAME_NON_LATIN = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.ts_119_495.gen-5.2.3-1.nca_name_non_latin'
    )

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_NCA_NAME_NON_LATIN], pdu_class=ts_119_495_asn1.NCAName)

    def validate(self, node):
        nca_name = str(node.pdu)

        if not nca_name.isascii():
            raise validation.ValidationFindingEncountered(self.VALIDATION_NCA_NAME_NON_LATIN,
                                                          f'invalid NCA name: {nca_name}')


class NCAIdValidator(validation.Validator):
    """GEN-5.2.3-2: Validator for NCAId structure.
    The NCAId shall contain information using the following structure in the presented order:
    • 2 character ISO 3166-1 country code representing the Competent Authority country;
    • hyphen-minus "-" (0x2D (ASCII), U+002D (UTF-8)); and
    • 2-8 character Competent Authority identifier without country code (A-Z uppercase only, no separator)."""

    VALIDATION_INVALID_STRUCTURE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.ts_119_495.gen-5.2.3-2.invalid_structure'
    )
    VALIDATION_INVALID_ISO_COUNTRY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.ts_119_495.gen-5.2.3-2.invalid_iso_country'
    )
    VALIDATION_INVALID_CA_IDENTIFIER = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.ts_119_495.gen-5.2.3-2.invalid_ca_identifier'
    )

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_INVALID_STRUCTURE,
                                      self.VALIDATION_INVALID_ISO_COUNTRY,
                                      self.VALIDATION_INVALID_CA_IDENTIFIER],
                                      pdu_class=ts_119_495_asn1.NCAId)

    def validate(self, node):
        nca_id = str(node.pdu)

        if nca_id.count('-') != 1:
            raise validation.ValidationFindingEncountered(self.VALIDATION_INVALID_STRUCTURE,
                                                           f'Invalid separator in NCAId: {nca_id}')

        iso_country_code, ca_identifier = nca_id.rsplit('-', 1)

        if iso_country_code not in countries_by_alpha2:
            raise validation.ValidationFindingEncountered(self.VALIDATION_INVALID_ISO_COUNTRY,
                                                           f'Invalid ISO country code: {iso_country_code}')

        if not (2 <= len(ca_identifier) <= 8 and ca_identifier.isalpha() and ca_identifier.isupper()):
            raise validation.ValidationFindingEncountered(self.VALIDATION_INVALID_CA_IDENTIFIER,
                                                           f'Invalid Competent Authority identifier: {ca_identifier}')
