from pkilint import validation
from pkilint.etsi.asn1 import ts_119_495 as ts_119_495_asn1
from pyasn1_alt_modules import rfc3739


_ROLE_OID_TO_NAME_MAPPINGS = {
    ts_119_495_asn1.id_psd2_role_psp_as: 'PSP_AS',
    ts_119_495_asn1.id_psd2_role_psp_pi: 'PSP_PI',
    ts_119_495_asn1.id_psd2_role_psp_ai: 'PSP_AI',
    ts_119_495_asn1.id_psd2_role_psp_ic: 'PSP_IC',
}


class RolesOfPspContainsRolesValidator(validation.Validator):
    """GEN-5.2.2-1: RolesOfPSP shall contain one or more roles or contain a single entry indicating that the role is
    unspecified."""
    VALIDATION_PSP_ROLES_EMPTY = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'etsi.ts_119_495.gen-5.2.2-1.roles_of_psp_empty'
    )

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_PSP_ROLES_EMPTY], pdu_class=ts_119_495_asn1.RolesOfPSP)

    def validate(self, node):
        if not any(node.children):
            raise validation.ValidationFindingEncountered(self.VALIDATION_PSP_ROLES_EMPTY)

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
