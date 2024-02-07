from pkilint import validation
from pkilint.etsi.asn1 import ts_119_495 as ts_119_495_asn1


_ROLE_OID_TO_NAME_MAPPINGS = {
    ts_119_495_asn1.id_psd2_role_psp_as: 'PSP_AS',
    ts_119_495_asn1.id_psd2_role_psp_pi: 'PSP_PI',
    ts_119_495_asn1.id_psd2_role_psp_ai: 'PSP_AI',
    ts_119_495_asn1.id_psd2_role_psp_ic: 'PSP_IC',
}


class RolesOfPspContainsRolesValidator(validation.Validator):
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

    VALIDATION_PSP_ROLES_UNSPECIFIED = validation.ValidationFinding(validation.ValidationFindingSeverity.ERROR,
    'etsi.ts_119_495.gen-5.2.2-3a.psp_roles_not_unspecified')

    def __init__(self):
        super().__init__(validations=[self.VALIDATION_PSP_ROLES_EMPTY, self.VALIDATION_PSP_ROLES_INVALID, self.VALIDATION_PSP_ROLES_MISMATCH,
        self.VALIDATION_PSP_ROLES_UNSPECIFIED], pdu_class=ts_119_495_asn1.RolesOfPSP)
        self._expected_roles = {'0.4.0.19495.1.3': 'PSP_AI', '0.4.0.19495.1.1': 'PSP_AS',
        '0.4.0.19495.1.4': 'PSP_IC', '0.4.0.19495.1.2': 'PSP_PI', '0.4.0.19495.1.0': 'Unspecified'}

    def validate(self, node):
        if not any(node.children):
            raise validation.ValidationFindingEncountered(self.VALIDATION_PSP_ROLES_EMPTY)
        
        for children in node.children.values():
            psp_oid = str(children.pdu['roleOfPspOid'])
            role_psp = str(children.pdu['roleOfPspName'])
            expected_role = self._expected_roles.get(psp_oid)

            if psp_oid  == "0.4.0.19495.1.0" and role_psp != expected_role:
                raise validation.ValidationFindingEncountered(self.VALIDATION_PSP_ROLES_UNSPECIFIED)
            if psp_oid not in self._expected_roles.keys():
                raise validation.ValidationFindingEncountered(self.VALIDATION_PSP_OIDS_INVALID)
            if role_psp not in self._expected_roles.values():
                raise validation.ValidationFindingEncountered(self.VALIDATION_PSP_ROLES_INVALID)
            if role_psp != expected_role:
                raise validation.ValidationFindingEncountered(self.VALIDATION_PSP_ROLES_MISMATCH)


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
