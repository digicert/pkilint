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
