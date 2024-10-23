import validators

from pkilint import validation
from pkilint.msft import asn1


class UserPrincipalNameSyntaxValidator(validation.Validator):
    VALIDATION_INVALID_UPN_SYNTAX = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "msft.invalid_user_principal_name_syntax",
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_INVALID_UPN_SYNTAX],
            pdu_class=asn1.UserPrincipalName,
        )

    def validate(self, node):
        value = str(node.pdu)

        if not validators.email(value):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_INVALID_UPN_SYNTAX, f'Invalid UPN syntax: "{value}"'
            )
