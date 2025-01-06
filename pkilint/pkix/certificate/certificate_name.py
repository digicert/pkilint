from pyasn1_alt_modules import rfc5280

from pkilint import validation
from pkilint.pkix import general_name


class SubjectEmailAddressInSanValidator(validation.Validator):
    VALIDATION_SUBJECT_EMAIL_NOT_IN_SAN = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        "pkix.subject_email_address_not_in_san",
    )

    def __init__(self):
        super().__init__(
            pdu_class=rfc5280.EmailAddress,
            validations=[self.VALIDATION_SUBJECT_EMAIL_NOT_IN_SAN],
        )

    def validate(self, node):
        san_ext_idx = node.document.get_extension_by_oid(rfc5280.id_ce_subjectAltName)

        if san_ext_idx is None:
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_SUBJECT_EMAIL_NOT_IN_SAN,
                "Certificate does not have SAN extension",
            )

        ext, _ = san_ext_idx

        email_address = str(node.pdu)

        if not any(
            str(rfc822name_node.pdu) == email_address
            for rfc822name_node in node.document.get_san_general_names_by_type(
                general_name.GeneralNameTypeName.RFC822_NAME
            )
        ):
            raise validation.ValidationFindingEncountered(
                self.VALIDATION_SUBJECT_EMAIL_NOT_IN_SAN,
                f'Subject DN e-mail address "{email_address}" not found in SAN',
            )
