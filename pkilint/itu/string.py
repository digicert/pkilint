from pyasn1.type import constraint
from pyasn1.type.char import PrintableString

from pkilint import validation


def _char_range(start, end):
    return [chr(i) for i in range(ord(start), ord(end) + 1)]


class PrintableStringConstraintValidator(validation.ASN1ConstraintValidator):

    def __init__(self):
        allowed_chars = (
                _char_range('0', '9') +
                _char_range('A', 'Z') +
                _char_range('a', 'z') +
                list(" '()+,-./:=?")
        )
        c = constraint.PermittedAlphabetConstraint(*allowed_chars)

        super().__init__(pdu_supertype=PrintableString(), constraint=c,
                         validations=validation.ValidationFinding(
                             validation.ValidationFindingSeverity.ERROR,
                             'itu.invalid_printablestring_character'
                         )
                         )
