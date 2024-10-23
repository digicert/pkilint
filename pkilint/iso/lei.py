import re

from pyasn1.type import univ, char, constraint

from pkilint import validation

ISO_OID_ARC = univ.ObjectIdentifier("1.3.6.1.4.1.52266")


id_ce_lei = ISO_OID_ARC + (1,)
id_ce_role = ISO_OID_ARC + (2,)

ub_leiRole_length = 100


class Lei(char.PrintableString):
    subtypeSpec = constraint.ValueSizeConstraint(20, 20)


class Role(char.PrintableString):
    subtypeSpec = constraint.ValueSizeConstraint(1, ub_leiRole_length)


EXTENSION_MAPPINGS = {
    id_ce_lei: Lei(),
    id_ce_role: Role(),
}


_LEI_FORMAT_RE = re.compile(r"^(?P<value>[0-9A-Z]{18})(?P<checksum>\d{2})$")


VALIDATION_INVALID_LEI_FORMAT = validation.ValidationFinding(
    validation.ValidationFindingSeverity.ERROR, "iso.lei.invalid_lei_format"
)

VALIDATION_INVALID_LEI_CHECKSUM = validation.ValidationFinding(
    validation.ValidationFindingSeverity.ERROR, "iso.lei.invalid_lei_checksum"
)


def _calculate_checksum(value):
    subs = {chr(l): str(10 + l - ord("A")) for l in range(ord("A"), ord("Z") + 1)}

    for l, n in subs.items():
        value = value.replace(l, n)

    value += "00"

    value_int = int(value)

    remainder = value_int % 97

    return 98 - remainder


def validate_lei(lei: str):
    m = _LEI_FORMAT_RE.match(lei)

    if m is None:
        raise validation.ValidationFindingEncountered(
            VALIDATION_INVALID_LEI_FORMAT, f'Invalid LEI format: "{lei}"'
        )

    value_part = m.group("value")
    actual_checksum = int(m.group("checksum"))

    expected_checksum = _calculate_checksum(value_part)

    if actual_checksum != expected_checksum:
        raise validation.ValidationFindingEncountered(
            VALIDATION_INVALID_LEI_CHECKSUM,
            f"Expected: {expected_checksum}, actual: {actual_checksum}",
        )


class LeiExtensionValueSyntaxValidator(validation.Validator):
    def __init__(self):
        super().__init__(
            validations=[
                VALIDATION_INVALID_LEI_FORMAT,
                VALIDATION_INVALID_LEI_CHECKSUM,
            ],
            pdu_class=Lei,
        )

    def validate(self, node):
        value = str(node.pdu)

        validate_lei(value)
