from pyasn1.type import namedtype, constraint, char
from pyasn1_alt_modules import rfc5280

MAX = float("inf")


def _create_unbounded_directory_string_namedtypes():
    return namedtype.NamedTypes(
        namedtype.NamedType(
            "teletexString",
            char.TeletexString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            ),
        ),
        namedtype.NamedType(
            "printableString",
            char.PrintableString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            ),
        ),
        namedtype.NamedType(
            "universalString",
            char.UniversalString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            ),
        ),
        namedtype.NamedType(
            "utf8String",
            char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            ),
        ),
        namedtype.NamedType(
            "bmpString",
            char.BMPString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
            ),
        ),
    )


class X520OrganizationNameUnbounded(rfc5280.X520OrganizationName):
    componentType = _create_unbounded_directory_string_namedtypes()


class X520OrganizationalUnitNameUnbounded(rfc5280.X520OrganizationalUnitName):
    componentType = _create_unbounded_directory_string_namedtypes()


class X520CommonNameUnbounded(rfc5280.X520CommonName):
    componentType = _create_unbounded_directory_string_namedtypes()


class X520PseudonymUnbounded(rfc5280.X520Pseudonym):
    componentType = _create_unbounded_directory_string_namedtypes()


UNBOUNDED_ATTRIBUTE_TYPE_MAPPINGS = {
    rfc5280.id_at_organizationName: X520OrganizationNameUnbounded(),
    rfc5280.id_at_organizationalUnitName: X520OrganizationalUnitNameUnbounded(),
    rfc5280.id_at_commonName: X520CommonNameUnbounded(),
    rfc5280.id_at_pseudonym: X520PseudonymUnbounded(),
}
