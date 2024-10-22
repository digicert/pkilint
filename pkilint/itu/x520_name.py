from pyasn1.type import namedtype, char, constraint
from pyasn1.type.univ import Choice, ObjectIdentifier

id_at_businessCategory = ObjectIdentifier("2.5.4.15")

ub_business_category = 128


class X520BusinessCategory(Choice):
    pass


X520BusinessCategory.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "teletexString",
        char.TeletexString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_business_category)
        ),
    ),
    namedtype.NamedType(
        "printableString",
        char.PrintableString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_business_category)
        ),
    ),
    namedtype.NamedType(
        "universalString",
        char.UniversalString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_business_category)
        ),
    ),
    namedtype.NamedType(
        "utf8String",
        char.UTF8String().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_business_category)
        ),
    ),
    namedtype.NamedType(
        "bmpString",
        char.BMPString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_business_category)
        ),
    ),
)

id_at_postalCode = ObjectIdentifier("2.5.4.17")

ub_postal_code = 40


class X520PostalCode(Choice):
    pass


X520PostalCode.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "teletexString",
        char.TeletexString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_postal_code)
        ),
    ),
    namedtype.NamedType(
        "printableString",
        char.PrintableString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_postal_code)
        ),
    ),
    namedtype.NamedType(
        "universalString",
        char.UniversalString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_postal_code)
        ),
    ),
    namedtype.NamedType(
        "utf8String",
        char.UTF8String().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_postal_code)
        ),
    ),
    namedtype.NamedType(
        "bmpString",
        char.BMPString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_postal_code)
        ),
    ),
)

id_at_streetAddress = ObjectIdentifier("2.5.4.9")

ub_street_address = 128


class X520StreetAddress(Choice):
    pass


X520StreetAddress.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "teletexString",
        char.TeletexString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_street_address)
        ),
    ),
    namedtype.NamedType(
        "printableString",
        char.PrintableString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_street_address)
        ),
    ),
    namedtype.NamedType(
        "universalString",
        char.UniversalString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_street_address)
        ),
    ),
    namedtype.NamedType(
        "utf8String",
        char.UTF8String().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_street_address)
        ),
    ),
    namedtype.NamedType(
        "bmpString",
        char.BMPString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, ub_street_address)
        ),
    ),
)

id_at_organizationIdentifier = ObjectIdentifier("2.5.4.97")


class X520OrganizationIdentifier(Choice):
    pass


X520OrganizationIdentifier.componentType = namedtype.NamedTypes(
    namedtype.NamedType("teletexString", char.TeletexString()),
    namedtype.NamedType("printableString", char.PrintableString()),
    namedtype.NamedType("universalString", char.UniversalString()),
    namedtype.NamedType("utf8String", char.UTF8String()),
    namedtype.NamedType("bmpString", char.BMPString()),
)

ATTRIBUTE_TYPE_MAPPINGS = {
    id_at_businessCategory: X520BusinessCategory(),
    id_at_postalCode: X520PostalCode(),
    id_at_streetAddress: X520StreetAddress(),
    id_at_organizationIdentifier: X520OrganizationIdentifier(),
}
