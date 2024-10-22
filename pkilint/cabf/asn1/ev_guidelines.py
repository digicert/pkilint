# Auto-generated by asn1ate v.0.6.0 from ev_guidelines.asn1
# (last modified on 2020-12-23 17:42:25.113525)

from pyasn1.type import univ, char, namedtype, tag, constraint
from pyasn1.type.univ import ObjectIdentifier, Choice
from pyasn1_alt_modules import rfc5280


def _OID(*components):
    output = []
    for x in tuple(components):
        if isinstance(x, univ.ObjectIdentifier):
            output.extend(list(x))
        else:
            output.append(int(x))

    return univ.ObjectIdentifier(output)


class CABFOrganizationIdentifier(univ.Sequence):
    pass


CABFOrganizationIdentifier.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "registrationSchemeIdentifier",
        char.PrintableString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(3, 3)
        ),
    ),
    namedtype.NamedType(
        "registrationCountry",
        char.PrintableString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(2, 2)
        ),
    ),
    namedtype.OptionalNamedType(
        "registrationStateOrProvince",
        char.PrintableString()
        .subtype(subtypeSpec=constraint.ValueSizeConstraint(0, 128))
        .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)),
    ),
    namedtype.NamedType("registrationReference", char.UTF8String()),
)

id_CABFOrganizationIdentifier = _OID(2, 23, 140, 3, 1)

id_evat_jurisdiction_localityName = ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.1")


class EVGJurisdictionLocalityName(Choice):
    pass


EVGJurisdictionLocalityName.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "teletexString",
        char.TeletexString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, rfc5280.ub_locality_name)
        ),
    ),
    namedtype.NamedType(
        "printableString",
        char.PrintableString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, rfc5280.ub_locality_name)
        ),
    ),
    namedtype.NamedType(
        "universalString",
        char.UniversalString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, rfc5280.ub_locality_name)
        ),
    ),
    namedtype.NamedType(
        "utf8String",
        char.UTF8String().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, rfc5280.ub_locality_name)
        ),
    ),
    namedtype.NamedType(
        "bmpString",
        char.BMPString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, rfc5280.ub_locality_name)
        ),
    ),
)

id_evat_jurisdiction_stateOrProvinceName = ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.2")


class EVGJurisdictionStateOrProvinceName(Choice):
    pass


EVGJurisdictionStateOrProvinceName.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        "teletexString",
        char.TeletexString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, rfc5280.ub_state_name)
        ),
    ),
    namedtype.NamedType(
        "printableString",
        char.PrintableString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, rfc5280.ub_state_name)
        ),
    ),
    namedtype.NamedType(
        "universalString",
        char.UniversalString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, rfc5280.ub_state_name)
        ),
    ),
    namedtype.NamedType(
        "utf8String",
        char.UTF8String().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, rfc5280.ub_state_name)
        ),
    ),
    namedtype.NamedType(
        "bmpString",
        char.BMPString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, rfc5280.ub_state_name)
        ),
    ),
)

id_evat_jurisdiction_countryName = ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3")


class EVGJurisdictionCountryName(rfc5280.X520countryName):
    pass


ATTRIBUTE_TYPE_MAPPINGS = {
    id_evat_jurisdiction_countryName: EVGJurisdictionCountryName(),
    id_evat_jurisdiction_stateOrProvinceName: EVGJurisdictionStateOrProvinceName(),
    id_evat_jurisdiction_localityName: EVGJurisdictionLocalityName(),
}

EXTENSION_MAPPINGS = {
    id_CABFOrganizationIdentifier: CABFOrganizationIdentifier(),
}
