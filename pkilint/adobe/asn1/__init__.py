from pyasn1.type import univ, namedtype, namedval
from pyasn1_alt_modules import rfc5280


_ADOBE_X509_OID_ARC = univ.ObjectIdentifier("1.2.840.113583.1.1.9")


id_adobe_timestamp = univ.ObjectIdentifier(_ADOBE_X509_OID_ARC.asTuple() + (1,))


class AdobeExtensionVersion(univ.Integer):
    pass


AdobeExtensionVersion.componentType = namedval.NamedValues(
    ("v1", 1),
)


class AdobeTimestamp(univ.Sequence):
    pass


AdobeTimestamp.componentType = namedtype.NamedTypes(
    namedtype.NamedType("version", AdobeExtensionVersion()),
    namedtype.NamedType("location", rfc5280.GeneralName()),
    namedtype.DefaultedNamedType("requiresAuth", univ.Boolean().subtype(value=False)),
)


id_adobe_archiverevinfo = univ.ObjectIdentifier(_ADOBE_X509_OID_ARC.asTuple() + (2,))


class AdobeArchiveRevInfo(univ.Sequence):
    pass


AdobeArchiveRevInfo.componentType = namedtype.NamedTypes(
    namedtype.NamedType("version", AdobeExtensionVersion())
)


EXTENSION_MAPPINGS = {
    id_adobe_timestamp: AdobeTimestamp(),
    id_adobe_archiverevinfo: AdobeArchiveRevInfo(),
}
