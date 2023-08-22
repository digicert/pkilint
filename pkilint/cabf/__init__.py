from pyasn1_alt_modules import rfc3739, rfc2985

from pkilint.cabf.asn1 import ev_guidelines as ev_guidelines_asn1
from pkilint.itu import x520_name
from pkilint.pkix import extension, name

NAME_ATTRIBUTE_MAPPINGS = {
    **rfc2985._certificateAttributesMapUpdate,
    **x520_name.ATTRIBUTE_TYPE_MAPPINGS,
    **name.ATTRIBUTE_TYPE_MAPPINGS,
    **ev_guidelines_asn1.ATTRIBUTE_TYPE_MAPPINGS,
}

EXTENSION_MAPPINGS = {
    **extension.EXTENSION_MAPPINGS,
    **ev_guidelines_asn1.EXTENSION_MAPPINGS,
    **rfc3739.certificateExtensionsMap,
}
