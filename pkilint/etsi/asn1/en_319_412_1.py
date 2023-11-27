from pyasn1.type import univ


def _OID(*components):
    output = []
    for x in tuple(components):
        if isinstance(x, univ.ObjectIdentifier):
            output.extend(list(x))
        else:
            output.append(int(x))

    return univ.ObjectIdentifier(output)


_ID_ETSI_ARC = _OID(0, 4, 0, 194121)


id_etsi_qcs_semantics_identifiers = _OID(_ID_ETSI_ARC, 1)


id_etsi_qcs_semanticsId_Natural = _OID(id_etsi_qcs_semantics_identifiers, 1)


id_etsi_qcs_SemanticsId_Legal = _OID(id_etsi_qcs_semantics_identifiers, 2)


id_etsi_qcs_semanticsId_eIDASNatural = _OID(id_etsi_qcs_semantics_identifiers, 3)


id_etsi_qcs_SemanticsId_eIDASLegal = _OID(id_etsi_qcs_semantics_identifiers, 4)


id_etsi_ext = _OID(_ID_ETSI_ARC, 2)


id_etsi_ext_valassured_ST_certs = _OID(id_etsi_ext, 1)


EXTENSION_MAPPINGS = {
    id_etsi_ext_valassured_ST_certs: univ.Null(),
}
