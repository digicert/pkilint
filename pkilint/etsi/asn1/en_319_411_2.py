from pyasn1.type.univ import ObjectIdentifier


_ARC = ObjectIdentifier("0.4.0.194112.1")


id_qcp_natural = _ARC + (0,)

id_qcp_legal = _ARC + (1,)

id_qcp_natural_qscd = _ARC + (2,)

id_qcp_legal_qscd = _ARC + (3,)

id_qcp_web = _ARC + (4,)

id_qncp_web = _ARC + (5,)

id_qncp_web_gen = _ARC + (6,)

QUALIFIED_POLICY_OIDS = {
    id_qcp_natural,
    id_qcp_legal,
    id_qcp_natural_qscd,
    id_qcp_legal_qscd,
    id_qcp_web,
    id_qncp_web,
    id_qncp_web_gen,
}
