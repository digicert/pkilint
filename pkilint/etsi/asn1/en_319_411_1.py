from pyasn1.type import univ


_ARC = univ.ObjectIdentifier("0.4.0.2042.1")

id_ncp = _ARC + (1,)

id_ncp_plus = _ARC + (2,)

id_lcp = _ARC + (3,)

id_evcp = _ARC + (4,)

id_dvcp = _ARC + (6,)

id_ovcp = _ARC + (7,)

id_ivcp = _ARC + (8,)

POLICY_OIDS = {
    id_ncp,
    id_ncp_plus,
    id_lcp,
    id_evcp,
    id_dvcp,
    id_ovcp,
    id_ivcp,
}
