from pyasn1.type import univ
from pyasn1.type.constraint import ValueSizeConstraint

from pkilint import document
from pkilint.nist.asn1 import csor


ML_KEM_512_PublicKeySize = 800
ML_KEM_768_PublicKeySize = 1184
ML_KEM_1024_PublicKeySize = 1568


class MlKem512PublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        ML_KEM_512_PublicKeySize, ML_KEM_512_PublicKeySize
    )


class MlKem768PublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        ML_KEM_768_PublicKeySize, ML_KEM_768_PublicKeySize
    )


class MlKem1024PublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        ML_KEM_1024_PublicKeySize, ML_KEM_1024_PublicKeySize
    )


ALGORITHM_OID_TO_KEY_MAPPINGS = {
    csor.id_alg_ml_kem_512: MlKem512PublicKey(),
    csor.id_alg_ml_kem_768: MlKem768PublicKey(),
    csor.id_alg_ml_kem_1024: MlKem1024PublicKey(),
}

ALGORITHM_OID_TO_PARAMETER_MAPPINGS = {
    k: document.ValueDecoder.VALUE_NODE_ABSENT
    for k in ALGORITHM_OID_TO_KEY_MAPPINGS.keys()
}
