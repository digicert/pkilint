from pyasn1.type import univ
from pyasn1.type.constraint import ValueSizeConstraint

from pkilint import document
from pkilint.nist.asn1 import csor


ML_DSA_44_PublicKeySize = 1312
ML_DSA_65_PublicKeySize = 1952
ML_DSA_87_PublicKeySize = 2592


class MlDsa44PublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(ML_DSA_44_PublicKeySize, ML_DSA_44_PublicKeySize)


class MlDsa65PublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(ML_DSA_65_PublicKeySize, ML_DSA_65_PublicKeySize)


class MlDsa87PublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(ML_DSA_87_PublicKeySize, ML_DSA_87_PublicKeySize)


ALGORITHM_OID_TO_KEY_MAPPINGS = {
    # pure
    csor.id_ml_dsa_44: MlDsa44PublicKey(),
    csor.id_ml_dsa_65: MlDsa65PublicKey(),
    csor.id_ml_dsa_87: MlDsa87PublicKey(),
    # pre-hashed
    csor.id_hash_ml_dsa_44_with_sha512: MlDsa44PublicKey(),
    csor.id_hash_ml_dsa_65_with_sha512: MlDsa65PublicKey(),
    csor.id_hash_ml_dsa_87_with_sha512: MlDsa87PublicKey(),
}

ALGORITHM_OID_TO_PARAMETER_MAPPINGS = {
    k: document.ValueDecoder.VALUE_NODE_ABSENT
    for k in ALGORITHM_OID_TO_KEY_MAPPINGS.keys()
}
