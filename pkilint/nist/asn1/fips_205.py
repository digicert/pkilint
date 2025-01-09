from pyasn1.type import univ
from pyasn1.type.constraint import ValueSizeConstraint

from pkilint import document
from pkilint.nist.asn1 import csor


SlhDsaShaTwo128sPublicKeySize = 32
SlhDsaShaTwo128fPublicKeySize = 32

SlhDsaShaTwo192sPublicKeySize = 48
SlhDsaShaTwo192fPublicKeySize = 48

SlhDsaShaTwo256sPublicKeySize = 64
SlhDsaShaTwo256fPublicKeySize = 64

SlhDsaShake128sPublicKeySize = 32
SlhDsaShake128fPublicKeySize = 32

SlhDsaShake192sPublicKeySize = 48
SlhDsaShake192fPublicKeySize = 48

SlhDsaShake256sPublicKeySize = 64
SlhDsaShake256fPublicKeySize = 64


class SlhDsaShaTwo128sPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShaTwo128sPublicKeySize, SlhDsaShake128sPublicKeySize
    )


class SlhDsaShaTwo128fPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShaTwo128fPublicKeySize, SlhDsaShake128fPublicKeySize
    )


class SlhDsaShaTwo192sPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShaTwo192sPublicKeySize, SlhDsaShake192sPublicKeySize
    )


class SlhDsaShaTwo192fPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShaTwo192fPublicKeySize, SlhDsaShake192fPublicKeySize
    )


class SlhDsaShaTwo256sPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShaTwo256sPublicKeySize, SlhDsaShake256sPublicKeySize
    )


class SlhDsaShaTwo256fPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShaTwo256fPublicKeySize, SlhDsaShake256fPublicKeySize
    )


class SlhDsaShake128sPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShake128sPublicKeySize, SlhDsaShake128sPublicKeySize
    )


class SlhDsaShake128fPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShake128fPublicKeySize, SlhDsaShake128fPublicKeySize
    )


class SlhDsaShake192sPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShake192sPublicKeySize, SlhDsaShake192sPublicKeySize
    )


class SlhDsaShake192fPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShake192fPublicKeySize, SlhDsaShake192fPublicKeySize
    )


class SlhDsaShake256sPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShake256sPublicKeySize, SlhDsaShake256sPublicKeySize
    )


class SlhDsaShake256fPublicKey(univ.OctetString):
    subtypeSpec = ValueSizeConstraint(
        SlhDsaShake256fPublicKeySize, SlhDsaShake256fPublicKeySize
    )


ALGORITHM_OID_TO_KEY_MAPPINGS = {
    # pure
    csor.id_slh_dsa_sha2_128f: SlhDsaShaTwo128fPublicKey(),
    csor.id_slh_dsa_sha2_128s: SlhDsaShaTwo128sPublicKey(),
    csor.id_slh_dsa_sha2_192f: SlhDsaShaTwo192fPublicKey(),
    csor.id_slh_dsa_sha2_192s: SlhDsaShaTwo192sPublicKey(),
    csor.id_slh_dsa_sha2_256f: SlhDsaShaTwo256fPublicKey(),
    csor.id_slh_dsa_sha2_256s: SlhDsaShaTwo256sPublicKey(),
    csor.id_slh_dsa_shake_128f: SlhDsaShake128fPublicKey(),
    csor.id_slh_dsa_shake_128s: SlhDsaShake128sPublicKey(),
    csor.id_slh_dsa_shake_192f: SlhDsaShake192fPublicKey(),
    csor.id_slh_dsa_shake_192s: SlhDsaShake192sPublicKey(),
    csor.id_slh_dsa_shake_256f: SlhDsaShake256fPublicKey(),
    csor.id_slh_dsa_shake_256s: SlhDsaShake256sPublicKey(),
    # pre-hashed
    csor.id_hash_slh_dsa_sha2_128f_with_sha256: SlhDsaShaTwo128fPublicKey(),
    csor.id_hash_slh_dsa_sha2_128s_with_sha256: SlhDsaShaTwo128sPublicKey(),
    csor.id_hash_slh_dsa_sha2_192f_with_sha512: SlhDsaShaTwo192fPublicKey(),
    csor.id_hash_slh_dsa_sha2_192s_with_sha512: SlhDsaShaTwo192sPublicKey(),
    csor.id_hash_slh_dsa_sha2_256f_with_sha512: SlhDsaShaTwo256fPublicKey(),
    csor.id_hash_slh_dsa_sha2_256s_with_sha512: SlhDsaShaTwo256sPublicKey(),
    csor.id_hash_slh_dsa_shake_128f_with_shake128: SlhDsaShake128fPublicKey(),
    csor.id_hash_slh_dsa_shake_128s_with_shake128: SlhDsaShake128sPublicKey(),
    csor.id_hash_slh_dsa_shake_192f_with_shake256: SlhDsaShake192fPublicKey(),
    csor.id_hash_slh_dsa_shake_192s_with_shake256: SlhDsaShake192sPublicKey(),
    csor.id_hash_slh_dsa_shake_256f_with_shake256: SlhDsaShake256fPublicKey(),
    csor.id_hash_slh_dsa_shake_256s_with_shake256: SlhDsaShake256sPublicKey(),
}

ALGORITHM_OID_TO_PARAMETER_MAPPINGS = {
    k: document.ValueDecoder.VALUE_NODE_ABSENT
    for k in ALGORITHM_OID_TO_KEY_MAPPINGS.keys()
}
