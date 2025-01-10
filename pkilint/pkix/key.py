from cryptography import exceptions
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    rsa,
    padding,
    dsa,
    ed25519,
    ed448,
)
from pyasn1.type import univ
from pyasn1_alt_modules import rfc3279, rfc5480, rfc8410

from pkilint import document
from pkilint.document import PDUNode
from pkilint.nist.asn1 import fips_203, fips_204, fips_205

SUBJECT_PUBLIC_KEY_ALGORITHM_IDENTIFIER_MAPPINGS = {
    rfc3279.rsaEncryption: rfc5480.RSAPublicKey(),
    rfc5480.id_ecPublicKey: rfc5480.ECPoint(),
    rfc5480.id_ecDH: rfc5480.ECPoint(),
    rfc5480.id_ecMQV: rfc5480.ECPoint(),
    rfc8410.id_Ed448: univ.OctetString(),
    rfc8410.id_Ed25519: univ.OctetString(),
    rfc8410.id_X448: univ.OctetString(),
    rfc8410.id_X25519: univ.OctetString(),
    **fips_203.ALGORITHM_OID_TO_KEY_MAPPINGS,
    **fips_204.ALGORITHM_OID_TO_KEY_MAPPINGS,
    **fips_205.ALGORITHM_OID_TO_KEY_MAPPINGS,
}

SUBJECT_KEY_PARAMETER_ALGORITHM_IDENTIFIER_MAPPINGS = {
    rfc3279.rsaEncryption: univ.Null(),
    rfc5480.id_ecPublicKey: rfc5480.ECParameters(),
    rfc5480.id_ecDH: rfc5480.ECParameters(),
    rfc5480.id_ecMQV: rfc5480.ECParameters(),
    **{
        o: document.ValueDecoder.VALUE_NODE_ABSENT
        for o in (
            rfc8410.id_Ed448,
            rfc8410.id_Ed25519,
            rfc8410.id_X448,
            rfc8410.id_X25519,
        )
    },
    **fips_203.ALGORITHM_OID_TO_PARAMETER_MAPPINGS,
    **fips_204.ALGORITHM_OID_TO_PARAMETER_MAPPINGS,
    **fips_205.ALGORITHM_OID_TO_PARAMETER_MAPPINGS,
}

EC_CURVE_OID_TO_OBJECT_MAPPINGS = {
    rfc5480.secp256r1: ec.SECP256R1(),
    rfc5480.secp384r1: ec.SECP384R1(),
    rfc5480.secp521r1: ec.SECP521R1(),
}

_EC_PUBLIC_KEY_OIDS = {rfc5480.id_ecPublicKey, rfc5480.id_ecDH, rfc5480.id_ecMQV}


def convert_spki_to_object(spki_node: PDUNode):
    key_type = spki_node.navigate("algorithm.algorithm").pdu

    if key_type == rfc3279.rsaEncryption:
        rsa_public_key = spki_node.navigate("subjectPublicKey.rSAPublicKey")

        modulus = rsa_public_key.children["modulus"].pdu
        exponent = rsa_public_key.children["publicExponent"].pdu

        return rsa.RSAPublicNumbers(int(exponent), int(modulus)).public_key()
    elif key_type in _EC_PUBLIC_KEY_OIDS:
        curve_oid = spki_node.navigate(
            "algorithm.parameters.eCParameters.namedCurve"
        ).pdu

        curve = EC_CURVE_OID_TO_OBJECT_MAPPINGS.get(curve_oid)
        if curve is not None:
            return ec.EllipticCurvePublicKey.from_encoded_point(
                curve, spki_node.navigate("subjectPublicKey").pdu.asOctets()
            )
    elif key_type == rfc8410.id_Ed448:
        return ed448.Ed448PublicKey.from_public_bytes(
            spki_node.navigate("subjectPublicKey").pdu.asOctets()
        )
    elif key_type == rfc8410.id_Ed25519:
        return ed25519.Ed25519PublicKey.from_public_bytes(
            spki_node.navigate("subjectPublicKey").pdu.asOctets()
        )

    # TODO: others
    return None


def verify_signature(public_key, message, signature, signature_hash_algorithm=None):
    try:
        # TODO: add support for RSASSA-PSS

        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature, message, padding.PKCS1v15(), signature_hash_algorithm
            )
        elif isinstance(public_key, dsa.DSAPublicKey):
            public_key.verify(signature, message, signature_hash_algorithm)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, message, ec.ECDSA(signature_hash_algorithm))
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, message)
        elif isinstance(public_key, ed448.Ed448PublicKey):
            public_key.verify(signature, message)
        else:
            type_name = type(public_key).__name__

            raise exceptions.UnsupportedAlgorithm(
                f'Unsupported public key type "{type_name}"'
            )
    except exceptions.InvalidSignature:
        return False

    return True
