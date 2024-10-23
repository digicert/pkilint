from typing import Optional

from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ, base
from pyasn1_alt_modules import rfc3279, rfc5280, rfc5480, rfc5639, rfc4055

from pkilint import validation
from pkilint.pkix import algorithm
from pkilint.pkix.certificate import certificate_key


class RsaKeyValidator(validation.Validator):
    """
    TS 119 312, clause 6.2.2.1:

    The public exponent e shall be an odd positive integer such that 2^16 < e < 2^256.
    """

    VALIDATION_RSA_EXPONENT_OUT_OF_RANGE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "ts_119_312.6.2.2.1.rsa_exponent_of_range",
    )

    VALIDATION_RSA_SMALL_MODULUS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE, "ts_119_312.8.4.rsa_small_modulus"
    )

    _MIN_MODULUS_LENGTH = 1900
    _MIN_EXPONENT_EXCLUSIVE = 1 << 16
    _MAX_EXPONENT_EXCLUSIVE = 1 << 256

    def __init__(self):
        super().__init__(
            validations=[
                self.VALIDATION_RSA_EXPONENT_OUT_OF_RANGE,
                self.VALIDATION_RSA_SMALL_MODULUS,
            ],
            pdu_class=rfc3279.RSAPublicKey,
        )

    def validate(self, node):
        modulus_len = int(node.children["modulus"].pdu).bit_length()
        exponent_int = int(node.children["publicExponent"].pdu)

        findings = []

        if modulus_len < 1900:
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_RSA_SMALL_MODULUS,
                    f"RSA public key has a modulus length of {modulus_len} bits",
                )
            )

        if (
            not self._MIN_EXPONENT_EXCLUSIVE
            < exponent_int
            < self._MAX_EXPONENT_EXCLUSIVE
        ):
            findings.append(
                validation.ValidationFindingDescription(
                    self.VALIDATION_RSA_EXPONENT_OUT_OF_RANGE,
                    f"RSA public key has an exponent of {exponent_int}",
                )
            )

        return validation.ValidationResult(self, node, findings)


def _create_alg_id_der(
    o: univ.ObjectIdentifier, params: Optional[base.Asn1Type]
) -> bytes:
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id["algorithm"] = o

    if params is not None:
        alg_id["parameters"] = params

    return encode(alg_id)


_SPKI_ALG_ID_ENCODINGS = (
    [
        # RSA
        _create_alg_id_der(rfc5480.rsaEncryption, univ.Null(""))
    ]
    + [
        # ECDSA
        _create_alg_id_der(rfc5480.id_ecPublicKey, c)
        for c in (
            univ.ObjectIdentifier("1.2.250.1.223.101.256.1"),  # FRP256v1
            rfc5639.brainpoolP256r1,
            rfc5639.brainpoolP384r1,
            rfc5639.brainpoolP512r1,
            rfc5480.secp256r1,
            rfc5480.secp384r1,
            rfc5480.secp521r1,
        )
    ]
    # TODO: add DSA
)


class AllowedPublicKeyTypeValidator(
    certificate_key.AllowedPublicKeyAlgorithmEncodingValidator
):
    """
    From EN 319 412 2:

    GEN-4.2.5-1

    The subject public key should be selected according to ETSI TS 119 312 [i.7].

    NOTE: Cryptographic suites recommendations defined in ETSI TS 119 312 [i.7] can be superseded by national
    recommendations.
    """

    VALIDATION_DISCOURAGED_PUBLIC_KEY_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "etsi.en_319_412_2.gen-4.2.5-1.discouraged_public_key_type",
    )

    def __init__(self):
        super().__init__(
            validation=self.VALIDATION_DISCOURAGED_PUBLIC_KEY_TYPE,
            allowed_encodings=_SPKI_ALG_ID_ENCODINGS,
            pdu_class=rfc5280.AlgorithmIdentifier,
        )


_NIST_ALG_ARC = univ.ObjectIdentifier("2.16.840.1.101.3.4")
_SHA3_ARC = _NIST_ALG_ARC + (2,)

id_sha3_224 = _SHA3_ARC + (7,)
id_sha3_256 = _SHA3_ARC + (8,)
id_sha3_384 = _SHA3_ARC + (9,)
id_sha3_512 = _SHA3_ARC + (10,)


_ECDSA_WITH_SHA3_ARC = _NIST_ALG_ARC + (3,)

id_ecdsa_with_sha3_256 = _ECDSA_WITH_SHA3_ARC + (10,)
id_ecdsa_with_sha3_384 = _ECDSA_WITH_SHA3_ARC + (11,)
id_ecdsa_with_sha3_512 = _ECDSA_WITH_SHA3_ARC + (12,)


_HASH_ALG_ID_TO_HASH_LENGTH = {
    o: l / 8
    for o, l in (
        (rfc4055.id_sha224, 224),
        (rfc4055.id_sha256, 256),
        (rfc4055.id_sha384, 384),
        (rfc4055.id_sha512, 512),
        (id_sha3_224, 224),
        (id_sha3_256, 256),
        (id_sha3_384, 384),
        (id_sha3_512, 512),
    )
}


def _create_rsapss_params(hash_alg, encode_null_params):
    params = rfc4055.RSASSA_PSS_params()
    params["hashAlgorithm"]["algorithm"] = hash_alg

    if encode_null_params:
        params["hashAlgorithm"]["parameters"] = univ.Null("")

    params["maskGenAlgorithm"]["algorithm"] = rfc4055.id_mgf1

    mask_gen_alg_id = rfc5280.AlgorithmIdentifier()
    mask_gen_alg_id["algorithm"] = hash_alg

    if encode_null_params:
        mask_gen_alg_id["parameters"] = univ.Null("")

    params["maskGenAlgorithm"]["parameters"] = mask_gen_alg_id

    params["saltLength"] = _HASH_ALG_ID_TO_HASH_LENGTH[hash_alg]

    return params


_SIGNATURE_ALG_ID_ENCODINGS = (
    [
        # PKCS v1.5
        _create_alg_id_der(o, univ.Null(""))
        for o in (
            rfc4055.sha256WithRSAEncryption,
            rfc4055.sha384WithRSAEncryption,
            rfc4055.sha512WithRSAEncryption,
        )
    ]
    + [
        # RSASSA-PSS without null parameters
        _create_alg_id_der(rfc4055.id_RSASSA_PSS, _create_rsapss_params(h, False))
        for h in (
            rfc4055.id_sha224,
            rfc4055.id_sha256,
            rfc4055.id_sha384,
            rfc4055.id_sha512,
            id_sha3_224,
            id_sha3_256,
            id_sha3_384,
            id_sha3_512,
        )
    ]
    + [
        # RSASSA-PSS with null parameters
        _create_alg_id_der(rfc4055.id_RSASSA_PSS, _create_rsapss_params(h, True))
        for h in (
            rfc4055.id_sha224,
            rfc4055.id_sha256,
            rfc4055.id_sha384,
            rfc4055.id_sha512,
            id_sha3_224,
            id_sha3_256,
            id_sha3_384,
            id_sha3_512,
        )
    ]
    + [
        # ECDSA
        _create_alg_id_der(o, None)
        for o in (
            rfc5480.ecdsa_with_SHA256,
            rfc5480.ecdsa_with_SHA384,
            rfc5480.ecdsa_with_SHA512,
            id_ecdsa_with_sha3_256,
            id_ecdsa_with_sha3_384,
            id_ecdsa_with_sha3_512,
        )
    ]
    # TODO: add support for Schnorr signatures
)


class AllowedSignatureAlgorithmValidator(
    algorithm.AllowedSignatureAlgorithmEncodingValidator
):
    """
    From EN 319 412 2:

    GEN-4.2.2-1

    Signature algorithm should be selected according to ETSI TS 119 312 [i.7].

    NOTE: Cryptographic suites recommendations defined in ETSI TS 119 312 [i.7] can be superseded by national
    recommendations.
    """

    VALIDATION_DISCOURAGED_SIGNATURE_ALGORITHM = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        "etsi.en_319_412_2.gen-4.2.2-1.discouraged_signature_algorithm",
    )

    def __init__(self, path: str):
        super().__init__(
            validation=self.VALIDATION_DISCOURAGED_SIGNATURE_ALGORITHM,
            allowed_encodings=_SIGNATURE_ALG_ID_ENCODINGS,
            path=path,
        )
