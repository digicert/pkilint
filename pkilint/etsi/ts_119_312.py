from typing import Optional

from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ, base
from pyasn1_alt_modules import rfc3279, rfc5280, rfc5480, rfc5639

from pkilint import validation
from pkilint.pkix.certificate import certificate_key


class RsaKeyValidator(validation.Validator):
    """
    TS 119 312, clause 6.2.2.1:

    The public exponent e shall be an odd positive integer such that 2^16 < e < 2^256.
    """
    VALIDATION_RSA_EXPONENT_OUT_OF_RANGE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'ts_119_312.6.2.2.1.rsa_exponent_of_range'
    )

    VALIDATION_RSA_SMALL_MODULUS = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'ts_119_312.8.4.rsa_small_modulus'
    )

    _MIN_MODULUS_LENGTH = 1900
    _MIN_EXPONENT_EXCLUSIVE = 1 << 16
    _MAX_EXPONENT_EXCLUSIVE = 1 << 256

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_RSA_EXPONENT_OUT_OF_RANGE, self.VALIDATION_RSA_SMALL_MODULUS],
            pdu_class=rfc3279.RSAPublicKey
        )

    def validate(self, node):
        modulus_len = int(node.children['modulus'].pdu).bit_length()
        exponent_int = int(node.children['publicExponent'].pdu)

        findings = []

        if modulus_len < 1900:
            findings.append(validation.ValidationFindingDescription(
                self.VALIDATION_RSA_SMALL_MODULUS,
                f'RSA public key has a modulus length of {modulus_len} bits'
            ))

        if not self._MIN_EXPONENT_EXCLUSIVE < exponent_int < self._MAX_EXPONENT_EXCLUSIVE:
            findings.append(validation.ValidationFindingDescription(
                self.VALIDATION_RSA_EXPONENT_OUT_OF_RANGE,
                f'RSA public key has an exponent of {exponent_int}'
            ))

        return validation.ValidationResult(self, node, findings)


def _create_alg_id_der(o: univ.ObjectIdentifier, params: Optional[base.Asn1Type]) -> bytes:
    alg_id = rfc5280.AlgorithmIdentifier()
    alg_id['algorithm'] = o

    if params is not None:
        alg_id['parameters'] = encode(params)

    return encode(alg_id)


_RSA_SPKI_ALG_ID_ENCODINGS = [
    _create_alg_id_der(rfc5480.rsaEncryption, univ.Null(''))
]


# TODO: add DSA


_ECDSA_SPKI_ALG_ID_ENCODINGS = [
    _create_alg_id_der(rfc5480.id_ecPublicKey, c) for c in (
        univ.ObjectIdentifier('1.2.250.1.223.101.256.1'),  # FRP256v1
        rfc5639.brainpoolP256r1,
        rfc5639.brainpoolP384r1,
        rfc5639.brainpoolP512r1,
        rfc5480.secp256r1,
        rfc5480.secp384r1,
        rfc5480.secp521r1,
    )
]


_SPKI_ALG_ID_ENCODINGS = _RSA_SPKI_ALG_ID_ENCODINGS + _ECDSA_SPKI_ALG_ID_ENCODINGS


class AllowedPublicKeyTypeValidator(certificate_key.AllowedPublicKeyAlgorithmEncodingValidator):
    """
    GEN-4.2.5-1

    The subject public key should be selected according to ETSI TS 119 312 [i.7].

    NOTE: Cryptographic suites recommendations defined in ETSI TS 119 312 [i.7] can be superseded by national
    recommendations.
    """
    VALIDATION_DISCOURAGED_PUBLIC_KEY_TYPE = validation.ValidationFinding(
        validation.ValidationFindingSeverity.NOTICE,
        'etsi.en_319_412_2.gen-4.2.5-1.discouraged_public_key_type'
    )

    def __init__(self):
        super().__init__(
            validation=self.VALIDATION_DISCOURAGED_PUBLIC_KEY_TYPE,
            allowed_encodings=_SPKI_ALG_ID_ENCODINGS,
            pdu_class=rfc5280.AlgorithmIdentifier
        )
