import binascii

from pyasn1.codec.der.encoder import encode
from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5280, rfc5480, rfc8410

from pkilint import validation, document
from pkilint.nist.asn1 import fips_204, fips_205

SIGNATURE_ALGORITHM_IDENTIFIER_MAPPINGS = {
    **{
        o: document.ValueDecoder.VALUE_NODE_ABSENT
        for o in (
            rfc8410.id_Ed448,
            rfc8410.id_Ed25519,
            rfc8410.id_X448,
            rfc8410.id_X25519,
            rfc5480.id_dsa_with_sha1,
            rfc5480.id_dsa_with_sha224,
            rfc5480.id_dsa_with_sha256,
            rfc5480.ecdsa_with_SHA1,
            rfc5480.ecdsa_with_SHA224,
            rfc5480.ecdsa_with_SHA256,
            rfc5480.ecdsa_with_SHA384,
            rfc5480.ecdsa_with_SHA512,
        )
    },
    **{
        o: univ.Null()
        for o in (
            rfc5480.md2WithRSAEncryption,
            rfc5480.md5WithRSAEncryption,
            rfc5480.sha1WithRSAEncryption,
            rfc4055.sha224WithRSAEncryption,
            rfc4055.sha256WithRSAEncryption,
            rfc4055.sha384WithRSAEncryption,
            rfc4055.sha512WithRSAEncryption,
        )
    },
    **fips_204.ALGORITHM_OID_TO_PARAMETER_MAPPINGS,
    **fips_205.ALGORITHM_OID_TO_PARAMETER_MAPPINGS,
    rfc4055.id_RSASSA_PSS: rfc4055.RSASSA_PSS_params(),
}


class AlgorithmIdentifierDecodingValidator(validation.DecodingValidator):
    def __init__(self, *, decode_func, **kwargs):
        super().__init__(
            pdu_class=rfc5280.AlgorithmIdentifier, decode_func=decode_func, **kwargs
        )


class AllowedSignatureAlgorithmEncodingValidator(validation.Validator):
    def __init__(self, *, validation, allowed_encodings, **kwargs):
        self._allowed_encodings = allowed_encodings

        super().__init__(validations=[validation], **kwargs)

    def validate(self, node):
        encoded = encode(node.pdu)

        if encoded not in self._allowed_encodings:
            encoded_str = binascii.hexlify(encoded).decode("us-ascii")

            raise validation.ValidationFindingEncountered(
                self._validations[0], f"Prohibited encoding: {encoded_str}"
            )
