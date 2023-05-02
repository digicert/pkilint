import binascii

from pyasn1.codec.der.encoder import encode
from pyasn1_alt_modules import rfc5280

from pkilint import validation

ALGORITHM_IDENTIFIER_MAPPINGS = rfc5280.algorithmIdentifierMap.copy()


class AlgorithmIdentifierDecodingValidator(validation.DecodingValidator):
    def __init__(self, *, decode_func, **kwargs):
        super().__init__(pdu_class=rfc5280.AlgorithmIdentifier,
                         decode_func=decode_func,
                         **kwargs
                         )


class AllowedSignatureAlgorithmEncodingValidator(validation.Validator):
    def __init__(self, *, validation, allowed_encodings, **kwargs):
        self._allowed_encodings = allowed_encodings

        super().__init__(
            validations=[validation],
            **kwargs
        )

    def validate(self, node):
        encoded = encode(node.pdu)

        if encoded not in self._allowed_encodings:
            encoded_str = binascii.hexlify(encoded).decode('us-ascii')

            raise validation.ValidationFindingEncountered(
                self._validations[0],
                f'Prohibited encoding: {encoded_str}'
            )
