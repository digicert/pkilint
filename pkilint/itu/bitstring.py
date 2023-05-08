from pyasn1.codec.der.encoder import encode
from pyasn1.type.univ import BitString

from pkilint import validation


class NamedBitStringMinimalEncodingValidator(validation.Validator):
    VALIDATION_BIT_STRING_NOT_MINIMALLY_ENCODED = validation.ValidationFinding(
        validation.ValidationFindingSeverity.ERROR,
        'itu.bitstring_not_der_encoded'
    )

    def __init__(self):
        super().__init__(
            validations=[self.VALIDATION_BIT_STRING_NOT_MINIMALLY_ENCODED],
            pdu_class=BitString,
            predicate=lambda n: any(n.pdu.namedValues)
        )

    def validate(self, node):
        # extract values then re-encode

        asserted_values = ','.join((k for k in node.pdu.namedValues.keys() if has_named_bit(node, k)))

        encoded = encode(node.pdu)

        new_encoded = encode(type(node.pdu)(asserted_values), asn1Spec=node.pdu)

        if encoded != new_encoded:
            encoded_hex = encoded.hex()
            new_encoded_hex = new_encoded.hex()

            raise validation.ValidationFindingEncountered(
                self.VALIDATION_BIT_STRING_NOT_MINIMALLY_ENCODED,
                f'Expected: "{new_encoded_hex}", actual: "{encoded_hex}"'
            )


def has_named_bit(node, bit_name):
    bit = node.pdu.namedValues[bit_name]
    return len(node.pdu) > bit and node.pdu[bit] != 0
